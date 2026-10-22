#include "auth.h"
#include "jwt.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/sha.h>

/* 依赖快照(auth_init 后只读)；单线程事件循环内使用，无并发问题 */
static auth_deps_t D;

void auth_init(const auth_deps_t *deps)
{
    D = *deps;
}

/* 字符白名单净化: 拼 Redis 键的字段只留 [A-Za-z0-9_-]，其余替换 '_'
 * (hiredis %s 整参数本无注入面，此层是纵深防御) */
static void sanitize(char *s)
{
    for (; *s; s++)
        if (!(*s >= 'a' && *s <= 'z') && !(*s >= 'A' && *s <= 'Z') &&
            !(*s >= '0' && *s <= '9') && *s != '-' && *s != '_')
            *s = '_';
}

/* 凭证指纹: SHA256 十六进制串作为缓存键，不落原始凭证明文 */
static void cred_fingerprint(const char *cred, size_t n, char out[65])
{
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)cred, n, md);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(out + i * 2, 3, "%02x", md[i]);
}

/* 从 Cookie 头值提取 sid=(零拷贝缓冲无 NUL，用带界扫描而非 strstr)。
 * 'sid=' 前必须是串首/空格/分号，防 "asid=x" 误匹配
 * 返回 0 找到 / 1 超长截断 / -1 未找到 */
static int cookie_sid(const char *ck, size_t n, char *out, size_t cap)
{
    for (size_t i = 0; i + 4 <= n; i++) {
        if (ck[i] != 's' || ck[i + 1] != 'i' || ck[i + 2] != 'd' || ck[i + 3] != '=')
            continue;
        if (!(i == 0 || ck[i - 1] == ' ' || ck[i - 1] == ';'))
            continue;                          /* 非独立键名，跳过防误匹配 */
        size_t j = i + 4, o = 0;
        while (j < n && ck[j] != ';' && o + 1 < cap) {
            if (ck[j] == ' ') { j++; continue; }
            out[o++] = ck[j++];
        }
        out[o] = '\0';
        if (j < n && ck[j] != ';') return 1;   /* cap 写满仍有剩余 → 截断(上层严格拒) */
        return o ? 0 : -1;
    }
    return -1;
}

/* 限流/失败计数的客户端标识(信任边界):
 * TRUST_PROXY 模式下 TCP 对端恒为 Nginx 本机，改用其注入的 X-Real-IP
 * ($remote_addr 客户端伪造不了)；直连模式一律忽略该头(此时可伪造，
 * 无条件信任等于限流/锁定被换 IP 绕过)。需过 inet_pton 校验，
 * 非法/缺失回落 socket IP；可信前提是监听仅对网关可达(main.c 已收窄) */
static void client_key(const http_request_t *req, const char *ip,
                       char *out, size_t cap)
{
    if (D.trust_proxy && req->x_real_ip && req->x_real_ip_len > 0 &&
        req->x_real_ip_len < 46) {
        char tmp[46];
        struct sockaddr_in sa;
        memcpy(tmp, req->x_real_ip, req->x_real_ip_len);
        tmp[req->x_real_ip_len] = '\0';
        if (inet_pton(AF_INET, tmp, &sa.sin_addr) == 1) {
            snprintf(out, cap, "%s", tmp);
            return;
        }
        /* 非法值回落 socket IP(异常输入从严); v6 形态当前部署不可达(监听 AF_INET) */
    }
    snprintf(out, cap, "%s", ip);
}

/* 暴力破解失败计数: 原子 INCR + 首次 EXPIRE(键 authfail:<客户端标识>)
 * 返回 INCR 后的次数；-1 = Redis 不可用(锁定检查随之失效，属降级面) */
static long long fail_incr(const char *ip)
{
    char fkey[64];                       /* "authfail:" + IPv4 点分 足容 */
    snprintf(fkey, sizeof(fkey), "authfail:%s", ip);
    return redis_incr_ttl(D.rds, fkey, D.fail_window);
}

/* ─────────────────────────────────────────────────────────────
 * 鉴权主入口
 * ───────────────────────────────────────────────────────────── */

int auth_check(const http_request_t *req, const char *ip,
               char *user, size_t ucap,
               char *note, size_t ncap,
               char *extra, size_t ecap)
{
    user[0] = '\0';
    int degraded = 0;    /* Redis 不可用降级标记 → X-Auth-Degraded: 1 */
    int cache_hit = 0;   /* JWT 结果缓存命中 → X-Auth-Cache: hit */
    char uid[64] = "";   /* 校验通过的用户身份。零初始化: 降级 fail-open 路径
                          * 不产生身份，空串即不透传 X-User-Id */

    char ckey[48];       /* 限流/失败计数键的客户端标识(socket IP 或 X-Real-IP, 信任边界见 client_key) */
    client_key(req, ip, ckey, sizeof(ckey));

    if (!D.rds) {        /* 依赖未就绪(demo 模式在上层短路，此为防御性兜底) */
        snprintf(note, ncap, "auth deps not ready");
        return 401;
    }

    /* 0) 暴力破解锁定检查: 失败计数达阈值一律 403(锁定期内有效凭证也拒，
     *    迫使攻击者放弃该 IP)。计数查不到(-1)时跳过并置降级——
     *    锁定是防爆破增益项，Redis 挂掉退回逐请求凭证校验 */
    char fbuf[16];
    int fr = 0;
    {
        char fkey[64];
        snprintf(fkey, sizeof(fkey), "authfail:%s", ckey);
        fr = redis_get(D.rds, fkey, fbuf, sizeof(fbuf));
    }
    if (fr > 0 && atoi(fbuf) >= D.fail_limit) {
        snprintf(note, ncap, "ip locked: %s recent auth failures", fbuf);
        return 403;
    }
    if (fr < 0) degraded = 1;

    /* 1) 凭证识别与分派(优先级 X-Api-Key > Cookie sid > Bearer，互斥先到先得)
     *    invalid 记 "出示了凭证但校验失败"——只有这类计入暴力破解计数，
     *    未携带凭证/被注销的请求不计数(注销≠爆破，缺失凭证也≠爆破) */
    int rc = 401;        /* 默认: 无可识别凭证 → 401 */
    int invalid = 0;     /* 1 = 凭证无效(计失败数) */

    if (req->api_key && req->api_key_len > 0) {
        /* --- API Key(服务间调用): Redis 查 apikey:<key>，键由运维预置 --- */
        char key[96], kfull[128];
        if (req->api_key_len >= sizeof(key)) {   /* 超长凭证严格拒，防截断碰撞 */
            fail_incr(ckey);
            snprintf(note, ncap, "api key too long");
            return 401;
        }
        size_t klen = req->api_key_len;
        memcpy(key, req->api_key, klen);
        key[klen] = '\0';
        sanitize(key);
        snprintf(kfull, sizeof(kfull), "apikey:%s", key);
        int g = redis_get(D.rds, kfull, uid, sizeof(uid));
        if (g == 1) {
            rc = 200;
            snprintf(note, ncap, "api key ok");
        } else if (g == 0) {
            invalid = 1; rc = 401;
            snprintf(note, ncap, "invalid api key");
        } else {
            degraded = 1; rc = 200;      /* 查询失败 fail-open；uid 空串不透传身份 */
            snprintf(note, ncap, "apikey lookup degraded, fail-open");
        }
    } else {
        char sid[80];
        int have_sid = 0;
        if (req->cookie && req->cookie_len > 0) {
            int cs = cookie_sid(req->cookie, req->cookie_len, sid, sizeof(sid));
            if (cs == 1) {   /* sid 超长截断: 与 API Key 同策略严格拒(截断碰撞防护) */
                fail_incr(ckey);
                snprintf(note, ncap, "session id too long");
                return 401;
            }
            have_sid = (cs == 0);
        }
        if (have_sid) {
            /* --- Session: Redis 查 sess:<sid>，TTL 即会话有效期，过期即键消失 --- */
            sanitize(sid);
            char sfull[112];
            snprintf(sfull, sizeof(sfull), "sess:%s", sid);
            int g = redis_get(D.rds, sfull, uid, sizeof(uid));
            if (g == 1) {
                rc = 200;
                snprintf(note, ncap, "session ok");
            } else if (g == 0) {
                invalid = 1; rc = 401;
                snprintf(note, ncap, "invalid/expired session");
            } else {
                degraded = 1; rc = 200;   /* fail-open: 身份未验证，uid 空串不透传 */
                snprintf(note, ncap, "session lookup degraded, fail-open");
            }
        } else if (req->authorization && req->authorization_len >= 8 &&
                   strncasecmp(req->authorization, "Bearer ", 7) == 0) {
            /* --- JWT(无状态 API): Bearer Token，本地验签 + 结果缓存 + 黑名单 --- */
            const char *tok = req->authorization + 7;
            while (*tok == ' ') tok++;       /* 容忍 scheme 后多余空格 */
            size_t tlen = req->authorization_len - (size_t)(tok - req->authorization);
            if (tlen == 0) {
                snprintf(note, ncap, "empty bearer token");
                return 401;                  /* 未出示有效凭证，不计失败 */
            }

            /* 结果缓存: 指纹键命中 → 跳过验签与黑名单(注销生效延迟 ≤30s) */
            char fp[65];
            cred_fingerprint(tok, tlen, fp);
            char ck[80];
            snprintf(ck, sizeof(ck), "authcache:%s", fp);
            int g = redis_get(D.rds, ck, uid, sizeof(uid));
            if (g == 1) {
                cache_hit = 1;
                rc = 200;
                snprintf(note, ncap, "jwt auth cache hit");
            } else {
                if (g < 0) degraded = 1;     /* 缓存查询失败不阻塞主链路 */
                jwt_claim_t claim;
                char jerr[64] = {0};
                int r = jwt_verify(tok, tlen, D.secret, D.rs256_pkey,
                                   &claim, jerr, sizeof(jerr));
                if (r == -2) {               /* 算法混淆 = 构造性攻击 → 403 */
                    fail_incr(ckey);
                    snprintf(note, ncap, "jwt alg attack: %s", jerr);
                    return 403;
                }
                if (r != 0) {                /* 格式/签名/过期 → 401 */
                    invalid = 1;
                    snprintf(note, ncap, "jwt invalid: %s", jerr);
                    rc = 401;
                } else {
                    /* 注销黑名单: EXISTS blk:<jti>，登出即失效 */
                    int blk = redis_blacklisted(D.rds, claim.jti);
                    if (blk == 1) {
                        snprintf(note, ncap, "token revoked jti=%s", claim.jti);
                        return 401;          /* 凭证有效但被注销，不计爆破 */
                    }
                    if (blk < 0) degraded = 1;
                    snprintf(uid, sizeof(uid), "%s", claim.sub);
                    rc = 200;
                    /* 成功结果写缓存(30s；写失败静默——缓存是加速项非正确性依赖) */
                    redis_setex(D.rds, ck, 30, uid);
                    snprintf(note, ncap, "user=%s jti=%s%s", claim.sub, claim.jti,
                             degraded ? " (redis degraded)" : "");
                }
            }
        } else {
            snprintf(note, ncap, "missing credentials");   /* 无凭证，不计失败 */
            return 401;
        }
    }

    if (invalid) {
        fail_incr(ckey);   /* 凭证无效计入暴力破解计数，达阈值后下一请求起锁定 */
        return rc;
    }
    if (rc != 200) return rc;

    /* 2) IP 固定窗口限流: 排在凭证校验之后——只有通过校验的请求消耗配额
     *    (键的客户端标识经信任边界解析, 见 client_key) */
    int over = redis_rate_limit(D.rds, ckey, D.rl_limit, D.rl_window);
    if (over == 1) {
        snprintf(extra, ecap, "Retry-After: %d\r\n", D.rl_window);
        snprintf(note, ncap, "rate limited ip=%s", ckey);
        return 429;
    }
    if (over < 0) degraded = 1;

    /* 3) 放行: 透传 X-User-Id，降级/缓存命中带标记头 */
    snprintf(user, ucap, "%s", uid);
    snprintf(extra, ecap, "%s%s%s",
             uid[0] ? "X-User-Id: " : "",
             uid[0] ? uid : "",
             (uid[0] ? "\r\n" : ""));
    {
        size_t len = strlen(extra);
        if (degraded)  snprintf(extra + len, ecap - len, "X-Auth-Degraded: 1\r\n");
        len = strlen(extra);
        if (cache_hit) snprintf(extra + len, ecap - len, "X-Auth-Cache: hit\r\n");
    }
    return 200;
}
