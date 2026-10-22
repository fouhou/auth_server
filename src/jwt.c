#include "jwt.h"
#include "util.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

/* token 总长上限: 超长输入一律 -1 拒绝(防解析/解码阶段被超大 token 拖垮；
 * 合法 JWT 通常几百字节，RS256 也就 700 字节左右，4KB 余量充足) */
#define JWT_MAX      4096
/* 签名段长度上限: HS256 输出 32 字节 → base64url 约 43 字符；
 * RS256(RSA-2048) 签名 256 字节 → base64url 约 342 字符，1024 覆盖到 RSA-4096 */
#define SIG_MAX      1024

/* 失败原因登记: err 允许为 NULL(调用方不关心原因时) */
static void fail(char *err, size_t cap, const char *msg)
{
    if (err) snprintf(err, cap, "%s", msg);
}

/* HS256 放行开关(默认放行): AUTH_ALG=rs256 时关闭，防配置级算法混淆 */
static int allow_hs256 = 1;
void jwt_set_alg_policy(int hs256_allowed) { allow_hs256 = hs256_allowed ? 1 : 0; }

/* 朴素 JSON 字符串字段提取: 找 "key":"value" 截取 value 到 out(NUL 结尾)。
 * 边界: 不容忍冒号后空格、不处理转义——只验本生态签发的紧凑 JSON */
static void json_str(const char *json, const char *key, char *out, size_t cap)
{
    char pat[48];   /* 搜索模式: "key":" 的完整形态 */
    snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    const char *p = strstr(json, pat);   /* 字段起点(指向值的首字符) */
    if (!p) { out[0] = '\0'; return; }
    p += strlen(pat);
    size_t i = 0;                        /* 拷贝游标，最多 cap-1 留 NUL */
    while (p[i] && p[i] != '"' && i + 1 < cap) {
        out[i] = p[i];
        i++;
    }
    out[i] = '\0';
}

/* 朴素 JSON 整数字段提取: strtol 严格解析(数字开头、无溢出、收尾于 , } 或串尾)，
 * 任一不满足返回 0，上层用 exp<=0 统一判"缺失/非法" */
static long json_int(const char *json, const char *key)
{
    char pat[32];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(json, pat);
    if (!p) return 0;
    const char *d = p + strlen(pat);
    char *end = NULL;
    errno = 0;
    long v = strtol(d, &end, 10);
    if (end == d || errno == ERANGE) return 0;   /* 非数字开头/溢出都拒绝，防"永不过期" */
    while (*end == ' ') end++;                   /* 容忍数字后空格 */
    if (*end != ',' && *end != '}' && *end != '\0') return 0;   /* "123abc" 残缺文本拒绝 */
    return v;
}

/* JWT 验签主流程(安全设计见 jwt.h)。
 * 返回 0 / -1 格式或解码错 / -2 算法混淆(攻击，回 403) / -3 签名不符 / -4 过期或缺 exp */
int jwt_verify(const char *tok, size_t len, const char *secret,
               const EVP_PKEY *rs_pkey,
               jwt_claim_t *out, char *err, size_t errcap)
{
    memset(out, 0, sizeof(*out));   /* 失败路径上 claim 不残留脏数据 */
    if (len == 0 || len > JWT_MAX) { fail(err, errcap, "bad length"); return -1; }

    /* 1) 三段拆分 header.payload.signature */
    const char *end = tok + len;                      /* 输入尾部哨兵 */
    const char *d1 = memchr(tok, '.', len);           /* 第一/第二个点分隔符 */
    if (!d1) { fail(err, errcap, "malformed token"); return -1; }
    const char *d2 = memchr(d1 + 1, '.', (size_t)(end - d1 - 1));
    if (!d2) { fail(err, errcap, "malformed token"); return -1; }
    size_t hlen = (size_t)(d1 - tok);                 /* header 段长度 */
    size_t plen = (size_t)(d2 - d1 - 1);              /* payload 段长度 */
    size_t slen = (size_t)(end - d2 - 1);             /* signature 段长度 */
    if (!hlen || !plen || !slen || slen > SIG_MAX) {  /* 任一段为空/签名超长都拒绝 */
        fail(err, errcap, "malformed token"); return -1;
    }
    /* payload/signature 内若再藏 '.' 会让拆分错位 → 后续解码失败兜底 -1 */

    /* 2) 算法白名单: 只接受显式 HS256 / RS256，杜绝 alg:none / 其他算法混淆 */
    char hdr[512];    /* 解码后的 header 文本(合法 JWT 头几十字节) */
    size_t hn;        /* 解码后实际长度 */
    if (b64url_decode(tok, hlen, (unsigned char *)hdr, sizeof(hdr) - 1, &hn) != 0) {
        fail(err, errcap, "header decode fail"); return -1;
    }
    hdr[hn] = '\0';
    /* 精确匹配 "alg":"HS256"/"alg":"RS256"，none/变体形态不认。
     * 命中拒绝返回 -2: 算法混淆按构造性攻击处理(403)；
     * RS256 未配置公钥时同样 -2，防配置缺失绕过验签 */
    int is_hs = strstr(hdr, "\"alg\":\"HS256\"") != NULL;
    int is_rs = strstr(hdr, "\"alg\":\"RS256\"") != NULL;
    if (is_hs && !allow_hs256) {   /* 策略锁定 rs256-only: HS256 视同算法混淆攻击 */
        fail(err, errcap, "alg not allowed"); return -2;
    }
    if ((!is_hs && !is_rs) || (is_rs && !rs_pkey)) {
        fail(err, errcap, "alg not allowed"); return -2;
    }

    /* 3) 解码请求方出示的签名，再按算法分支比对 */
    unsigned char given[SIG_MAX];   /* 请求方出示的签名(解码后；RSA-2048 为 256 字节) */
    size_t given_len = 0;
    if (b64url_decode(d2 + 1, slen, given, sizeof(given), &given_len) != 0) {
        fail(err, errcap, "signature decode fail"); return -1;
    }
    if (is_hs) {
        /* HS256: 重算 HMAC-SHA256(header.payload) 与第三段常量时间比对 */
        unsigned char mac[EVP_MAX_MD_SIZE];   /* OpenSSL 通用摘要缓冲(实际用 32 字节) */
        unsigned int maclen = 0;              /* 实际摘要长度(HMAC 输出参数) */
        /* 签名输入是 tok 前 hlen+1+plen 字节，即 "header.payload" 连同中间点；
         * secret 长度按 strlen 传入(密钥非空，调用方已兜底默认值) */
        HMAC(EVP_sha256(), secret, (int)strlen(secret),
             (const unsigned char *)tok, hlen + 1 + plen, mac, &maclen);
        /* 先比长度(不等则短路)再常量时间比内容；长度泄露无侧信道价值(合法签名定长) */
        if (given_len != maclen || !consttime_eq(mac, given, maclen)) {
            fail(err, errcap, "signature mismatch"); return -3;
        }
    } else {
        /* RS256: 用公钥验证签发方对 "header.payload" 的签名。
         * 用 EVP_DigestVerify 一步式——不要用 verify_init + set_signature_md +
         * verify 旧三段式，OpenSSL 3.0 provider 路径下摘要设置不生效，
         * 合法 SHA256 签名会被误判。返回非 1 一律按验签失败；
         * 非对称验签不存在逐字节时间侧信道 */
        EVP_MD_CTX *mdc = EVP_MD_CTX_new();
        if (!mdc) { fail(err, errcap, "verify ctx fail"); return -1; }
        int vok = -1;
        if (EVP_DigestVerifyInit(mdc, NULL, EVP_sha256(), NULL,
                                 (EVP_PKEY *)rs_pkey) == 1)
            vok = EVP_DigestVerify(mdc, given, given_len,
                                   (const unsigned char *)tok, hlen + 1 + plen);
        EVP_MD_CTX_free(mdc);
        if (vok != 1) {
            fail(err, errcap, "signature mismatch"); return -3;
        }
    }

    /* 4) payload: 提取 exp/sub/jti */
    char payload[1024];   /* 解码后的 payload 文本 */
    size_t pn;            /* 实际长度 */
    if (b64url_decode(d1 + 1, plen, (unsigned char *)payload, sizeof(payload) - 1, &pn) != 0) {
        fail(err, errcap, "payload decode fail"); return -1;
    }
    payload[pn] = '\0';

    json_str(payload, "sub", out->sub, sizeof(out->sub));
    json_str(payload, "jti", out->jti, sizeof(out->jti));
    out->exp = json_int(payload, "exp");

    /* 5) 时效校验: exp 必须存在(>0)且未过期——防永不过期 Token */
    if (out->exp <= 0) { fail(err, errcap, "missing exp"); return -4; }
    if (out->exp <= (long)time(NULL)) { fail(err, errcap, "token expired"); return -4; }

    /* jti 白名单净化后再拼 Redis 键 blk:<jti>(hiredis %s 整参数本无注入面，
     * 此层是纵深防御) */
    if (out->jti[0]) {
        for (char *p = out->jti; *p; p++)
            if (!(*p >= 'a' && *p <= 'z') && !(*p >= 'A' && *p <= 'Z') &&
                !(*p >= '0' && *p <= '9') && *p != '-' && *p != '_') {
                *p = '_';   /* 白名单外字符统一替换，长度与可读性保留 */
            }
    }
    return 0;
}
