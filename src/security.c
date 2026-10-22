#include "security.h"
#include "util.h"
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>

/* 走私判定: findings 位图逐位翻译成拦截原因，命中任意一位即 403。
 * 网关模式下子请求无 body 且 CL 被清空，解析器采集不到客户端原始定界头，
 * 由 Nginx 以 X-Original-CL/TE 别名头透传，这里补做同款词法判定——
 * 只覆盖纯头证据类，TE.CL 等需 body 字节定界的形态由直连部署承担 */
int smuggling_check(const http_request_t *r, char *reason, size_t cap)
{
    if (r->findings & F_CLTE_DUP) {
        snprintf(reason, cap, "CL and TE in one request");
        return 1;
    }
    if (r->findings & F_CL_MULTI) {
        snprintf(reason, cap, "multiple/duplicated Content-Length");
        return 1;
    }
    if (r->findings & F_CL_INVALID) {
        snprintf(reason, cap, "malformed Content-Length value");
        return 1;
    }
    if (r->findings & F_TE_OBSCURE) {
        snprintf(reason, cap, "obscured Transfer-Encoding");
        return 1;
    }
    if (r->findings & F_HDR_TOK) {
        snprintf(reason, cap, "invalid character in header name");
        return 1;
    }

    {
        int gw_cl = (r->x_orig_cl && r->x_orig_cl_len > 0);
        int gw_te = (r->x_orig_te && r->x_orig_te_len > 0);

        if (gw_cl && gw_te) {
            snprintf(reason, cap, "CL and TE in one request (via gateway header)");
            return 1;
        }
        if (gw_cl) {
            /* 重复 CL 被 Nginx 以 ", " 拼接: 值含逗号即多 CL 分歧 */
            int comma = 0, bad = 0, digits = 0;
            for (size_t i = 0; i < r->x_orig_cl_len; i++) {
                char c = r->x_orig_cl[i];
                if (c == ' ') continue;
                if (c == ',') { comma = 1; continue; }
                if (c < '0' || c > '9') { bad = 1; break; }
                digits = 1;
            }
            if (comma) {
                snprintf(reason, cap, "multiple/duplicated Content-Length (via gateway header)");
                return 1;
            }
            if (bad || !digits) {
                snprintf(reason, cap, "malformed Content-Length value (via gateway header)");
                return 1;
            }
        }
        if (gw_te) {
            char te[64];
            size_t n = r->x_orig_te_len < sizeof(te) - 1 ? r->x_orig_te_len : sizeof(te) - 1;
            memcpy(te, r->x_orig_te, n);
            te[n] = '\0';
            for (char *p = te; *p; p++)
                if (*p >= 'A' && *p <= 'Z') *p = (char)(*p - 'A' + 'a');
            if (strchr(te, ',') || strcmp(te, "chunked") != 0) {
                snprintf(reason, cap, "obscured Transfer-Encoding (via gateway header)");
                return 1;
            }
        }
    }
    return 0;
}

/* ── WAF 规则层: 多轮解码归一化 → AC 自动机一次扫描 ── */

typedef struct {
    char *id;        /* 规则编号，进日志与 X-WAF-Rule 响应头 */
    char *pattern;   /* 匹配子串，全小写 */
} waf_rule_t;

/* 规则表从外部文件加载(deploy/waf_rules.txt)，进程生命周期持有 */
static waf_rule_t *RULES = NULL;
static int n_rules = 0;

/* 归一化输入窗口上限; body 按此窗口滚动扫描 */
#define NORM_CAP 8192

/* ── AC 自动机: 规则匹配内核 ──
 * 规则插入 Trie → BFS 建失败指针 → 空转移补全(全 goto 确定化)，
 * 匹配单循环无回退，O(文本长度)。
 * 终结节点存 fail 链上最小的规则表序，保证多规则同命中时
 * 输出与旧版逐条 strstr 的"表序优先"语义一致。 */

#define AC_SIGMA     256

typedef struct {
    unsigned short next[AC_SIGMA];        /* 确定化转移表; 0 = 转到根 */
    unsigned short fail;
    short rule;                           /* 命中的最小规则表序; -1 = 非终结 */
} ac_node_t;

/* 堆分配: 容量按规则文件统计精确定容，进程生命周期持有 */
static ac_node_t *AC = NULL;
static int ac_count = 0;
static int ac_cap = 0;

static int ac_insert(const char *pat, int rule_idx)
{
    int cur = 0;
    for (const char *p = pat; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (!AC[cur].next[c]) {
            if (ac_count >= ac_cap) return -1;
            AC[ac_count].rule = -1;
            AC[cur].next[c] = (unsigned short)ac_count++;
        }
        cur = AC[cur].next[c];
    }
    if (AC[cur].rule < 0 || rule_idx < AC[cur].rule)
        AC[cur].rule = (short)rule_idx;
    return 0;
}

/* BFS 逐深度处理: 算 v 的 fail 转移时父节点的转移表已确定化 */
static void ac_build_fail(void)
{
    int *queue = malloc(sizeof(int) * (size_t)ac_cap);
    if (!queue) return;
    int head = 0, tail = 0;
    for (int c = 0; c < AC_SIGMA; c++) {
        int v = AC[0].next[c];
        if (v) { AC[v].fail = 0; queue[tail++] = v; }
    }
    while (head < tail) {
        int u = queue[head++];
        for (int c = 0; c < AC_SIGMA; c++) {
            int v = AC[u].next[c];
            if (v) {
                AC[v].fail = AC[AC[u].fail].next[c];
                int fr = AC[AC[v].fail].rule;       /* 合并 fail 链上的终结表序 */
                if (fr >= 0 && (AC[v].rule < 0 || fr < AC[v].rule))
                    AC[v].rule = (short)fr;
                queue[tail++] = v;
            } else {
                AC[u].next[c] = AC[AC[u].fail].next[c];   /* 补全 = 确定化 */
            }
        }
    }
    free(queue);
}

/* 加载规则文件并构建自动机。两遍扫描: 先统计定容一次 calloc，再严格解析。
 * fail-fast: 文件缺失/零规则/格式错误行(带行号)返回 -1，调用方拒绝启动——
 * 规则表宁可不服务，不可静默丢规则带病运行 */
int waf_init(const char *rules_file)
{
    FILE *fp = fopen(rules_file, "r");
    if (!fp) return -1;

    int cap_rules = 0;
    long cap_chars = 1;                    /* 根节点 */
    char line[192];
    while (fgets(line, sizeof(line), fp)) {
        cap_rules++;
        cap_chars += (long)strlen(line);
    }

    RULES = calloc(cap_rules > 0 ? (size_t)cap_rules : 1, sizeof(waf_rule_t));
    AC = calloc((size_t)cap_chars, sizeof(ac_node_t));
    ac_cap = (int)cap_chars;
    if (!RULES || !AC) { fclose(fp); return -1; }
    ac_count = 1;
    AC[0].rule = -1;

    int lineno = 0;
    rewind(fp);
    while (fgets(line, sizeof(line), fp)) {
        lineno++;
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[--len] = '\0';
        if (len + 1 == sizeof(line)) {
            fprintf(stderr, "waf rules %s:%d line too long\n", rules_file, lineno);
            fclose(fp); return -1;
        }
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '#') continue;                 /* 空行/注释 */
        char *bar = strchr(p, '|');
        if (!bar) {
            fprintf(stderr, "waf rules %s:%d missing '|'\n", rules_file, lineno);
            fclose(fp); return -1;
        }
        *bar = '\0';
        char *id = p, *pat = bar + 1;
        while (*pat == ' ' || *pat == '\t') pat++;
        size_t plen = strlen(pat);
        while (plen > 0 && (pat[plen - 1] == ' ' || pat[plen - 1] == '\t' ||
                            pat[plen - 1] == '\r'))
            pat[--plen] = '\0';
        if (!id[0] || id[0] != 'R' || plen == 0 || plen > 160) {
            fprintf(stderr, "waf rules %s:%d bad format\n", rules_file, lineno);
            fclose(fp); return -1;
        }
        for (const char *q = id + 1; *q; q++) {
            if (*q < '0' || *q > '9') {
                fprintf(stderr, "waf rules %s:%d bad rule id\n", rules_file, lineno);
                fclose(fp); return -1;
            }
        }
        ascii_lower(pat, plen);            /* 强制小写: 大写规则会静默失效 */
        RULES[n_rules].id = strdup(id);
        RULES[n_rules].pattern = strdup(pat);
        if (!RULES[n_rules].id || !RULES[n_rules].pattern) { fclose(fp); return -1; }
        if (ac_insert(RULES[n_rules].pattern, n_rules) != 0) { fclose(fp); return -1; }
        n_rules++;
    }
    fclose(fp);

    if (n_rules == 0) {
        fprintf(stderr, "waf rules %s: no valid rules\n", rules_file);
        return -1;
    }
    ac_build_fail();
    fprintf(stderr, "waf: %d rules loaded from %s\n", n_rules, rules_file);
    return 0;
}

/* 长度定界扫描，返回命中的最小规则表序 / -1 */
static int ac_match(const char *buf, size_t n)
{
    int cur = 0, best = -1;
    for (size_t i = 0; i < n; i++) {
        cur = (int)AC[cur].next[(unsigned char)buf[i]];
        if (AC[cur].rule >= 0 && (best < 0 || AC[cur].rule < best))
            best = AC[cur].rule;
    }
    return best;
}

/* 多轮解码 + 归一化: 每轮 = URL 解码 + HTML 实体解码，再小写化与空白归一。
 * URI 用 3 轮防多重编码，头/体用 1 轮；plus=1 时 '+' 视作空格。
 * 解码失败 fail-safe: 保留上一轮已解码内容继续匹配，绝不置空致盲。
 * NUL 归一为 '_'，防 %00 解码产物截断后续匹配 */
static size_t normalize(const char *src, size_t srclen, int rounds, int plus,
                        char *dst, size_t dstcap)
{
    char tmp[NORM_CAP];
    size_t n = srclen;
    if (n > NORM_CAP) n = NORM_CAP;
    memcpy(tmp, src, n);

    for (int i = 0; i < rounds; i++) {
        char out[NORM_CAP];
        size_t outn = 0;
        if (url_decode(tmp, n, out, NORM_CAP, &outn, plus) != 0)
            break;                          /* 保留上一轮产物继续匹配 */
        size_t hn = outn;
        html_decode(out, outn, out, NORM_CAP, &hn);
        memcpy(tmp, out, hn);
        n = hn;
    }
    if (n > dstcap) n = dstcap;
    for (size_t i = 0; i < n; i++) {
        char c = tmp[i];
        if (c == '\t' || c == '\n' || c == '\r') c = ' ';
        if (c == '\0') c = '_';
        dst[i] = (char)((c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c);
    }
    return n;
}

static int match_rules(const char *buf, size_t n, char *rule_id, size_t cap)
{
    int idx = ac_match(buf, n);
    if (idx < 0) return 0;
    snprintf(rule_id, cap, "%s", RULES[idx].id);
    return 1;
}

/* WAF 主入口。检测目标与策略:
 *   0) CRLF 注入(查原始串)   1) URI(3 轮解码)
 *   2) UA/Referer/Cookie(1 轮)   3) Body(8KB 窗口滚动扫描) */
int waf_check(const http_request_t *r, char *rule_id, size_t cap)
{
    /* 网关模式取 X-Original-URI(客户端原始请求)，子请求自身 URI 恒为 /auth */
    const char *uri = (r->x_orig_uri && r->x_orig_uri_len) ? r->x_orig_uri : r->uri;
    size_t uri_len = (r->x_orig_uri && r->x_orig_uri_len) ? r->x_orig_uri_len : r->uri_len;

    /* 0) CRLF 注入: 编码形态与裸形态双判据，查原始串 */
    {
        char raw[NORM_CAP];
        size_t n = uri_len < NORM_CAP - 1 ? uri_len : NORM_CAP - 1;
        memcpy(raw, uri, n);
        ascii_lower(raw, n);
        raw[n] = '\0';
        for (size_t i = 0; i < n; i++)
            if (raw[i] == '\0') raw[i] = '_';
        if (strstr(raw, "%0d%0a") || strstr(raw, "%0a%0d") ||
            memchr(uri, '\n', uri_len) || memchr(uri, '\r', uri_len)) {
            snprintf(rule_id, cap, "R9501");
            return 1;
        }
    }

    /* 1) URI: 3 轮解码防双重编码，'+' 视作空格 */
    {
        char buf[NORM_CAP + 1];
        size_t n = normalize(uri, uri_len, 3, 1, buf, NORM_CAP);
        buf[n] = '\0';
        if (match_rules(buf, n, rule_id, cap)) return 1;
    }

    /* 2) 头部字段: 一轮解码 */
    struct { const char *s; size_t len; } fields[] = {
        { r->user_agent, r->user_agent_len },
        { r->referer,    r->referer_len },
        { r->cookie,     r->cookie_len },
    };
    for (size_t f = 0; f < 3; f++) {
        if (!fields[f].s || fields[f].len == 0) continue;
        char buf[NORM_CAP + 1];
        size_t n = normalize(fields[f].s, fields[f].len, 1, 0, buf, NORM_CAP);
        buf[n] = '\0';
        if (match_rules(buf, n, rule_id, cap)) return 1;
    }

    /* 3) Body: 8KB 窗口按"窗口-64B 重叠"步进滚动，跨窗指纹不漏检 */
    if (r->body && r->body_len > 0) {
        char buf[NORM_CAP + 1];
        const size_t STEP = NORM_CAP - 64;
        size_t off = 0;
        while (off < r->body_len) {
            size_t wlen = r->body_len - off;
            if (wlen > NORM_CAP) wlen = NORM_CAP;
            size_t n = normalize(r->body + off, wlen, 1, 0, buf, NORM_CAP);
            buf[n] = '\0';
            if (match_rules(buf, n, rule_id, cap)) return 1;
            if (r->body_len - off <= NORM_CAP) break;
            off += STEP;
        }
    }
    return 0;
}
