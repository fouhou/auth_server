#include "http_parser.h"
#include <string.h>
#include <strings.h>
#include <stdlib.h>

/*
 * HTTP/1.x 零拷贝状态机解析
 *
 *   ST_REQ_LINE ─→ ST_HEADERS ─┬─(CL)─→ ST_BODY_CL ─→ ST_DONE
 *                              └─(chunked)─→ ST_CHUNK_SIZE ⇄ ST_CHUNK_DATA
 *                                                │(size=0)
 *                                                ↓
 *                                             ST_TRAILER ─→ ST_DONE
 *
 * 每条 case 做三件事: 找行边界 → 校验/采集 → 前移 p 并切状态。
 * 数据不够时返回 PARSE_NEED_MORE，状态停在原地等下次续跑。
 * 走私特征(CL/TE 歧义等)在头部阶段同步采集进 findings 位图，
 * 证据此刻不采集后面就拿不到了。
 */

enum {
    ST_REQ_LINE = 0, ST_HEADERS, ST_BODY_CL,
    ST_CHUNK_SIZE, ST_CHUNK_DATA, ST_CHUNK_CRLF, ST_TRAILER, ST_DONE
};

void http_request_init(http_request_t *r)
{
    memset(r, 0, sizeof(*r));
    r->state = ST_REQ_LINE;
}

/* 只 chunk_body 是堆内存(CL 路径 body 是零拷贝指针)；不 free 会泄漏 */
void http_request_free(http_request_t *r)
{
    free(r->chunk_body);
    r->chunk_body = NULL;
    r->chunk_body_len = 0;
}

/* 在 [p, p+n) 找行尾。*eff 为剔除 \r\n 后的有效长度；裸 \n 也接受(宽松行读) */
static const char *find_line(const char *p, size_t n, size_t *eff)
{
    const char *nl = memchr(p, '\n', n);
    if (!nl) return NULL;
    size_t l = (size_t)(nl - p);
    if (l > 0 && p[l - 1] == '\r') l--;
    *eff = l;
    return nl;
}

/* 未识别方法返回 M_OTHER，不在此拒绝——交给上层裁决 */
static http_method_t method_of(const char *s, size_t n)
{
#define EQ(lit) (n == strlen(lit) && memcmp(s, lit, n) == 0)
    if (EQ("GET")) return M_GET;
    if (EQ("POST")) return M_POST;
    if (EQ("PUT")) return M_PUT;
    if (EQ("DELETE")) return M_DELETE;
    if (EQ("HEAD")) return M_HEAD;
    if (EQ("OPTIONS")) return M_OPTIONS;
    if (EQ("PATCH")) return M_PATCH;
    return M_OTHER;
#undef EQ
}

/* CL 值词法校验: 只认纯十进制数字；逐位累加边乘边判溢出(不用 strtol)；
 * n>12 直接拒绝——1MB body 最多 7 位数。返回 1 合法 / 0 非法 */
static int cl_value_ok(const char *s, size_t n, size_t *out)
{
    if (n == 0 || n > 12) return 0;
    size_t v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return 0;
        v = v * 10 + (size_t)(s[i] - '0');
        if (v > MAX_BODY) return 0;
    }
    if (out) *out = v;
    return 1;
}

/* 头名 token 合法性(RFC 7230 tchar): 非法不中断解析，只记 F_HDR_TOK 证据 */
static int header_name_ok(const char *s, size_t n)
{
    if (n == 0) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c <= 32 || c >= 127) return 0;
        if (strchr("()<>@,;:\\\"/[]?={}", c)) return 0;
    }
    return 1;
}

/* 头名大小写无关比较; 先比长度避免前缀误匹配 */
static int name_is(const http_header_t *h, const char *lit)
{
    size_t n = strlen(lit);
    if (h->name_len != n) return 0;
    return strncasecmp(h->name, lit, n) == 0;
}

/* 原地剥头值前导 SP/HTAB(OWS)，零拷贝风格 */
static int trim_sp(const char **s, size_t *n)
{
    while (*n > 0 && ((*s)[0] == ' ' || (*s)[0] == '\t')) { (*s)++; (*n)--; }
    return 0;
}

/* chunked 重组缓冲追加。首块到来时一次 malloc MAX_CHUNK，之后只 memcpy */
static int chunk_buf_append(http_request_t *r, const char *data, size_t n)
{
    if (n == 0) return 0;
    size_t need = r->chunk_body_len + n;
    if (need > MAX_BODY || need > (size_t)1 << 20) return -1;
    if (!r->chunk_body) {
        r->chunk_body = malloc(MAX_CHUNK);
        if (!r->chunk_body) return -1;
    }
    memcpy(r->chunk_body + r->chunk_body_len, data, n);
    r->chunk_body_len += n;
    return 0;
}

/* 状态机主入口。r->state 记录断点，NEED_MORE 后带着更多数据续跑 */
int http_parse(http_request_t *r, const char *buf, size_t len)
{
    const char *p = buf;      /* 输入窗口游标，全程零拷贝 */
    size_t avail = len;

    while (1) {
        switch (r->state) {
        case ST_REQ_LINE: {
            size_t eff;
            const char *nl = find_line(p, avail, &eff);
            if (!nl) {
                if (avail > MAX_LINE) { r->err = 414; return PARSE_ERR; }
                return PARSE_NEED_MORE;
            }
            if (eff > MAX_LINE) { r->err = 414; return PARSE_ERR; }

            /* 请求行三段式: METHOD SP URI SP HTTP/1.x */
            size_t m_end = 0;
            while (m_end < eff && p[m_end] != ' ') m_end++;
            if (m_end == 0 || m_end >= eff || m_end > 15) { r->err = 400; return PARSE_ERR; }
            r->method_s = p; r->method_len = m_end;
            r->method = method_of(p, m_end);

            size_t u_start = m_end + 1, u_end = u_start;
            while (u_end < eff && p[u_end] != ' ') u_end++;
            if (u_end == u_start || u_end >= eff) { r->err = 400; return PARSE_ERR; }
            if (u_end - u_start > MAX_URI) { r->err = 414; return PARSE_ERR; }
            r->uri = p + u_start; r->uri_len = u_end - u_start;

            size_t v_start = u_end + 1, v_len = eff - v_start;
            if (v_len != 8 || memcmp(p + v_start, "HTTP/1.", 7) != 0 ||
                (p[v_start + 7] != '0' && p[v_start + 7] != '1')) {
                r->err = 400; return PARSE_ERR;
            }
            r->http_minor = p[v_start + 7] - '0';

            avail -= (size_t)(nl - p) + 1;
            p = nl + 1;
            r->state = ST_HEADERS;
            break;
        }

        case ST_HEADERS: {
            size_t eff;
            const char *nl = find_line(p, avail, &eff);
            if (!nl) {
                if (avail > MAX_LINE) { r->err = 431; return PARSE_ERR; }
                return PARSE_NEED_MORE;
            }
            if (eff > MAX_LINE) { r->err = 431; return PARSE_ERR; }

            if (eff == 0) {  /* 空行: 头结束，此处做走私证据结算与 body 分派 */
                if (r->cl_count > 0 && r->te_count > 0)
                    r->findings |= F_CLTE_DUP;
                if (r->cl_count > 1)
                    r->findings |= F_CL_MULTI;

                size_t body_cl = 0;
                for (int i = 0; i < r->cl_count && i < 4; i++) {
                    size_t v;
                    if (!cl_value_ok(r->cl_raw[i], r->cl_raw_len[i], &v))
                        r->findings |= F_CL_INVALID;
                    else if (body_cl == 0)
                        body_cl = v;   /* 多 CL 冲突取首个合法值，分歧已记证据 */
                }

                int is_chunked = 0;
                if (r->te_count > 0) {
                    if (r->te_count > 1) r->findings |= F_TE_OBSCURE;
                    if (r->transfer_encoding_len == 7 &&
                        strncasecmp(r->transfer_encoding, "chunked", 7) == 0)
                        is_chunked = 1;
                    else
                        r->findings |= F_TE_OBSCURE;  /* identity/逗号组合等 */
                }

                if (is_chunked) {
                    r->state = ST_CHUNK_SIZE;
                } else if (body_cl > 0) {
                    r->body_len = body_cl;
                    r->state = ST_BODY_CL;
                } else {
                    r->state = ST_DONE;
                }

                avail -= (size_t)(nl - p) + 1;
                p = nl + 1;
                break;
            }

            /* 常规头行: 名 : 值 */
            const char *colon = memchr(p, ':', eff);
            if (!colon) { r->err = 400; return PARSE_ERR; }

            http_header_t *h = &r->hdrs[r->nhdrs];
            h->name = p; h->name_len = (size_t)(colon - p);
            h->value = colon + 1; h->value_len = eff - h->name_len - 1;
            trim_sp(&h->value, &h->value_len);

            if (!header_name_ok(h->name, h->name_len))
                r->findings |= F_HDR_TOK;
            if (r->nhdrs < MAX_HDRS - 1)
                r->nhdrs++;   /* 超上限只覆写末槽不计数，保证不越界 */

            /* 关键头快捷指针(重复头以最后一个为准，CL 例外——原始值留证) */
            if (name_is(h, "Content-Length")) {
                if (r->cl_count < 4) {
                    r->cl_raw[r->cl_count] = h->value;
                    r->cl_raw_len[r->cl_count] = h->value_len;
                }
                r->cl_count++;                 /* 超过 4 个仍计数，触发 F_CL_MULTI */
                r->content_length = h->value;
                r->content_length_len = h->value_len;
            } else if (name_is(h, "Transfer-Encoding")) {
                r->te_count++;
                r->transfer_encoding = h->value;
                r->transfer_encoding_len = h->value_len;
            } else if (name_is(h, "Connection")) {
                r->connection = h->value; r->connection_len = h->value_len;
            } else if (name_is(h, "User-Agent")) {
                r->user_agent = h->value; r->user_agent_len = h->value_len;
            } else if (name_is(h, "Referer")) {
                r->referer = h->value; r->referer_len = h->value_len;
            } else if (name_is(h, "Cookie")) {
                r->cookie = h->value; r->cookie_len = h->value_len;
            } else if (name_is(h, "Authorization")) {
                r->authorization = h->value; r->authorization_len = h->value_len;
            } else if (name_is(h, "X-Original-URI")) {
                r->x_orig_uri = h->value; r->x_orig_uri_len = h->value_len;
            } else if (name_is(h, "X-Original-Method")) {
                r->x_orig_method = h->value; r->x_orig_method_len = h->value_len;
            } else if (name_is(h, "X-Api-Key")) {
                r->api_key = h->value; r->api_key_len = h->value_len;
            } else if (name_is(h, "X-Real-IP")) {
                r->x_real_ip = h->value; r->x_real_ip_len = h->value_len;
            } else if (name_is(h, "X-Original-CL")) {
                r->x_orig_cl = h->value; r->x_orig_cl_len = h->value_len;
            } else if (name_is(h, "X-Original-TE")) {
                r->x_orig_te = h->value; r->x_orig_te_len = h->value_len;
            }

            avail -= (size_t)(nl - p) + 1;
            p = nl + 1;
            break;
        }

        case ST_BODY_CL: {
            if (avail < r->body_len) return PARSE_NEED_MORE;
            r->body = p;
            /* body 必须计入 consumed，否则字节残留污染流水线下一条请求 */
            avail -= r->body_len;
            r->state = ST_DONE;
            break;
        }

        case ST_CHUNK_SIZE: {
            size_t eff;
            const char *nl = find_line(p, avail, &eff);
            if (!nl) return (avail > MAX_LINE) ? (r->err = 400, PARSE_ERR)
                                               : PARSE_NEED_MORE;
            /* 块长行不允许为空: RFC 7230 要求至少 1 个 hex 位 */
            if (eff == 0) { r->err = 400; return PARSE_ERR; }
            size_t v = 0, i = 0;
            for (; i < eff && p[i] != ';'; i++) {   /* ';' 后是块扩展，忽略 */
                char c = p[i];
                int d = (c >= '0' && c <= '9') ? c - '0'
                      : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                      : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
                if (d < 0) { r->err = 400; return PARSE_ERR; }
                v = v * 16 + (size_t)d;
                if (v > MAX_CHUNK) { r->err = 413; return PARSE_ERR; }
            }
            if (r->chunk_body_len + v > MAX_BODY) { r->err = 413; return PARSE_ERR; }
            r->body_len = v;
            avail -= (size_t)(nl - p) + 1;
            p = nl + 1;
            r->state = (v == 0) ? ST_TRAILER : ST_CHUNK_DATA;
            break;
        }

        case ST_CHUNK_DATA: {
            if (avail < r->body_len + 2) return PARSE_NEED_MORE;
            if (p[r->body_len] != '\r' || p[r->body_len + 1] != '\n') {
                r->err = 400; return PARSE_ERR;   /* 块尾必须严格 CRLF */
            }
            if (chunk_buf_append(r, p, r->body_len) != 0) { r->err = 413; return PARSE_ERR; }
            avail -= r->body_len + 2;
            p += r->body_len + 2;
            r->state = ST_CHUNK_CRLF;
            break;
        }

        case ST_CHUNK_CRLF:
            r->state = ST_CHUNK_SIZE;   /* CRLF 已随数据一并消费，骨架状态 */
            break;

        case ST_TRAILER: {
            size_t eff;
            const char *nl = find_line(p, avail, &eff);
            if (!nl) return (avail > MAX_LINE) ? (r->err = 400, PARSE_ERR)
                                               : PARSE_NEED_MORE;
            if (eff == 0) {
                /* 终止空行必须消费，否则残留 "\r\n" 污染流水线下一条请求 */
                avail -= (size_t)(nl - p) + 1;
                p = nl + 1;
                r->state = ST_DONE;
            } else {
                /* trailer 藏 CL 是真实走私变体，采集证据 */
                if (eff >= 14 && strncasecmp(p, "content-length", 14) == 0)
                    r->findings |= F_TE_OBSCURE;
                avail -= (size_t)(nl - p) + 1;
                p = nl + 1;
            }
            break;
        }

        case ST_DONE: {
            r->consumed = len - avail;   /* 本请求总字节数(流水线下一条从此起) */
            if (r->body == NULL && r->chunk_body != NULL) {
                r->body = r->chunk_body;
                r->body_len = r->chunk_body_len;
            }
            return PARSE_OK;
        }

        default:
            r->err = 500;   /* 状态字损坏，兜底防死循环 */
            return PARSE_ERR;
        }
    }
}
