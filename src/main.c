/*
 * auth_server - 基于 Nginx auth_request 的鉴权网关
 *
 * 接收 Nginx auth_request 子请求，对请求依次执行:
 *   1. HTTP 走私检测(security.c)          -> 403
 *   2. WAF 特征检测(security.c)           -> 403
 *   3. JWT/Session/API Key 鉴权(auth.c)   -> 401/403
 *   4. Redis 注销黑名单(redis_client.c)   -> 401
 *   5. 固定窗口限流                       -> 429
 *   全部通过 -> 200 放行(X-User-Id 透传)
 *
 * 网络模型: 单线程 epoll(LT) + 非阻塞 socket，免锁。
 * 用法: ./auth_server [port] [--demo]
 * 配置: 环境变量 AUTH_SECRET / AUTH_PUBKEY / REDIS_HOST / REDIS_PORT /
 *       RL_LIMIT / AUTHFAIL_LIMIT / AUTH_ALG / TRUST_PROXY / WAF_RULES_FILE
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>

#include "http_parser.h"
#include "security.h"
#include "util.h"
#include "auth.h"
#include "jwt.h"
#include "redis_client.h"
#include <openssl/evp.h>
#include <openssl/pem.h>

#define MAX_CONNS     1024                    /* 连接池槽位数，也是并发连接上限 */
#define IN_BUF_INIT   4096                    /* 接收缓冲初始容量 */
#define IN_BUF_MAX    (2 * 1024 * 1024)       /* 单连接接收缓冲硬顶 2MB，超限 413 */
#define IDLE_TIMEOUT  60                      /* 空闲连接回收秒数 */

/* 单条客户端连接状态(连接池槽位，静态数组避免逐连接 malloc) */
typedef struct {
    int     fd;                                  /* -1 表示空槽 */
    char   *in;        size_t in_len, in_cap;    /* 接收缓冲(堆，按需倍增) */
    char   *out;       size_t out_len, out_cap, out_sent;   /* 响应缓冲，out_sent=已写出游标 */
    char    ip[48];                              /* 对端 IP(日志；限流键见 auth.c) */
    time_t  last_active;                         /* 空闲判定 */
    unsigned char in_use, want_write, closing;   /* 槽位占用 / 已订阅 EPOLLOUT / 响应后待关闭 */
} conn_t;

/* 运行配置(启动时收集一次，此后只读) */
static struct {
    const char *secret;      /* JWT HS256 共享密钥(env AUTH_SECRET) */
    char redis_host[64];
    int  redis_port;
    int  rl_limit;           /* 每窗口每标识请求上限 */
    int  rl_window;          /* 窗口秒数 */
    int  fail_limit;         /* 失败锁定阈值(env AUTHFAIL_LIMIT) */
    int  demo_mode;          /* 1=跳过鉴权(联调) */
    int  trust_proxy;        /* 网关模式: 限流/锁定键用 X-Real-IP，监听收窄 127.0.0.1 */
    char rules_file[160];    /* WAF 规则文件路径 */
} cfg;

static redis_ctx_t *rds;         /* demo 模式下保持 NULL */
static int epfd = -1;
static conn_t conns[MAX_CONNS];
static EVP_PKEY *rs_pkey;        /* RS256 公钥；NULL=未启用 */

/* 请求日志: 时间 方法 URI -> 状态码 (原因) */
static void log_req(const conn_t *c, const char *method, const char *uri,
                    int code, const char *note)
{
    (void)c;
    char ts[32];
    time_t now = time(NULL);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(stderr, "[%s] %s %s -> %d (%s)\n", ts,
            method ? method : "-", uri ? uri : "-", code, note ? note : "");
}

/* 关闭并回收连接。返回后 c 指针即失效，之后一律不再触碰 */
static void conn_close(conn_t *c)
{
    if (c->fd >= 0) {
        epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);   /* 不摘表会残留悬空指针事件 */
        close(c->fd);
    }
    free(c->in);
    free(c->out);
    memset(c, 0, sizeof(*c));
    c->fd = -1;
}

/* 倍增扩容追加。返回 0 成功 / -1 超顶(maxcap)或 realloc 失败 */
static int buf_append(char **buf, size_t *len, size_t *cap,
                      const char *data, size_t n, size_t maxcap)
{
    if (*len + n > maxcap) return -1;
    if (*len + n > *cap) {
        size_t ncap = *cap ? *cap * 2 : IN_BUF_INIT;
        while (ncap < *len + n) ncap *= 2;
        char *nb = realloc(*buf, ncap);
        if (!nb) return -1;
        *buf = nb; *cap = ncap;
    }
    memcpy(*buf + *len, data, n);
    *len += n;
    return 0;
}

/* 重设连接的 epoll 关注事件；data.ptr 回指 conn_t 便于分派时 O(1) 还原 */
static void ep_update(conn_t *c, unsigned events)
{
    struct epoll_event ev;
    ev.events = events | EPOLLRDHUP;
    ev.data.ptr = c;
    epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev);
}

/* 尽量写完 out 缓冲: EAGAIN 则订阅 EPOLLOUT 等续写，写完时 closing 则关连接 */
static void flush_out(conn_t *c)
{
    while (c->out_sent < c->out_len) {
        ssize_t n = write(c->fd, c->out + c->out_sent, c->out_len - c->out_sent);
        if (n > 0) { c->out_sent += (size_t)n; continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            c->want_write = 1;
            ep_update(c, EPOLLIN | EPOLLOUT);
            return;
        }
        conn_close(c);
        return;
    }
    c->out_len = c->out_sent = 0;
    if (c->closing) { conn_close(c); return; }   /* 非 keep-alive: 响应落地即断 */
    if (c->want_write) { c->want_write = 0; ep_update(c, EPOLLIN); }
}

static const char *status_text(int code)
{
    switch (code) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 429: return "Too Many Requests";
    case 413: return "Payload Too Large";
    case 414: return "URI Too Long";
    case 431: return "Request Header Fields Too Large";
    case 501: return "Not Implemented";
    default:  return "Error";
    }
}

/* 组装响应(头 + JSON 体)追加进 out 缓冲并尝试写出 */
static void respond(conn_t *c, int code, const char *extra_hdr,
                    const char *body, int keep_alive)
{
    char hdr[1024];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Server: auth-gw/0.1\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "%s"
        "Connection: %s\r\n"
        "\r\n",
        code, status_text(code), strlen(body),
        extra_hdr ? extra_hdr : "",
        keep_alive ? "keep-alive" : "close");

    c->closing = (unsigned char)!keep_alive;
    if (buf_append(&c->out, &c->out_len, &c->out_cap, hdr, (size_t)n, 1 << 20) == 0 &&
        buf_append(&c->out, &c->out_len, &c->out_cap, body, strlen(body), 1 << 20) == 0)
        flush_out(c);
    else
        conn_close(c);
}

/* 本请求处理后连接是否保活: Connection 头显式声明优先，缺省按版本 */
static int is_keep_alive(const http_request_t *r)
{
    char v[64] = {0};
    if (r->connection && r->connection_len && r->connection_len < sizeof(v)) {
        memcpy(v, r->connection, r->connection_len);
        ascii_lower(v, r->connection_len);
        if (strstr(v, "close")) return 0;
        if (strstr(v, "keep-alive")) return 1;
    }
    return r->http_minor >= 1;
}

/* 请求处理编排: 解析 → 走私/WAF 检测 → 鉴权 → 响应 → 流水线续传。
 * req 用 static 复用避免反复入栈(单线程环境)；while 消化粘包流水线 */
static void process(conn_t *c)
{
    static http_request_t req;

    while (c->in_len > 0 && !c->closing) {   /* 已声明关闭则不再处理下一条 */
        http_request_init(&req);
        int rc = http_parse(&req, c->in, c->in_len);

        if (rc == PARSE_NEED_MORE) {
            http_request_free(&req);      /* 释放半包可能的 chunk 缓冲，等数据 */
            return;
        }
        if (rc == PARSE_ERR) {
            char body[128];
            snprintf(body, sizeof(body), "{\"error\":\"bad_request\",\"code\":%d}", req.err);
            log_req(c, NULL, NULL, req.err, "parse error");
            respond(c, req.err, NULL, body, 0);   /* 协议已错位，不保活 */
            http_request_free(&req);
            return;
        }

        /* 日志用方法/URI: URI 优先 X-Original-URI(网关注入的客户端原始 URI) */
        char method[16] = "-", uri[256] = "-";
        if (req.method_len && req.method_len < sizeof(method)) {
            memcpy(method, req.method_s, req.method_len); method[req.method_len] = 0;
        }
        const char *u = (req.x_orig_uri && req.x_orig_uri_len) ? req.x_orig_uri : req.uri;
        size_t ul = (req.x_orig_uri && req.x_orig_uri_len) ? req.x_orig_uri_len : req.uri_len;
        if (ul && ul < sizeof(uri)) { memcpy(uri, u, ul); uri[ul] = 0; }

        char reason[128] = {0}, rule[16] = {0}, extra[256] = {0};
        int code;

        if (smuggling_check(&req, reason, sizeof(reason))) {   /* 1) 走私 → 403 */
            code = 403;
            snprintf(extra, sizeof(extra), "X-Security-Block: request-smuggling\r\n"
                                           "X-Security-Reason: %s\r\n", reason);
            log_req(c, method, uri, code, reason);
        } else if (waf_check(&req, rule, sizeof(rule))) {      /* 2) WAF → 403 */
            code = 403;
            snprintf(extra, sizeof(extra), "X-Security-Block: waf\r\n"
                                           "X-WAF-Rule: %s\r\n", rule);
            log_req(c, method, uri, code, rule);
        } else if (cfg.demo_mode) {                            /* 3) demo 直通 */
            code = 200;
            snprintf(extra, sizeof(extra), "X-Auth-Result: demo-allow\r\n");
            log_req(c, method, uri, code, "demo mode");
        } else {                                               /* 4) 完整鉴权链 */
            char note[192], user[64];
            code = auth_check(&req, c->ip, user, sizeof(user),
                              note, sizeof(note), extra, sizeof(extra));
            log_req(c, method, uri, code, note);
        }

        char body[192];
        if (code == 200)
            snprintf(body, sizeof(body), "{\"result\":\"allow\"}");
        else if (code == 401 && !rule[0] && !reason[0])
            snprintf(body, sizeof(body), "{\"error\":\"unauthorized\"}");
        else if (code == 429)
            snprintf(body, sizeof(body), "{\"error\":\"rate_limited\"}");
        else if (rule[0])
            snprintf(body, sizeof(body), "{\"error\":\"forbidden\",\"rule\":\"%s\"}", rule);
        else
            snprintf(body, sizeof(body), "{\"error\":\"forbidden\",\"reason\":\"%s\"}", reason);

        int keep = is_keep_alive(&req);
        size_t consumed = req.consumed;   /* 先保存: free 之后 req 即失效 */
        http_request_free(&req);
        respond(c, code, extra, body, keep);

        if (!c->in_use) return;           /* respond 可能已关连接 */
        memmove(c->in, c->in + consumed, c->in_len - consumed);   /* 裁掉已消费前缀 */
        c->in_len -= consumed;
    }
}

/* 可读事件: 读到 EAGAIN 为止(LT 模式必须读尽)，交给 process。
 * 对端 FIN 不在此直接关——先处理已到数据并响应，再断开 */
static void on_readable(conn_t *c)
{
    char tmp[16384];
    int eof = 0;
    while (1) {
        ssize_t n = read(c->fd, tmp, sizeof(tmp));
        if (n > 0) {
            if (buf_append(&c->in, &c->in_len, &c->in_cap, tmp, (size_t)n, IN_BUF_MAX) != 0) {
                respond(c, 413, NULL, "{\"error\":\"payload too large\"}", 0);
                return;
            }
            c->last_active = time(NULL);
            continue;
        }
        if (n == 0) { eof = 1; break; }
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        if (errno == EINTR) continue;
        conn_close(c);
        return;
    }
    process(c);
    if (!c->in_use) return;
    if (eof) {
        c->closing = 1;   /* 半关闭: 本批处理完即断，响应经 flush_out 落地后关闭 */
        flush_out(c);
    }
}

/* accept 新连接 → 找空槽初始化 → 入 epoll。槽满返回 NULL(并发上限即 DoS 边界) */
static conn_t *conn_accept(int lfd)
{
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    int fd = accept4(lfd, (struct sockaddr *)&ss, &slen, SOCK_NONBLOCK);
    if (fd < 0) return NULL;

    conn_t *c = NULL;
    for (int i = 0; i < MAX_CONNS; i++)
        if (!conns[i].in_use) { c = &conns[i]; break; }
    if (!c) { close(fd); return NULL; }

    memset(c, 0, sizeof(*c));             /* 清槽: 清掉旧缓冲指针 */
    c->fd = fd;
    c->last_active = time(NULL);
    c->in_use = 1;
    if (ss.ss_family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        inet_ntop(AF_INET, &a->sin_addr, c->ip, sizeof(c->ip));
    } else {
        snprintf(c->ip, sizeof(c->ip), "unix");
    }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLRDHUP;     /* 只订可读，可写按需再开 */
    ev.data.ptr = c;
    epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
    return c;
}

int main(int argc, char **argv)
{
    int port = 8081;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--demo") == 0) cfg.demo_mode = 1;
        else port = atoi(argv[i]);
    }

    /* 配置收集: 环境变量优先，缺省值兜底。生产必须注入真实 AUTH_SECRET */
    cfg.secret = getenv("AUTH_SECRET");
    if (!cfg.secret || !cfg.secret[0]) {
        cfg.secret = "dev-secret-change-me";
        fprintf(stderr, "warn: AUTH_SECRET not set - using INSECURE default (dev/demo only)\n");
    }
    snprintf(cfg.redis_host, sizeof(cfg.redis_host), "%s",
             (getenv("REDIS_HOST") && getenv("REDIS_HOST")[0]) ? getenv("REDIS_HOST") : "127.0.0.1");
    cfg.redis_port = getenv("REDIS_PORT") ? atoi(getenv("REDIS_PORT")) : 6379;
    cfg.rl_limit = getenv("RL_LIMIT") ? atoi(getenv("RL_LIMIT")) : 100;
    if (cfg.rl_limit <= 0) cfg.rl_limit = 100;
    cfg.rl_window = 60;
    cfg.fail_limit = getenv("AUTHFAIL_LIMIT") ? atoi(getenv("AUTHFAIL_LIMIT")) : 20;
    if (cfg.fail_limit <= 0) cfg.fail_limit = 20;

    /* RS256 公钥加载; 非配置即禁用。PEM_read_PUBKEY 什么类型都收，
     * RS256 要求 RSA——非 RSA 公钥拒绝启用，防类型混淆验签 */
    const char *pub = getenv("AUTH_PUBKEY");
    if (pub && pub[0]) {
        FILE *pf = fopen(pub, "r");
        if (pf) {
            rs_pkey = PEM_read_PUBKEY(pf, NULL, NULL, NULL);
            fclose(pf);
        }
        int bad_type = 0;
        if (rs_pkey && EVP_PKEY_base_id(rs_pkey) != EVP_PKEY_RSA) {
            bad_type = 1;
            EVP_PKEY_free(rs_pkey);
            rs_pkey = NULL;
        }
        if (bad_type)
            fprintf(stderr, "warn: %s is not an RSA public key (RS256 disabled)\n", pub);
        else if (!rs_pkey)
            fprintf(stderr, "warn: load RS256 pubkey failed: %s (RS256 disabled)\n", pub);
    }

    /* AUTH_ALG=rs256: 锁定单算法，HS256 一律按算法混淆 403 */
    const char *alg = getenv("AUTH_ALG");
    if (alg && strcmp(alg, "rs256") == 0) {
        jwt_set_alg_policy(0);
        fprintf(stderr, "auth policy: RS256-only (HS256 rejected as alg-confusion)\n");
    }

    /* TRUST_PROXY=1: 挂网关时限流/锁定键改用 X-Real-IP(TCP 对端恒为本机，
     * socket IP 无区分度)；监听同步收窄 127.0.0.1——信任头只对仅网关可达
     * 的部署安全，外部直连 8081 可伪造头绕过限流 */
    cfg.trust_proxy = (getenv("TRUST_PROXY") && strcmp(getenv("TRUST_PROXY"), "1") == 0);
    if (cfg.trust_proxy)
        fprintf(stderr, "trust proxy: on (limit keys use X-Real-IP, bind 127.0.0.1)\n");

    snprintf(cfg.rules_file, sizeof(cfg.rules_file), "%s",
             (getenv("WAF_RULES_FILE") && getenv("WAF_RULES_FILE")[0])
                 ? getenv("WAF_RULES_FILE") : "deploy/waf_rules.txt");

    signal(SIGPIPE, SIG_IGN);   /* 对已关闭 socket write 默认杀死进程，改由 EPIPE 分诊 */

    int lfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (lfd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = cfg.trust_proxy ? htonl(INADDR_LOOPBACK) : htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(lfd, 128) < 0) { perror("listen"); return 1; }

    epfd = epoll_create1(0);
    if (epfd < 0) { perror("epoll_create1"); return 1; }

    struct epoll_event ev;
    ev.events = EPOLLIN;                  /* 监听 fd 只关心可读 */
    ev.data.ptr = NULL;                   /* NULL 标识监听 fd */
    epoll_ctl(epfd, EPOLL_CTL_ADD, lfd, &ev);

    for (int i = 0; i < MAX_CONNS; i++) conns[i].fd = -1;

    if (!cfg.demo_mode) {
        rds = redis_connect_ctx(cfg.redis_host, cfg.redis_port);
        fprintf(stderr, "redis: %s (%s:%d)\n",
                redis_alive(rds) ? "connected" : "unavailable(degraded)",
                cfg.redis_host, cfg.redis_port);
    }

    auth_deps_t dep = { cfg.secret, rs_pkey, rds,
                        cfg.rl_limit, cfg.rl_window, cfg.fail_limit, 300,
                        cfg.trust_proxy };
    auth_init(&dep);

    /* WAF 规则文件外部加载，fail-fast: 缺失/格式错/零规则拒绝启动 */
    if (waf_init(cfg.rules_file) != 0) {
        fprintf(stderr, "waf: init failed (%s) - refusing to start\n", cfg.rules_file);
        return 1;
    }

    fprintf(stderr, "auth-gw/0.1 listening on :%d mode=%s limit=%d/%ds "
            "fail_lock=%d/300s rs256=%s secret=%s\n",
            port, cfg.demo_mode ? "demo" : "jwt+session+apikey",
            cfg.rl_limit, cfg.rl_window, cfg.fail_limit,
            rs_pkey ? "on" : "off", cfg.demo_mode ? "-" : "env:AUTH_SECRET");

    struct epoll_event evs[256];
    time_t last_sweep = time(NULL);
    while (1) {
        int n = epoll_wait(epfd, evs, 256, 1000);   /* 1s 超时兼作空闲扫描节拍 */
        if (n < 0 && errno != EINTR) { perror("epoll_wait"); break; }

        for (int i = 0; i < n; i++) {
            if (evs[i].data.ptr == NULL) {          /* 哨兵: 监听 fd 可读 */
                while (conn_accept(lfd)) {}         /* 一次收完，防 LT 反复唤醒 */
                continue;
            }
            conn_t *c = evs[i].data.ptr;
            if (evs[i].events & EPOLLERR) { conn_close(c); continue; }
            if (evs[i].events & EPOLLOUT) flush_out(c);
            if (!c->in_use) continue;               /* flush_out 里可能已关连接 */
            /* RDHUP/HUP 不在此直接关: 对端发完请求立刻 FIN 时数据与 FIN 并进
             * 同一事件，先关就读丢请求——统一交给 on_readable 处理完再断 */
            if (evs[i].events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP)) on_readable(c);
        }

        time_t now = time(NULL);
        if (now - last_sweep >= 5) {
            last_sweep = now;
            for (int i = 0; i < MAX_CONNS; i++)
                if (conns[i].in_use && now - conns[i].last_active > IDLE_TIMEOUT)
                    conn_close(&conns[i]);
        }
    }
    return 0;
}
