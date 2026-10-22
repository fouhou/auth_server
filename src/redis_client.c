#include "redis_client.h"
#include <hiredis/hiredis.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

/* 上下文实体的不透明结构(对外只暴露 redis_ctx_t 前置声明)
 * c    : hiredis 连接句柄；NULL = 从未连上或已断开(降级状态标记)
 * host : 连接地址快照——断线重连时复用，调用方无需再传
 * port : 连接端口快照，同上 */
struct redis_ctx_s {
    redisContext *c;
    char host[64];
    int  port;
};

/* 带超时建连: 连接 1s + 读写 1s。同步阻塞模型下无超时 = 网络黑洞时
 * TCP 默认重试两分钟以上，单线程事件循环整体停摆；有界失败后走 -1 降级 */
static redisContext *dial(const char *host, int port)
{
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    redisContext *c = redisConnectWithTimeout(host, port, tv);   /* 本机 hiredis 按值收 timeval */
    if (c && !c->err)
        redisSetTimeout(c, tv);   /* 读写同 1s: Redis 挂起(收请求不回包)时有界失败 */
    return c;
}

/* 建立连接(契约见 redis_client.h): calloc 清零 → 快照 host/port 作重连依据
 * → 首连，失败打日志并保留 ctx 壳，后续调用走 -1 降级 */
redis_ctx_t *redis_connect_ctx(const char *host, int port)
{
    redis_ctx_t *x = calloc(1, sizeof(*x));   /* 清零: 未连上时 c 恒为 NULL */
    if (!x) return NULL;
    snprintf(x->host, sizeof(x->host), "%s", host);
    x->port = port;
    x->c = dial(host, port);                  /* hiredis 同步 TCP 连接(带超时) */
    if (!x->c || x->c->err) {                 /* 两种失败: 分配失败 / 连接错误 */
        fprintf(stderr, "redis connect %s:%d failed: %s\n", host, port,
                x->c ? x->c->errstr : "alloc fail");
        if (x->c) { redisFree(x->c); x->c = NULL; }
    }
    return x;
}

/* 健康检查: 指针、句柄、错误位三者全过才算活着 */
int redis_alive(const redis_ctx_t *x)
{
    return x && x->c && !x->c->err;
}

/* 懒重连: 上下文可用直接返回 0；否则释放旧句柄重连一次，断线自愈无需后台线程 */
static int ensure_conn(redis_ctx_t *x)
{
    if (x->c && !x->c->err) return 0;         /* 已连接且无错误位 */
    if (x->c) { redisFree(x->c); x->c = NULL; }   /* 带错误位的旧句柄先释放 */
    x->c = dial(x->host, x->port);
    if (!x->c || x->c->err) {
        if (x->c) { redisFree(x->c); x->c = NULL; }
        return -1;
    }
    fprintf(stderr, "redis reconnected %s:%d\n", x->host, x->port);
    return 0;
}

/* 注销黑名单查询: EXISTS blk:<jti>
 * hiredis 的 %s 生成 RESP 批量字符串(整参数发送)，jti 又经 jwt 层白名单
 * 净化，key 构造无注入面；返回 1=已注销 0=未注销 -1=不可用 */
int redis_blacklisted(redis_ctx_t *x, const char *jti)
{
    if (ensure_conn(x) != 0) return -1;
    redisReply *r = redisCommand(x->c, "EXISTS blk:%s", jti);
    if (!r) return -1;                        /* NULL: 超时/断连等 IO 失败 */
    int hit = (r->type == REDIS_REPLY_INTEGER && r->integer == 1);   /* 类型校验防脏回复 */
    freeReplyObject(r);                       /* hiredis reply 必须调用方释放 */
    return hit;
}

/* 原子计数脚本: INCR 与首次 EXPIRE 服务端一次执行，天然原子，
 * 避免两命令间崩溃留下不过期的计数键
 * KEYS[1] = 计数键   ARGV[1] = 窗口秒数   返回: INCR 后的序号(1 起) */
static const char *INCR_TTL_LUA =
    "local n = redis.call('INCR', KEYS[1]) "
    "if n == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end "
    "return n";

/* 原子计数器: 限流(rl:)与暴力破解失败计数(authfail:)共用 */
long long redis_incr_ttl(redis_ctx_t *x, const char *key, int ttl_s)
{
    if (ensure_conn(x) != 0) return -1;
    /* EVAL 的各参数由 hiredis 按 RESP 批量字符串整参数发送:
     * 脚本常量含空格无碍，键变量不参与命令文本拼接，无注入面 */
    redisReply *r = redisCommand(x->c, "EVAL %s 1 %s %d", INCR_TTL_LUA, key, ttl_s);
    if (!r || r->type != REDIS_REPLY_INTEGER) {   /* NULL 或异常类型都按不可用 */
        if (r) freeReplyObject(r);
        return -1;
    }
    long long n = r->integer;
    freeReplyObject(r);
    return n;
}

/* 固定窗口限流: 原子计数 + 阈值判定(契约见 redis_client.h) */
int redis_rate_limit(redis_ctx_t *x, const char *ip, int limit, int window_s)
{
    char key[32];                       /* "rl:" + IPv4 点分(≤15) 足容 */
    snprintf(key, sizeof(key), "rl:%s", ip);
    long long n = redis_incr_ttl(x, key, window_s);
    if (n < 0) return -1;
    return (n > limit) ? 1 : 0;   /* 前 limit 个放行，第 limit+1 个起超限 */
}

/* 通用 GET: 会话/API Key/结果缓存三类键共用
 * 键名由调用方构造(拼键变量都过字符白名单净化，见 auth.c/jwt.c)，
 * hiredis 的 %s 按 RESP 整参数发送，无注入面 */
int redis_get(redis_ctx_t *x, const char *key, char *out, size_t cap)
{
    if (ensure_conn(x) != 0 || cap == 0) return -1;
    redisReply *r = redisCommand(x->c, "GET %s", key);
    if (!r) return -1;                            /* NULL: 超时/断连等 IO 失败 */
    int rc;
    if (r->type == REDIS_REPLY_STRING && r->len > 0) {
        size_t n = (r->len < cap - 1) ? r->len : cap - 1;   /* 超长截断(值域受控) */
        memcpy(out, r->str, n);
        out[n] = '\0';
        rc = 1;
    } else {
        rc = 0;                                   /* NIL/空串/异常类型按"不存在" */
    }
    freeReplyObject(r);
    return rc;
}

/* 通用 SETEX: 结果缓存写入；+OK 才算成功 */
int redis_setex(redis_ctx_t *x, const char *key, int ttl_s, const char *val)
{
    if (ensure_conn(x) != 0) return -1;
    redisReply *r = redisCommand(x->c, "SETEX %s %d %s", key, ttl_s, val);
    int rc = (r && r->type == REDIS_REPLY_STATUS) ? 0 : -1;
    if (r) freeReplyObject(r);
    return rc;
}

/* 释放上下文: 先关 hiredis 连接再释放结构体本体；NULL 安全 */
void redis_close_ctx(redis_ctx_t *x)
{
    if (!x) return;
    if (x->c) redisFree(x->c);
    free(x);
}
