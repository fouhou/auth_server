#ifndef AUTH_REDIS_CLIENT_H
#define AUTH_REDIS_CLIENT_H

#include <stddef.h>

/* hiredis 同步客户端封装(单线程内使用)
 * 连接断开时在下次调用前自动重连一次；所有接口:
 *   返回 1=命中/超限  0=正常  -1=Redis 不可用(上层决定 fail-open/close) */

typedef struct redis_ctx_s redis_ctx_t;

/* 建立连接并返回上下文
 * 返回: 除内存分配失败外总是非 NULL——首连失败也返回连接为空的 ctx，
 *       让后续调用走 -1 降级路径而非空指针崩溃 */
redis_ctx_t *redis_connect_ctx(const char *host, int port);

/* 释放上下文与底层连接；NULL 安全 */
void         redis_close_ctx(redis_ctx_t *ctx);

/* 连接健康检查：1=可用 0=不可用(启动日志/降级标记用) */
int          redis_alive(const redis_ctx_t *ctx);

/* 注销黑名单: EXISTS blk:<jti>
 * 参数 jti: 验签输出的 Token 唯一 ID(已做字符白名单净化)
 * 返回 1=已注销(应 401)  0=未注销  -1=Redis 不可用 */
int          redis_blacklisted(redis_ctx_t *ctx, const char *jti);

/* 原子计数器: Lua 原子执行 INCR+首次 EXPIRE(IP 限流 / 暴力破解失败计数共用)
 * 返回 INCR 后的计数值(>=1，计数键由调用方构造并负责字符白名单)
 * 返回 -1 = Redis 不可用 */
long long     redis_incr_ttl(redis_ctx_t *ctx, const char *key, int ttl_s);

/* 固定窗口限流: Lua 原子执行 INCR+EXPIRE，超过 limit 返回 1
 * 返回 1=超限(应 429)  0=未超  -1=Redis 不可用 */
int          redis_rate_limit(redis_ctx_t *ctx, const char *ip, int limit, int window_s);

/* 通用 GET: 读字符串键(会话 sess:<sid> / API Key apikey:<key> / 结果缓存 authcache: 共用)
 * 参数 out/cap: 值缓冲与容量(超长值截断，值域受写入方控制)
 * 返回 1=键存在且非空(out 写入值)  0=键不存在  -1=Redis 不可用 */
int          redis_get(redis_ctx_t *ctx, const char *key, char *out, size_t cap);

/* 通用 SETEX: 写字符串键并设过期(鉴权结果缓存用，TTL 到点自动失效)
 * 返回 0 成功  -1 失败或不可用(缓存写失败不影响主流程，调用方可静默忽略) */
int          redis_setex(redis_ctx_t *ctx, const char *key, int ttl_s, const char *val);

#endif
