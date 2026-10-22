#ifndef AUTH_AUTH_H
#define AUTH_AUTH_H

#include <stddef.h>
#include "http_parser.h"
#include "redis_client.h"

/* OpenSSL 公钥前向声明(RS256 用)，避免在本头文件引入 OpenSSL 完整头 */
typedef struct evp_pkey_st EVP_PKEY;

/*
 * 鉴权编排层: 三种鉴权方式的统一入口
 *
 *   凭证形态           识别来源                      校验路径
 *   -----------------  ----------------------------  -------------------------
 *   API Key(服务间)    X-Api-Key: <key> 头           Redis GET apikey:<key>
 *   Session(传统 Web)  Cookie: sid=<会话ID>          Redis GET sess:<sid>
 *   JWT(无状态 API)    Authorization: Bearer <jwt>   本地验签(HS256/RS256)
 *                                                    + Redis 注销黑名单
 *
 * 识别优先级: X-Api-Key > Cookie sid > Bearer Token，互斥先到先得。
 * 附加防线: 暴力破解锁定(按标识计数，窗口内达阈值一律 403)、JWT 结果
 * 缓存(凭证指纹 30s，注销生效延迟 ≤30s)、IP 固定窗口限流。
 * Redis 不可用时全链 fail-open + X-Auth-Degraded 标记
 */

/* 鉴权依赖集合: main.c 启动时收集一次，auth_init 保存(单线程事件循环内复用) */
typedef struct {
    const char *secret;    /* HS256 共享密钥(env AUTH_SECRET，非空) */
    EVP_PKEY *rs256_pkey;  /* RS256 公钥(env AUTH_PUBKEY 指向 PEM；NULL=未启用) */
    redis_ctx_t *rds;      /* Redis 上下文(demo 模式为 NULL——demo 在上层已短路) */
    int rl_limit;          /* IP 限流: 单窗口配额 */
    int rl_window;         /* IP 限流: 窗口秒数 */
    int fail_limit;        /* 暴力破解锁定: 窗口内失败阈值(env AUTHFAIL_LIMIT) */
    int fail_window;       /* 暴力破解锁定: 计数窗口秒数(固定 300) */
    int trust_proxy;       /* 信任边界开关(env TRUST_PROXY=1): 网关模式时限流/锁定键
                              改用 Nginx 注入的 X-Real-IP；直连模式必须为 0(可伪造) */
} auth_deps_t;

/* 保存依赖集合(仅结构体拷贝；调用时机: main 启动、Redis 连接建立之后) */
void auth_init(const auth_deps_t *deps);

/* 鉴权主入口: 走私/WAF 检测通过后调用
 * 出参 user=用户身份(透传 X-User-Id)  note=日志原因  extra=附加响应头
 * 返回 200 放行 / 401 凭证无效 / 403 攻击或锁定 / 429 限流 */
int auth_check(const http_request_t *req, const char *ip,
               char *user, size_t ucap,
               char *note, size_t ncap,
               char *extra, size_t ecap);

#endif