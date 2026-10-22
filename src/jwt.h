#ifndef AUTH_JWT_H
#define AUTH_JWT_H

#include <stddef.h>

/* OpenSSL EVP 公钥前向声明(RS256 验签用)；引入头时无需暴露完整 OpenSSL 头 */
typedef struct evp_pkey_st EVP_PKEY;

/*
 * JWT 验签(HS256 + RS256)
 *
 * 安全设计:
 *  1. 算法白名单硬编码: alg 必须显式为 "HS256"/"RS256"——防 alg:none /
 *     混淆降级等经典绕过；RS256 未配置公钥时视同拒绝
 *  2. HS256 比对用常量时间比较，防时序侧信道逐字节猜签名
 *  3. exp 必须存在且大于当前时间——防永不过期 Token
 *
 * 返回 0 成功(claim 填充)；负数失败，err 输出原因:
 *  -1 格式/解码错  -2 算法混淆(攻击，调用方回 403)  -3 签名不符  -4 过期或缺 exp
 */
typedef struct {
    char sub[64];   /* 用户标识(sub claim)，验签成功后经 X-User-Id 透传给上游；
                       固定 64 字节含 '\0'，超长 claim 截断 */
    char jti[64];   /* Token 唯一 ID(JWT ID claim)，注销黑名单键 blk:<jti> 用；
                       验签后做字符白名单净化(见 jwt.c) */
    long exp;       /* 过期时间(unix 秒)；0 表示 claim 缺失(判 401) */
} jwt_claim_t;

/* 算法策略开关: 传 0 锁定 rs256-only(HS256 一律按算法混淆 -2 拒绝)，
 * 传 1 恢复默认双算法。RS256 部署不应同时暴露共享密钥验签面 */
void jwt_set_alg_policy(int hs256_allowed);

/* 验签入口: tok/len 为 token 原文(1..JWT_MAX，三段式)，secret 为 HS256
 * 共享密钥，rs_pkey 为 RS256 公钥(NULL=未配置，RS256 声明一律 -2)。
 * 成功时填充 out 三个 claim，失败时整体清零；err 可为 NULL */
int jwt_verify(const char *tok, size_t len, const char *secret,
               const EVP_PKEY *rs_pkey,
               jwt_claim_t *out, char *err, size_t errcap);

#endif
