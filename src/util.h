#ifndef AUTH_UTIL_H
#define AUTH_UTIL_H

#include <stddef.h>

/* 通用工具层: URL 解码 / base64url 编解码 / 常量时间比较 / 小写化
 * 被 WAF 归一化(security.c)与 JWT 验签(jwt.c)共用，无全局状态 */

/* URL 解码(%XX；plus_as_space=1 时 '+' 转空格，用于 query 归一化)。
 * 解码结果 <= 输入长度；非法转义("%G1"、截断的 "%2")或容量不足返回 -1，
 * 非法即拒绝不做容错——解码歧义正是绕过 WAF 的经典手法 */
int url_decode(const char *src, size_t srclen, char *dst, size_t dstcap,
               size_t *outlen, int plus_as_space);

/* HTML 实体解码(WAF 多层解码的第二层): 识别 &lt; &gt; &amp; &quot; &#39; &apos;。
 * 实体必然缩短，结果 <= 输入；返回 -1 仅容量不足(实际不可触发)。
 * 就地解码安全: 每步写游标 o <= 读游标 i */
int html_decode(const char *src, size_t srclen, char *dst, size_t dstcap,
                size_t *outlen);

/* base64url(RFC 4648 §5): encode 无填充，尾部不足一组用 '-' 占位；
 * decode 容忍标准填充，'-'/'_' 为表内合法字符，末尾残留位丢弃
 * (即"无填充输入"的正确语义)。encode 输出 NUL 结尾串 */
void b64url_encode(const unsigned char *in, size_t inlen, char *out, size_t outcap);
int  b64url_decode(const char *in, size_t inlen, unsigned char *out, size_t outcap,
                   size_t *outlen);

/* 常量时间比较：防时序侧信道逐字节猜凭证（JWT 签名比对用）
 * 逐字节异或累积进 diff，总耗时只与 n 有关、与"第几个字节开始不同"无关
 * 返回 1 相等 / 0 不等；n=0 视为相等 */
int consttime_eq(const unsigned char *a, const unsigned char *b, size_t n);

/* 原地把 s[0..n) 中的 A-Z 改为 a-z，其余字节不动
 * 用途: Connection 头 keep-alive 判定、WAF 原始串小写化(防大小写绕过) */
void ascii_lower(char *s, size_t n);

#endif
