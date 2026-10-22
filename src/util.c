#include "util.h"
#include <stdint.h>
#include <string.h>

/* 单个十六进制字符 → 数值(0..15)；非法字符返回 -1
 * 三个区间分别覆盖 0-9 / a-f / A-F，供 url_decode 用 */
static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* URL 解码。逐字节三态: '%' 转义 / 普通字节(按 plus 语义翻空格)。
 * 任何失败立即返回 -1，不做容错还原；失败时 *outlen 未写入 */
int url_decode(const char *src, size_t srclen, char *dst, size_t dstcap,
               size_t *outlen, int plus_as_space)
{
    size_t i = 0, o = 0;
    while (i < srclen) {
        char c = src[i];
        if (c == '%' ) {
            if (i + 2 >= srclen) return -1;           /* 截断的转义(不足两位可用) */
            int hi = hexval(src[i + 1]), lo = hexval(src[i + 2]);
            if (hi < 0 || lo < 0) return -1;          /* 非法字符，直接拒绝 */
            if (o >= dstcap) return -1;               /* 输出容量不足 */
            dst[o++] = (char)((hi << 4) | lo);        /* 高 4 位 | 低 4 位还原字节 */
            i += 3;                                   /* 跳过 %XY 三个字节 */
        } else {
            if (o >= dstcap) return -1;
            dst[o++] = (plus_as_space && c == '+') ? ' ' : c;
            i++;
        }
    }
    if (outlen) *outlen = o;
    return 0;
}

/* HTML 实体解码: 识别常见六个实体，WAF 多层解码的第二层。
 * '&' 处按最长匹配实体表，未命中原样拷贝——半截实体("&lt" 无分号)不吞字节；
 * 就地安全: 替换后 o(写) <= i(读) 恒成立 */
int html_decode(const char *src, size_t srclen, char *dst, size_t dstcap,
                size_t *outlen)
{
    /* 实体表: 名称(不含 &;)与替换值；按长度降序排列保证最长匹配 */
    static const struct { const char *ent; size_t len; char val; } ENT[] = {
        { "quot;", 5, '"'  },
        { "#39;",  4, '\'' },
        { "apos;", 5, '\'' },
        { "nbsp;", 5, ' '  },
        { "amp;",  4, '&'  },
        { "lt;",   3, '<'  },
        { "gt;",   3, '>'  },
    };
    const size_t N_ENT = sizeof(ENT) / sizeof(ENT[0]);

    size_t o = 0;
    for (size_t i = 0; i < srclen; i++) {
        char c = src[i];
        if (c == '&') {
            size_t j;
            for (j = 0; j < N_ENT; j++) {
                if (i + 1 + ENT[j].len <= srclen &&
                    memcmp(src + i + 1, ENT[j].ent, ENT[j].len) == 0) {
                    if (o >= dstcap) return -1;   /* 容量护栏 */
                    dst[o++] = ENT[j].val;        /* 实体还原为单字符 */
                    i += ENT[j].len;              /* 连实体名一起吃掉 */
                    break;
                }
            }
            if (j < N_ENT) continue;
        }
        if (o >= dstcap) return -1;
        dst[o++] = c;                             /* 普通字节原样拷贝 */
    }
    if (outlen) *outlen = o;
    return 0;
}

/* base64url 字母表，数组下标即字符数值(0..63)；
 * 与标准 base64 的差别仅在 62/63 两位用 '-','_' 取代 '+','/'(URL 安全) */
static const char B64URL[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* base64url 编码。3 字节一组切 4 份各 6 bit 查表；
 * 尾部不足一组右侧补 0 后查表，缺的字符用 '-' 占位 */
void b64url_encode(const unsigned char *in, size_t inlen, char *out, size_t outcap)
{
    size_t o = 0, i;
    for (i = 0; i + 2 < inlen && o + 4 < outcap; i += 3) {   /* o+4 留出 4 字符+'\0' 的空间 */
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | in[i+2];
        out[o++] = B64URL[(v >> 18) & 63];   /* 每 6 bit 一查表，从高位起 */
        out[o++] = B64URL[(v >> 12) & 63];
        out[o++] = B64URL[(v >>  6) & 63];
        out[o++] = B64URL[v & 63];
    }
    if (i < inlen && o + 4 < outcap) {   /* 尾部剩 1 或 2 字节 */
        uint32_t v = (uint32_t)in[i] << 16;   /* 首字节占据窗口高位，低位补 0 */
        int rem = (int)(inlen - i);           /* 剩余字节数 */
        if (rem == 2) v |= (uint32_t)in[i+1] << 8;
        out[o++] = B64URL[(v >> 18) & 63];    /* 前 2 字符始终有效 */
        out[o++] = B64URL[(v >> 12) & 63];
        out[o++] = (rem == 2) ? B64URL[(v >> 6) & 63] : '-';   /* 第 3 字符: 余 2 才有效 */
        out[o++] = '-';                       /* 第 4 字符: 一律占位 */
    }
    out[o] = '\0';
}

/* base64url 解码。流式位拼接: 每字符并入 6 bit，凑满 8 bit
 * 从高位切出一个字节——末尾残留自然丢弃，兼容无填充输入 */
int b64url_decode(const char *in, size_t inlen, unsigned char *out, size_t outcap,
                  size_t *outlen)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t o = 0;
    for (size_t i = 0; i < inlen; i++) {
        char c = in[i];
        if (c == '=') continue;              /* 容忍填充符；'-''_' 均为合法字符 */
        const char *p = strchr(B64URL, c);   /* 查表求值，O(64) 但 token 短小无所谓 */
        if (!p || c == '\0') return -1;      /* 非法字符；'\0' 需显式排除(strchr 会命中表尾) */
        acc = (acc << 6) | (uint32_t)(p - B64URL);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= outcap) return -1;      /* 输出容量不足 */
            out[o++] = (unsigned char)((acc >> bits) & 0xff);   /* 取高位已对齐的 8 bit */
        }
    }
    if (outlen) *outlen = o;
    return 0;
}

/* 常量时间比较。无分支无提前退出，泄露不出"匹配到第几个字节" */
int consttime_eq(const unsigned char *a, const unsigned char *b, size_t n)
{
    unsigned char diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

/* 原地小写化(仅 ASCII A-Z)，其余字节保持不动 */
void ascii_lower(char *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (s[i] >= 'A' && s[i] <= 'Z')
            s[i] = (char)(s[i] - 'A' + 'a');
}
