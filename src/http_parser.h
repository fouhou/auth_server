#ifndef AUTH_HTTP_PARSER_H
#define AUTH_HTTP_PARSER_H

#include <stddef.h>

/*
 * 零拷贝 HTTP/1.x 请求解析器
 *
 * 解析过程不 memcpy 请求内容，结果里所有 const char* 都直接指向调用方
 * 接收缓冲区——从解析成功到响应处理完成，缓冲区不得移动(main.c 只在
 * 响应处理后 memmove 裁掉已消费前缀)。
 *
 * 职责边界: 只负责方法/URI/头/body 的定位与粗检，走私/规则判定由
 * security.c 完成；但走私特征必须在头部解析阶段同步采集(findings 位图)，
 * 否则证据已被消费——例如多个 Content-Length 的原始值，解析完下一行
 * 就取不到了，cl_raw[] 必须边解析边留证。
 *
 * 增量解析: 单次 read 可能只拿到半条请求，状态保存在 r->state，
 * 调用方把新数据追加到旧数据之后再次调用 http_parse 续跑。
 */

/* 容量上限(编译期常量；调整需同步评估连接内存占用与 DoS 攻击面) */
#define MAX_HDRS      64        /* 单请求收录头数量上限，超出的头仍扫描证据但不收录 */
#define MAX_LINE      8192     /* 请求行/单头行上限，超限 414/431 */
#define MAX_URI       2048     /* 请求目标(URI)长度上限，超限 414 */
#define MAX_BODY      (1 << 20) /* 1MB，超限 413 */
#define MAX_CHUNK     (1 << 20) /* 单 chunk 长度上限(413)；也是 chunked 重组缓冲的一次分配大小 */

/* http_parse() 的三种返回值——驱动 main.c 的"攒半包 → 续解析"循环 */
enum {
    PARSE_OK = 0,      /* r->consumed 字节已构成完整请求，可进入安全/鉴权处理 */
    PARSE_NEED_MORE,   /* 半包：调用方继续收数据，r 的状态保留待续跑 */
    PARSE_ERR          /* 协议错误：r->err 为应回的 HTTP 状态码(400/413/414/431/500) */
};

/* 走私/异常特征位(解析阶段采集，security 层判定):
 * 解析器发现可疑特征只记账不报警，证据齐了由 smuggling_check 统一 403，
 * 解析与安全判定解耦。每一位对应一类 CL.TE / TE.CL 走私的构造原料 */
enum {
    F_CLTE_DUP    = 1u << 0,  /* Content-Length 与 Transfer-Encoding 同现 */
    F_CL_MULTI    = 1u << 1,  /* 出现多个 Content-Length 头 */
    F_CL_INVALID  = 1u << 2,  /* CL 值非纯数字/为负/溢出 */
    F_TE_OBSCURE  = 1u << 3,  /* TE 值混淆: 重复出现/非 chunked/逗号组合 */
    F_HDR_TOK     = 1u << 4   /* 头名含空格等非法 token 字符(经典走私变体) */
};

/* 请求方法枚举: method_of() 按字面量匹配；未识别方法归入 M_OTHER，
 * 解析器不擅自拒绝，放给上层统一裁决 */
typedef enum { M_GET, M_POST, M_PUT, M_DELETE, M_HEAD, M_OPTIONS, M_PATCH, M_OTHER } http_method_t;

/* 单个头部的名字/值视图。零拷贝：两个指针都指向请求缓冲区，不持有内存 */
typedef struct {
    const char *name;  size_t name_len;  /* 头名(冒号前)；token 合法性已检查，非法只记 F_HDR_TOK 不中断 */
    const char *value; size_t value_len; /* 头值(冒号后)，已去掉前导 SP/HTAB，尾部原样保留 */
} http_header_t;

/* 一次 HTTP 请求的完整解析结果(结构体约 2KB；main.c 以 static 复用避免反复占用栈)
 * 所有 const char* 均为零拷贝指针，指向调用方接收缓冲区内部 */
typedef struct {
    /* 请求行 */
    http_method_t method;                      /* 方法枚举值，未识别为 M_OTHER */
    const char *method_s; size_t method_len;   /* 方法原文指针与长度(1..15 字节，超长 400) */
    const char *uri;      size_t uri_len;      /* 请求目标原文(<= MAX_URI，不含空格) */
    int http_minor;               /* 0/1：HTTP/1.0 或 HTTP/1.1(已校验，其余判 400) */
    /* 头部 */
    http_header_t hdrs[MAX_HDRS];   /* 收录的头部数组(按出现顺序) */
    int nhdrs;                      /* 已收录头数 0..MAX_HDRS-1 */
    /* 关键头快捷指针(可能为 NULL) —— 热点头直接定位，免去遍历 hdrs[]；
     * 对应头未出现时指针为 NULL 且长度为 0 */
    const char *content_length; size_t content_length_len;   /* 最后一个 CL 的值(证据在 cl_raw) */
    const char *transfer_encoding; size_t transfer_encoding_len; /* 最后一个 TE 的值 */
    const char *connection; size_t connection_len;   /* keep-alive 判定用 */
    const char *user_agent; size_t user_agent_len;   /* WAF 扫描目标 */
    const char *referer; size_t referer_len;         /* WAF 扫描目标 */
    const char *cookie; size_t cookie_len;           /* WAF 扫描目标 */
    const char *authorization; size_t authorization_len;  /* Bearer Token 提取源 */
    const char *x_orig_uri; size_t x_orig_uri_len;   /* Nginx auth_request 注入 */
    const char *x_orig_method; size_t x_orig_method_len; /* Nginx auth_request 注入 */
    const char *api_key; size_t api_key_len;         /* X-Api-Key 头(服务间 API Key 鉴权) */
    const char *x_real_ip; size_t x_real_ip_len;     /* Nginx 注入: 客户端真实 IP(限流/锁定键, 信任边界见 auth.c) */
    const char *x_orig_cl; size_t x_orig_cl_len;     /* Nginx 注入: 客户端原始 CL 值(网关形态走私证据, 子请求自身 CL 被清空) */
    const char *x_orig_te; size_t x_orig_te_len;     /* Nginx 注入: 客户端原始 TE 值(同上) */
    /* CL 出现计数与原始值(走私检测证据) */
    const char *cl_raw[4]; size_t cl_raw_len[4]; int cl_count;  /* 最多留证 4 个 CL，多出仍计数 */
    int te_count;                   /* TE 头出现次数(>1 即 F_TE_OBSCURE) */
    /* 安全采集 */
    unsigned findings;              /* F_* 位图：解析期间发现的可疑特征集合 */
    /* 请求体 */
    const char *body; size_t body_len;      /* CL 场景零拷贝 */
    char *chunk_body;                       /* chunked 场景重组缓冲(调用方释放) */
    size_t chunk_body_len;
    /* 状态 */
    int state;                              /* 解析状态机当前位置(NEED_MORE 续跑) */
    int err;                                /* PARSE_ERR 时的 HTTP 状态码 */
    size_t consumed;                        /* 本次请求消耗的输入字节数 */
} http_request_t;

/* 复位解析上下文: 整体清零并把状态机拨回请求行状态。
 * 每个新请求(含流水线里的下一请求)解析前必须调用 */
void http_request_init(http_request_t *r);

/* 释放 chunked 重组缓冲(置 NULL/0)。复用上下文前/请求处理完后都必须调用，
 * 否则每次 chunked 请求泄漏一个 1MB 缓冲 */
void http_request_free(http_request_t *r);

/* 增量解析入口: 把 buf[0..len) 灌进状态机，buf 必须从当前请求的首字节
 * 开始(main.c 处理完一条请求后 memmove 掉 consumed 字节保证)。
 * 返回值语义见上方枚举；非线程安全，单事件循环内使用 */
int  http_parse(http_request_t *r, const char *buf, size_t len);

#endif
