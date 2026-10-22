#ifndef AUTH_SECURITY_H
#define AUTH_SECURITY_H

#include <stddef.h>
#include "http_parser.h"

/* ── 安全判定层：消费解析器采集的原始证据，输出"拦/放"结论 ──
 * 两级检查，调用方(main.c process())按序短路执行：
 *   1. 走私判定——协议层歧义(CL/TE 组合)，命中即 403
 *   2. WAF 特征——内容层攻击指纹(SQLi/XSS/穿越/RCE)，命中即 403
 * 任一命中都直接终止，不进入后续 JWT/Redis 鉴权链路 */

/* 走私判定：基于解析阶段采集的 findings 位图
 * 参数 r          : 解析完成(或至少已扫过头部)的请求上下文
 * 参数 reason/cap : 出参，人类可读的拦截原因，调用方保证缓冲容量
 * 返回 1 表示判定为走私请求(应 403)，0 表示未发现走私特征；
 * 检查顺序即优先级：多特征同现时只报最先命中的那类 */
int smuggling_check(const http_request_t *r, char *reason, size_t cap);

/* WAF 初始化: 从规则文件加载规则并构建 AC 自动机(解析 → Trie → BFS 失败
 * 指针 → 全 goto 确定化)。必须在第一次 waf_check 之前调用一次(main 启动时)。
 * fail-fast: 文件缺失/格式错误/零规则返回 -1, 调用方应拒绝启动——
 * 安全规则表宁可不服务, 不可静默丢规则带病运行 */
int waf_init(const char *rules_file);

/* WAF 特征规则检测(URI/UA/Referer/Cookie/Body)
 * 各目标先做"多轮解码 + 归一化"，再由 AC 自动机一次扫描匹配全部规则；
 * 匹配语义 = 命中规则中表序最靠前者
 * 返回 1 表示命中(应 403)，rule_id 输出规则编号如 "R1008"；0 表示放行 */
int waf_check(const http_request_t *r, char *rule_id, size_t cap);

#endif
