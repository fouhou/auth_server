#!/usr/bin/env bash
# 解析器/边界扩充回归套件: 覆盖 consumed 结算修复、半关闭、增量分片、
# CL/TE 词法与走私证据、chunked 细节、长度上限、WAF 解码绕过、keep-alive 行为
# 用法: ./tests/parser_regression.sh [port]   (默认 8081，服务需已启动)
# 注意: 建议以 RL_LIMIT=100000 启动服务，避免套件请求触发限流误报；
#       各节之间会清理 rl:127.0.0.1 兜底。期望值以 jwt+redis 完整模式为准。
set -u
PORT=${1:-8081}
PASS=0; FAIL=0; SKIP=0

# nc 能力探测: openbsd 变体支持 -N(发完即半关闭)，测试快速返回且顺带验证 RDHUP 修复
NC_OPENBSD=0
if nc -h 2>&1 | grep -qi OpenBSD; then NC_OPENBSD=1; fi
NCOPT=""; [ $NC_OPENBSD = 1 ] && NCOPT="-N"
TMO=3; [ $NC_OPENBSD = 0 ] && TMO=4   # 无 -N 时连接要等超时才收尾，放宽一点

redis-cli DEL "rl:127.0.0.1" >/dev/null 2>&1

# 发送原始字节流，返回收到的全部响应文本
send() { printf '%s' "$1" | timeout $TMO nc $NCOPT 127.0.0.1 $PORT 2>/dev/null; true; }

# 从响应流提取按序状态码列表
codes() { printf '%s' "$1" | grep -a -o 'HTTP/1\.1 [0-9][0-9][0-9]' | awk '{print $2}'; }

# 单码断言: expect_one <名称> <期望码> <请求>
expect_one() {
    local name=$1 want=$2 req=$3 got
    got=$(codes "$(send "$req")" | head -1)
    if [ "$got" = "$want" ]; then PASS=$((PASS+1)); echo "  PASS  $name ($got)"
    else FAIL=$((FAIL+1)); echo "  FAIL  $name 期望$want 实际${got:-无响应}"; fi
}

# 多码断言(流水线): expect_seq <名称> <期望码串 如 "401 401"> <请求>
expect_seq() {
    local name=$1 want=$2 req=$3 got
    got=$(codes "$(send "$req")" | tr '\n' ' ' | sed 's/ $//')
    if [ "$got" = "$want" ]; then PASS=$((PASS+1)); echo "  PASS  $name ($got)"
    else FAIL=$((FAIL+1)); echo "  FAIL  $name 期望[$want] 实际[${got:-无响应}]"; fi
}

# 响应头包含断言: expect_hdr <名称> <子串> <请求>
expect_hdr() {
    local name=$1 substr=$2 req=$3 resp
    resp=$(send "$req")
    local got; got=$(codes "$resp" | head -1)
    if printf '%s' "$resp" | grep -aq "$substr"; then PASS=$((PASS+1)); echo "  PASS  $name ($got 含 $substr)"
    else FAIL=$((FAIL+1)); echo "  FAIL  $name 未在响应中找到 [$substr]"; fi
}

GET1=$'GET /api/user HTTP/1.1\r\nHost: a\r\n\r\n'

echo "== A. consumed 结算修复回归(流水线粘包) =="
# 旧 bug: CL body 不计入 consumed，body 字节残留缓冲污染下一条请求(第二条应为 400)
expect_seq "CL body + 流水线 GET" "401 401" \
    $'POST /api/user HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nA AGET /api/user HTTP/1.1\r\nHost: a\r\n\r\n'
# 旧 bug: chunked 终止空行不消费，"\r\n" 残留(第二条应为 400)
expect_seq "chunked + 流水线 GET" "401 401" \
    $'POST /api/user HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\nGET /api/user HTTP/1.1\r\nHost: a\r\n\r\n'
# 带非空 trailer: 非 trailer 行消费路径 + 终止空行都要算对
expect_seq "chunked 带普通 trailer + 流水线 GET" "401 401" \
    $'POST /api/user HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Trail: v\r\n\r\nGET /api/user HTTP/1.1\r\nHost: a\r\n\r\n'
# trailer 藏 CL 是走私变体: 第一条 403，第二条不受残留影响
expect_seq "trailer 藏 CL(403) + 流水线 GET" "403 401" \
    $'POST /api/user HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nContent-Length: 5\r\n\r\nGET /api/user HTTP/1.1\r\nHost: a\r\n\r\n'
# body 内含 \r\n 字节: 按长度消费不按行扫描
expect_seq "CL body 内含 CRLF + 流水线 GET" "401 401" \
    $'POST /api/user HTTP/1.1\r\nHost: a\r\nContent-Length: 4\r\n\r\na\r\nbGET /api/user HTTP/1.1\r\nHost: a\r\n\r\n'

echo "== B. 半关闭(RDHUP 修复回归) =="
if [ $NC_OPENBSD = 1 ]; then
    expect_one "发完即 FIN 仍能收到响应" "401" "$GET1"
else
    echo "  SKIP  发完即 FIN 仍能收到响应 (需 openbsd nc)"
    SKIP=$((SKIP+1))
fi

echo "== C. 增量解析(分片到达) =="
if [ $NC_OPENBSD = 1 ]; then
    got=$({ printf 'GET /api/user HTT'; sleep 0.3; printf 'P/1.1\r\nHost: a\r\n\r\n'; } | timeout $TMO nc -N 127.0.0.1 $PORT 2>/dev/null | grep -a -o 'HTTP/1\.1 [0-9][0-9][0-9]' | awk '{print $2}' | head -1)
    if [ "$got" = "401" ]; then PASS=$((PASS+1)); echo "  PASS  请求行中途分片 ($got)"
    else FAIL=$((FAIL+1)); echo "  FAIL  请求行中途分片 期望401 实际${got:-无响应}"; fi
    got=$({ printf 'POST /api/user HTTP/1.1\r\nHost: a\r\nContent-Length: 9\r\n\r\nabc'; sleep 0.2; printf 'def'; sleep 0.2; printf 'ghi'; } | timeout $TMO nc -N 127.0.0.1 $PORT 2>/dev/null | grep -a -o 'HTTP/1\.1 [0-9][0-9][0-9]' | awk '{print $2}' | head -1)
    if [ "$got" = "401" ]; then PASS=$((PASS+1)); echo "  PASS  body 三段分片 ($got)"
    else FAIL=$((FAIL+1)); echo "  FAIL  body 三段分片 期望401 实际${got:-无响应}"; fi
else
    echo "  SKIP  分片测试 (需 openbsd nc)"
    SKIP=$((SKIP+2))
fi

echo "== D. Content-Length 词法与走私证据 =="
expect_one "CL 负数 -> 403"        "403" $'POST /api/user HTTP/1.1\r\nHost: a\r\nContent-Length: -5\r\n\r\n'
expect_one "CL 非数字 -> 403"      "403" $'POST /api/user HTTP/1.1\r\nHost: a\r\nContent-Length: abc\r\n\r\n'
expect_one "CL 尾随空格 -> 403"    "403" $'POST /api/user HTTP/1.1\r\nHost: a\r\nContent-Length: 5 \r\n\r\n'
expect_one "CL 十六进制形态 -> 403" "403" $'POST /api/user HTTP/1.1\r\nHost: a\r\nContent-Length: 0x10\r\n\r\n'
expect_one "双 CL 冲突 -> 403"     "403" $'POST /api/user HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nAAAAA'
expect_one "CL 超 1MB -> 403(非法值)" "403" $'POST /api/user HTTP/1.1\r\nHost: a\r\nContent-Length: 1048577\r\n\r\n'
expect_one "CL 0(无 body) -> 401"  "401" $'POST /api/user HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n'
expect_one "TE identity -> 403"    "403" $'POST /api/user HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: identity\r\n\r\n'
expect_one "TE 逗号组合 -> 403"    "403" $'POST /api/user HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked, gzip\r\n\r\n'
expect_one "TE 重复出现 -> 403"    "403" $'POST /api/user HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n'
expect_one "CL+TE 同现 -> 403"     "403" $'POST /api/user HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n'
expect_one "头名含空格 -> 403"     "403" $'GET /api/user HTTP/1.1\r\nX Foo: bar\r\nHost: a\r\n\r\n'
expect_one "头行无冒号 -> 400"     "400" $'GET /api/user HTTP/1.1\r\nBadHeader\r\nHost: a\r\n\r\n'

echo "== E. chunked 细节 =="
expect_one "chunk 扩展(;ext)合法 -> 401" "401" \
    $'POST /api/user HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5;x=y\r\nhello\r\n0\r\n\r\n'
expect_one "块尾非严格 CRLF -> 400" "400" \
    $'POST /api/user HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXY0\r\n\r\n'
expect_one "块长非十六进制 -> 400"  "400" \
    $'POST /api/user HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\nG\r\n0\r\n\r\n'
expect_one "空块长行(数据行后) -> 400" "400" \
    $'POST /api/user HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n\r\n0\r\n\r\n'
expect_one "单块超 1MB -> 413"     "413" \
    $'POST /api/user HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n1000001\r\n'

echo "== F. 请求行/头部边界 =="
A3000=$(printf 'A%.0s' $(seq 1 3000)); A8500=$(printf 'A%.0s' $(seq 1 8500))
H9K=$(printf 'Z%.0s' $(seq 1 9000))
R_URI3000=$(printf 'GET /%s HTTP/1.1\r\nHost: a\r\n\r\n' "$A3000")
R_LINE8500=$(printf 'GET /%s HTTP/1.1\r\nHost: a\r\n\r\n' "$A8500")
R_HDR9K=$(printf 'GET /api/user HTTP/1.1\r\nHost: a\r\nX-Big: %s\r\n\r\n' "$H9K")
expect_one "URI 超 2048 -> 414"    "414" "$R_URI3000"
expect_one "单头行超 8192 -> 431"  "431" "$R_HDR9K"
expect_one "请求行超 8192 -> 414"  "414" "$R_LINE8500"
expect_one "版本 HTTP/1.2 -> 400"  "400" $'GET /api/user HTTP/1.2\r\nHost: a\r\n\r\n'
expect_one "未知方法 BREW -> 401"  "401" $'BREW /api/user HTTP/1.1\r\nHost: a\r\n\r\n'
expect_one "空方法 -> 400"         "400" $' /api/user HTTP/1.1\r\nHost: a\r\n\r\n'
expect_hdr "HTTP/1.0 缺省关闭" "Connection: close" $'GET /api/user HTTP/1.0\r\n\r\n'
expect_hdr "显式 Connection: close" "Connection: close" $'GET /api/user HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n'
# 头名匹配大小写无关(strncasecmp): 小写 CL 亦被识别计数。
# 判定性证据: 若不识别则 body "A A" 残留污染流水线，第二条会 400
expect_seq "小写 content-length 亦识别(头名大小写无关) -> 401 401" "401 401" \
    $'POST /api/user HTTP/1.1\r\nHost: a\r\ncontent-length: 3\r\n\r\nA AGET /api/user HTTP/1.1\r\nHost: a\r\n\r\n'
expect_one "空头值合法 -> 401"     "401" $'GET /api/user HTTP/1.1\r\nHost: a\r\nX-Empty:\r\n\r\n'
# 70 个头: 超出 MAX_HDRS 的只不收录不中断
req70=$'GET /api/user HTTP/1.1\r\nHost: a\r\n'
for i in $(seq 1 70); do req70+="X-H$i: v$i"$'\r\n'; done
req70+=$'\r\n'
expect_one "70 个头(超收录上限) -> 401" "401" "$req70"

echo "== G. WAF 解码与绕过面 =="
expect_one "双重编码 %2520 -> 403"  "403" $'GET /api/user?id=1%2520union%2520select HTTP/1.1\r\nHost: a\r\n\r\n'
expect_one "Tab 变体 union%09select -> 403" "403" $'GET /api/user?q=union%09select HTTP/1.1\r\nHost: a\r\n\r\n'
expect_one "URI 含 %0d%0a -> 403"  "403" $'GET /api/user?x=%0d%0a HTTP/1.1\r\nHost: a\r\n\r\n'
expect_one "Cookie 注入 or 1=1 -> 403" "403" $'GET /api/user HTTP/1.1\r\nHost: a\r\nCookie: a=or 1=1\r\n\r\n'
expect_one "UA 注入 <script> -> 403" "403" $'GET /api/user HTTP/1.1\r\nHost: a\r\nUser-Agent: <script>\r\n\r\n'
expect_one "body 注入 <script> -> 403" "403" $'POST /api/user HTTP/1.1\r\nHost: a\r\nContent-Length: 8\r\n\r\n<script>'
B4K=$(printf 'B%.0s' $(seq 1 4000)); B9K=$(printf 'B%.0s' $(seq 1 9000))
R_BODY4K=$(printf 'POST /api/user HTTP/1.1\r\nHost: a\r\nContent-Length: 4012\r\n\r\n%sunion select' "$B4K")
R_BODY9K=$(printf 'POST /api/user HTTP/1.1\r\nHost: a\r\nContent-Length: 9012\r\n\r\n%sunion select' "$B9K")
R_SPAN=$(printf 'POST /api/user HTTP/1.1\r\nHost: a\r\nContent-Length: 8200\r\n\r\n%sunion select' "$(printf 'B%.0s' $(seq 1 8188))")
expect_one "body 4KB 处注入 -> 403" "403" "$R_BODY4K"
expect_one "body 9KB 处注入(滚动窗口覆盖,旧版 8KB 盲区) -> 403" "403" "$R_BODY9K"
expect_one "指纹跨 8KB 窗口边界(重叠 64B 兜住) -> 403" "403" "$R_SPAN"
# 旧版致盲缺陷对抗样本: %252G 一轮解码后成非法转义 %2G，旧版归一化二轮
# 失败置空串导致漏检；fail-safe 修复后保留上轮原文 %2Gunion select 继续匹配
# (用 printf -v 写变量,避免 $() 命令替换剥掉尾部 CRLF 使请求不完整)
check_uri403() { printf -v uri_req 'GET /api/user?%s HTTP/1.1\r\nHost: a\r\n\r\n' "$2"; expect_one "$1" "403" "$uri_req"; }
check_uri403 "非法转义+注入指纹(%252G) -> 403" "q=%252Gunion%20select"
check_uri403 "NUL 致盲对抗: %00 解码产物不截断匹配(%00union%20select) -> 403" "q=%00union%20select"
expect_one "干净 body -> 401"      "401" $'POST /api/user HTTP/1.1\r\nHost: a\r\nContent-Length: 7\r\n\r\nname=tm'
# AC 自动机语义钉子(2026-10-22 升级): 匹配内核由逐条 strstr 换为 AC 一次扫描,
# 优先级语义必须与旧实现逐字节等价——多规则同命中取表序最靠前者
expect_hdr "AC 语义: 多规则同命中取表序最前(R1001 非 R1005) -> 403" "X-WAF-Rule: R1001" \
    $'GET /api/user?q=%27%20or%20%27%20union%20select HTTP/1.1\r\nHost: a\r\n\r\n'
expect_hdr "AC 语义: union all select 精确命中 R1002(前缀共享不误报 R1001) -> 403" "X-WAF-Rule: R1002" \
    $'GET /api/user?q=union%20all%20select HTTP/1.1\r\nHost: a\r\n\r\n'
# 网关形态别名头证据: 子请求无 body/CL 被清空, 客户端原始定界头经 X-Original-*
# 透传, smuggling_check 二次词法判罚(直连伪造别名头只会让自己被拒, 无害)
expect_hdr "别名头: CL+TE 同现 -> 403" "X-Security-Block: request-smuggling" \
    $'GET /api/user HTTP/1.1\r\nHost: a\r\nX-Original-CL: 5\r\nX-Original-TE: chunked\r\n\r\n'
expect_hdr "别名头: 多 CL(Nginx 逗号拼接) -> 403" "X-Security-Block: request-smuggling" \
    $'GET /api/user HTTP/1.1\r\nHost: a\r\nX-Original-CL: 5, 6\r\n\r\n'
expect_hdr "别名头: CL 非法值 -> 403" "X-Security-Block: request-smuggling" \
    $'GET /api/user HTTP/1.1\r\nHost: a\r\nX-Original-CL: abc\r\n\r\n'
expect_hdr "别名头: TE 混淆(identity) -> 403" "X-Security-Block: request-smuggling" \
    $'GET /api/user HTTP/1.1\r\nHost: a\r\nX-Original-TE: identity\r\n\r\n'
expect_one "别名头: 合法单 CL 不误伤 -> 401" "401" \
    $'GET /api/user HTTP/1.1\r\nHost: a\r\nX-Original-CL: 5\r\n\r\n'

echo "== H. keep-alive 与连接复用 =="
expect_seq "三条 GET 流水线" "401 401 401" "$GET1$GET1$GET1"
# 声明关闭的连接不得再服务流水线下一条(closing 守卫回归: 修复前会答出 401 401)
expect_seq "Connection: close 后不再处理流水线下一条" "401" \
    $'GET /api/user HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\nGET /api/user HTTP/1.1\r\nHost: a\r\n\r\n'
if [ $NC_OPENBSD = 1 ]; then
    got=$({ printf '%s' "$GET1"; sleep 0.4; printf '%s' "$GET1"; } | timeout $TMO nc -N 127.0.0.1 $PORT 2>/dev/null | grep -a -o 'HTTP/1\.1 [0-9][0-9][0-9]' | awk '{print $2}' | tr '\n' ' ' | sed 's/ $//')
    if [ "$got" = "401 401" ]; then PASS=$((PASS+1)); echo "  PASS  同连接先后两条(间隔 0.4s) ($got)"
    else FAIL=$((FAIL+1)); echo "  FAIL  同连接先后两条 期望[401 401] 实际[${got:-无响应}]"; fi
else
    echo "  SKIP  同连接先后两条 (需 openbsd nc)"
    SKIP=$((SKIP+1))
fi

redis-cli DEL "rl:127.0.0.1" >/dev/null 2>&1
echo
echo "结果: $PASS 通过, $FAIL 失败, $SKIP 跳过"
[ "$FAIL" = 0 ]
