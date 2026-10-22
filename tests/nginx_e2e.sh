#!/usr/bin/env bash
# 端到端验证: 客户端 -> Nginx:8080 -> auth_request -> auth_server:8081
# 用法: ./tests/nginx_e2e.sh [nginx端口,默认8080]
cd "$(dirname "$0")/.." || exit 1
PORT=${1:-8080}
BASE="http://127.0.0.1:$PORT"
PASS=0; FAIL=0
TOK=$(bash tests/jwt_helper.sh alice e2e-001)

check() {
    if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "  PASS  $1 ($3)"
    else FAIL=$((FAIL+1)); echo "  FAIL  $1 期望$2 实际$3"; fi
}
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$@"; }

echo "== Nginx auth_request 端到端 =="
check "无 Token -> 401"                    401 "$(code $BASE/)"
check "合法 Token -> 200"                  200 "$(code -H "Authorization: Bearer $TOK" $BASE/)"
check "SQL 注入 -> 403"                    403 "$(code "$BASE/?id=1%20union%20select")"
# alg:none: 空签名属格式错误(401)，带垃圾签名才能命中算法白名单检查(-2->403)
H=$(printf '%s' '{"alg":"none","typ":"JWT"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
P=$(printf '%s' '{"sub":"a","jti":"n1","exp":9999999999}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
check "alg:none -> 403"                    403 "$(code -H "Authorization: Bearer $H.$P.AAAA" $BASE/)"
check "过期 Token -> 401"                  401 "$(code -H "Authorization: Bearer $(bash tests/jwt_helper.sh alice e2e-003 -10)" $BASE/)"
check "篡改签名 -> 401"                    401 "$(code -H "Authorization: Bearer ${TOK%.*}.AAAA" $BASE/)"

echo "== 走私经 Nginx 透传 =="
# Nginx 对 CL+TE 歧义请求边缘直接 400；auth_server 检测为第二道防线(直连场景 403)
r=$(printf 'POST /x HTTP/1.1\r\nHost: n\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n' | timeout 3 nc 127.0.0.1 $PORT | head -1)
if echo "$r" | grep -qE ' 400 | 403 '; then PASS=$((PASS+1)); echo "  PASS  走私 CL+TE -> 拒绝($r)"
else FAIL=$((FAIL+1)); echo "  FAIL  走私 CL+TE: $r"; fi

echo
echo "结果: $PASS 通过, $FAIL 失败"
[ "$FAIL" = 0 ]
