#!/usr/bin/env bash
# auth_server 鉴权链路测试: 签发 HS256 JWT + 全场景回归
# 用法: ./tests/auth_test.sh [port]   (默认 8081，服务需已启动)
set -u
PORT=${1:-8081}
BASE="http://127.0.0.1:$PORT"
SECRET=${AUTH_SECRET:-dev-secret-change-me}
PASS=0; FAIL=0

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# issue <sub> <jti> <exp_unix> [alg_header]
issue() {
    local sub=$1 jti=$2 exp=$3
    local header=${4:-'{"alg":"HS256","typ":"JWT"}'}
    local payload="{\"sub\":\"$sub\",\"jti\":\"$jti\",\"exp\":$exp}"
    local h p s
    h=$(printf '%s' "$header" | b64url)
    p=$(printf '%s' "$payload" | b64url)
    s=$(printf '%s' "$h.$p" | openssl dgst -sha256 -hmac "$SECRET" -binary | b64url)
    echo "$h.$p.$s"
}

# check <名称> <期望码> <实际码>
check() {
    if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "  PASS  $1 ($3)"
    else FAIL=$((FAIL+1)); echo "  FAIL  $1 期望$2 实际$3"; fi
}

NOW=$(date +%s)
TOK_OK=$(issue alice tok-ok-001 $((NOW + 600)))
TOK_EXPIRED=$(issue alice tok-old-001 $((NOW - 10)))
TOK_NONE=$(issue alice tok-non-001 $((NOW + 600)) '{"alg":"none","typ":"JWT"}')
TOK_OVEREXP=$(issue alice tok-of-001 99999999999999999999)   # exp 超出 long(溢出伪造"永不过期")
TOK_BADEXP=$(issue alice tok-gb-001 '123abc')                # exp 数字后拖垃圾文本
TOK_FORGED() { echo "${TOK_OK%.*}.AAAA forged-signature"; }

echo "== 鉴权链路 =="
c=$(curl -s -o /dev/null -w '%{http_code}' $BASE/api/user);                     check "无 Token -> 401"        401 "$c"
c=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK_OK" $BASE/api/user); check "合法 Token -> 200"      200 "$c"
c=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $(TOK_FORGED)" $BASE/api/user); check "篡改签名 -> 401"  401 "$c"
c=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK_NONE" $BASE/api/user); check "alg:none 攻击 -> 403" 403 "$c"
c=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK_EXPIRED" $BASE/api/user); check "过期 Token -> 401" 401 "$c"
c=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK_OVEREXP" $BASE/api/user); check "exp 溢出伪造永不过期 -> 401" 401 "$c"
c=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK_BADEXP" $BASE/api/user); check "exp 残缺数字文本 -> 401" 401 "$c"

echo "== 注销黑名单 =="
redis-cli DEL "blk:tok-rev-001" >/dev/null
redis-cli SET "blk:tok-rev-001" 1 EX 60 >/dev/null
TOK_REV=$(issue alice tok-rev-001 $((NOW + 600)))
c=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK_REV" $BASE/api/user); check "已注销 jti -> 401"     401 "$c"

echo "== 限流 =="
LAST=200
for i in $(seq 1 110); do
    LAST=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK_OK" $BASE/api/ping)
done
check "连续 110 次后触发 429" 429 "$LAST"
redis-cli DEL "rl:127.0.0.1" >/dev/null
c=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK_OK" $BASE/api/ping); check "清限流键后恢复 200"     200 "$c"

echo "== 安全回归(应不受鉴权影响) =="
c=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/?id=1%20union%20select");      check "SQL 注入 -> 403"        403 "$c"
r=$(printf 'POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n' | timeout 3 nc 127.0.0.1 $PORT | head -1)
if echo "$r" | grep -q 403; then check "走私 CL+TE -> 403" x x; else check "走私 CL+TE -> 403" 403 "$r"; fi

echo
echo "结果: $PASS 通过, $FAIL 失败"
[ "$FAIL" = 0 ]
