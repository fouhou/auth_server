#!/usr/bin/env bash
# 三种鉴权方式 + 附加防线回归: Session / API Key / RS256 / 结果缓存 / 失败锁定 / HTML 解码
# 用法: ./tests/auth_methods_test.sh [port]   (默认 8081，服务需已启动)
# 服务启动要求(本套件专用):
#   AUTH_PUBKEY=tests/keys/rs256.pub   ← RS256 用例依赖
#   AUTHFAIL_LIMIT=5 RL_LIMIT=1000000  ← 锁定用例快速触发 + 避免限流误报
# 凭证预置: 套件自己经 redis-cli 写入 sess:/apikey: 测试键(带 TTL 自清理)
set -u
PORT=${1:-8081}
BASE="http://127.0.0.1:$PORT"
PASS=0; FAIL=0

check() {
    if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "  PASS  $1 ($3)"
    else FAIL=$((FAIL+1)); echo "  FAIL  $1 期望$2 实际$3"; fi
}
# check_hdr <名称> <期望码> <响应头子串> <curl 参数...>
check_hdr() {
    local name=$1 want=$2 substr=$3; shift 3
    local resp; resp=$(curl -s -i --max-time 3 "$@")
    local code; code=$(printf '%s' "$resp" | head -1 | grep -o '[0-9][0-9][0-9]' | head -1)
    if [ "$code" = "$want" ] && printf '%s' "$resp" | grep -qi "$substr"; then
        PASS=$((PASS+1)); echo "  PASS  $name ($code 含 $substr)"
    else
        FAIL=$((FAIL+1)); echo "  FAIL  $name 期望$want 含[$substr] 实际${code:-无响应}"
    fi
}
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$@"; }
TOK_OK=$(bash tests/jwt_helper.sh methods mt-ok-001 600)
TOK_RS=$(bash tests/jwt_rs256_helper.sh methods mt-rs-001 600)

echo "== A. Session 鉴权(Cookie sid -> sess:<sid>) =="
redis-cli DEL authfail:127.0.0.1 >/dev/null
redis-cli SET sess:mt-sid-001 alice EX 120 >/dev/null
check_hdr "有效 Session -> 200+X-User-Id" 200 "X-User-Id: alice" -H "Cookie: sid=mt-sid-001" $BASE/api/user
check "无效 Session -> 401" 401 "$(code -H 'Cookie: sid=no-such-sid' $BASE/api/user)"
S96=$(printf 's%.0s' $(seq 1 96))
check "96 字符 Session ID(超长截断碰撞防护) -> 401" 401 "$(code -H "Cookie: sid=$S96" $BASE/api/user)"
redis-cli SET sess:mt-sid-exp bob EX 1 >/dev/null
sleep 1.3
check "过期 Session(键 TTL 到点) -> 401" 401 "$(code -H 'Cookie: sid=mt-sid-exp' $BASE/api/user)"
redis-cli DEL "sess:mt-sid-001" "sess:mt-sid-exp" >/dev/null

echo "== B. API Key 鉴权(X-Api-Key -> apikey:<key>) =="
redis-cli DEL authfail:127.0.0.1 >/dev/null
redis-cli SET apikey:mt-ak-001 svc-account >/dev/null
check_hdr "有效 API Key -> 200+X-User-Id" 200 "X-User-Id: svc-account" -H "X-Api-Key: mt-ak-001" $BASE/api/user
check "无效 API Key -> 401" 401 "$(code -H 'X-Api-Key: no-such-key' $BASE/api/user)"
AK96=$(printf 'k%.0s' $(seq 1 96))
check "96 字节 API Key(超长截断碰撞防护) -> 401" 401 "$(code -H "X-Api-Key: $AK96" $BASE/api/user)"
AK95=$(printf 'k%.0s' $(seq 1 95))
redis-cli SET "apikey:$AK95" svc-long EX 60 >/dev/null
check "95 字节 API Key(合法上限不误伤) -> 200" 200 "$(code -H "X-Api-Key: $AK95" $BASE/api/user)"
redis-cli DEL "apikey:mt-ak-001" "apikey:$AK95" >/dev/null

echo "== C. RS256 鉴签(AUTH_PUBKEY 公钥验签) =="
redis-cli DEL authfail:127.0.0.1 >/dev/null
check "RS256 合法 Token -> 200" 200 "$(code -H "Authorization: Bearer $TOK_RS" $BASE/api/user)"
check "RS256 篡改签名 -> 401" 401 "$(code -H "Authorization: Bearer ${TOK_RS%.*}.AAAA" $BASE/api/user)"
# 经典 RS256->HS256 混淆攻击: alg 声明 HS256,签名用公钥当 HMAC 密钥伪造。
# 服务端 HS256 固定用 AUTH_SECRET,公钥不是密钥 -> 签名不符 401(漏洞利用失败)
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
H=$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
P=$(printf '%s' '{"sub":"attacker","jti":"conf-001","exp":9999999999}' | openssl base64 -A | tr '+/' '-_' | tr -d '=')
S=$(printf '%s' "$H.$P" | openssl dgst -sha256 -hmac "$(cat tests/keys/rs256.pub)" -binary | b64url)
check "公钥当 HMAC 密钥的混淆攻击 -> 401" 401 "$(code -H "Authorization: Bearer $H.$P.$S" $BASE/api/user)"

echo "== D. 鉴权结果缓存(authcache:<sha256> 30s) =="
redis-cli DEL authfail:127.0.0.1 >/dev/null
code -H "Authorization: Bearer $TOK_OK" $BASE/api/user >/dev/null   # 首次: 验签+写缓存
check_hdr "第二次请求命中缓存" 200 "X-Auth-Cache: hit" -H "Authorization: Bearer $TOK_OK" $BASE/api/user

echo "== E. 暴力破解锁定(AUTHFAIL_LIMIT=5) =="
redis-cli DEL authfail:127.0.0.1 >/dev/null
LAST=200
for i in $(seq 1 5); do
    LAST=$(code -H "Authorization: Bearer bad-token-$i" $BASE/api/user)
done
check "连续 5 次无效凭证 -> 401" 401 "$LAST"
check "锁定后有效凭证也 403" 403 "$(code -H "Authorization: Bearer $TOK_OK" $BASE/api/user)"
redis-cli DEL authfail:127.0.0.1 >/dev/null
check "清失败计数后恢复 200" 200 "$(code -H "Authorization: Bearer $TOK_OK" $BASE/api/user)"

echo "== F. WAF HTML 实体解码(多层解码第二层) =="
redis-cli DEL authfail:127.0.0.1 >/dev/null
check "裸实体 &lt;script&gt; body -> 403" 403 \
    "$(code -X POST --data-binary '&lt;script&gt;alert(1)' $BASE/api/user)"
check "双重编码 %26lt%3B 解出实体 -> 403" 403 \
    "$(code "$BASE/?q=%26lt%3Bscript%26gt%3B")"

echo "== G. 算法策略锁定(AUTH_ALG=rs256) =="
redis-cli DEL authfail:127.0.0.1 >/dev/null
AUTH_ALG=rs256 AUTH_PUBKEY=tests/keys/rs256.pub RL_LIMIT=1000000 \
    nohup ./auth_server 8082 >/tmp/auth_algpolicy.log 2>&1 &
ALGPID=$!
sleep 0.8
# 用全新 jti 的 token: D 组写过 TOK_OK 的结果缓存(30s),缓存命中会绕过验签
# 直接 200,无法检验策略;新 token 指纹不同,必然走 jwt_verify 的白名单分支
TOK_GHS=$(bash tests/jwt_helper.sh algpol ghs-001 600)
check "rs256-only 下 HS256 Token -> 403(视同算法混淆)" 403 "$(code -H "Authorization: Bearer $TOK_GHS" http://127.0.0.1:8082/api/user)"
check "rs256-only 下 RS256 Token -> 200" 200 "$(code -H "Authorization: Bearer $TOK_RS" http://127.0.0.1:8082/api/user)"
kill $ALGPID 2>/dev/null

echo "== H. X-Real-IP 信任边界(TRUST_PROXY) =="
redis-cli DEL authfail:127.0.0.1 >/dev/null
# 钉子用例: 默认模式(不信任头)下伪造 X-Real-IP 仍按 socket IP 计数——
# 两个假 IP 各打 4 次失败, 若误信头则两桶各 4 <5 均不锁定; 按 socket IP
# 计数则 127.0.0.1 已累计 8 次 >=5, 有效凭证应被锁定 403
for i in 1 2 3 4; do
    code -H "Authorization: Bearer bad-fa-$i" -H "X-Real-IP: 8.8.8.8" $BASE/api/user >/dev/null
    code -H "Authorization: Bearer bad-fb-$i" -H "X-Real-IP: 9.9.9.9" $BASE/api/user >/dev/null
done
check "默认模式伪造头 8 次失败按 socket IP 计数 -> 有效凭证 403" 403 "$(code -H "Authorization: Bearer $TOK_OK" $BASE/api/user)"
redis-cli DEL authfail:127.0.0.1 >/dev/null
# TRUST_PROXY=1 实例: 限流/锁定键改用 Nginx 注入的 X-Real-IP, 不同假 IP 独立桶;
# 实例监听同步收窄 127.0.0.1(信任头只对仅网关可达的部署安全)
TRUST_PROXY=1 AUTHFAIL_LIMIT=5 RL_LIMIT=1000000 nohup ./auth_server 8083 >/tmp/auth_trustproxy.log 2>&1 &
TPPID=$!
sleep 0.8
for i in 1 2 3 4 5; do
    code -H "Authorization: Bearer bad-tp-$i" -H "X-Real-IP: 8.8.8.8" http://127.0.0.1:8083/api/user >/dev/null
done
check "TRUST_PROXY=1: 假 IP-A 失败 5 次后同 IP 锁定 -> 403" 403 "$(code -H 'Authorization: Bearer x' -H 'X-Real-IP: 8.8.8.8' http://127.0.0.1:8083/api/user)"
check "TRUST_PROXY=1: 假 IP-B 独立桶不受影响 -> 401" 401 "$(code -H 'Authorization: Bearer x' -H 'X-Real-IP: 9.9.9.9' http://127.0.0.1:8083/api/user)"
check "TRUST_PROXY=1: 无 X-Real-IP 回落 socket IP -> 401(未锁定)" 401 "$(code -H 'Authorization: Bearer x' http://127.0.0.1:8083/api/user)"
kill $TPPID 2>/dev/null

redis-cli DEL authfail:127.0.0.1 rl:127.0.0.1 >/dev/null
echo
echo "结果: $PASS 通过, $FAIL 失败"
[ "$FAIL" = 0 ]
