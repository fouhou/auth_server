#!/usr/bin/env bash
# Redis 故障降级测试: 正常 -> 停 Redis(降级放行) -> 恢复
# 用法: ./tests/degrade_test.sh [port]
#   免密 sudo 直接跑；或非交互环境传 SUDO_PASS=密码 走 sudo -S
# 断言: 全程 200；仅停机段带 X-Auth-Degraded: 1，且 JWT/Session/API Key
#       三种凭证在 Redis 宕机时全部 fail-open 放行(降级面完整覆盖)；
#       API Key/Session 降级响应不携带 X-User-Id(fail-open 不透传未验证身份)
cd "$(dirname "$0")/.." || exit 1
PORT=${1:-8081}
PASS=0; FAIL=0

# 统一 sudo 入口: 有 SUDO_PASS 走 -S 从 stdin 读密码，否则常规交互 sudo
run_sudo() {
    if [ -n "${SUDO_PASS:-}" ]; then
        printf '%s\n' "$SUDO_PASS" | sudo -S -p '' "$@"
    else
        sudo -p '' "$@"
    fi
}

TOK=$(bash tests/jwt_helper.sh tester degrade-001)

redis-cli DEL rl:127.0.0.1 authfail:127.0.0.1 >/dev/null   # 清压测残留的限流/锁定键
redis-cli SET sess:dg-sid-001 tester EX 120 >/dev/null     # 预置有效测试凭证
redis-cli SET apikey:dg-key-001 tester >/dev/null
pkill -x auth_server 2>/dev/null; sleep 0.5
nohup ./auth_server $PORT >/tmp/auth_degrade.log 2>&1 &
sleep 0.8

# check_leg <名称> <期望码> <yes/no: 是否应带 X-Auth-Degraded: 1> <curl 参数...>
check_leg() {
    local name=$1 want=$2 deg=$3; shift 3
    local resp code hit
    resp=$(curl -s -i --max-time 3 "$@")
    code=$(printf '%s' "$resp" | head -1 | grep -o '[0-9][0-9][0-9]' | head -1)
    hit=$(printf '%s' "$resp" | grep -ci 'X-Auth-Degraded: 1' || true)
    if [ "$code" = "$want" ] && { { [ "$deg" = "yes" ] && [ "$hit" -ge 1 ]; } ||
                                  { [ "$deg" = "no" ] && [ "$hit" = 0 ]; }; }; then
        PASS=$((PASS+1)); echo "  PASS  $name ($code)"
    else
        FAIL=$((FAIL+1)); echo "  FAIL  $name 期望$want 降级=$deg 实际${code:-无响应} 降级头行数=$hit"
    fi
}
AUTH=("-H" "Authorization: Bearer $TOK" "http://127.0.0.1:$PORT/api/user")

echo "== 1. Redis 正常 =="
check_leg "JWT -> 200 无降级标记" 200 no "${AUTH[@]}"
echo "== 2. 停 Redis(三种凭证全部 fail-open) =="
run_sudo systemctl stop redis-server
sleep 0.5
check_leg "JWT 宕机 -> 200 + X-Auth-Degraded: 1" 200 yes "${AUTH[@]}"
check_leg "Session 宕机 -> 200 + X-Auth-Degraded: 1" 200 yes -H "Cookie: sid=dg-sid-001" "http://127.0.0.1:$PORT/api/user"
check_leg "API Key 宕机 -> 200 + X-Auth-Degraded: 1" 200 yes -H "X-Api-Key: dg-key-001" "http://127.0.0.1:$PORT/api/user"
echo "== 2.5 降级身份语义: fail-open 不透传未验证身份 =="
resp=$(curl -s -i --max-time 3 -H "X-Api-Key: dg-key-001" "http://127.0.0.1:$PORT/api/user")
if printf '%s' "$resp" | grep -qi '^X-User-Id:'; then
    FAIL=$((FAIL+1)); echo "  FAIL  API Key 降级响应不应携带 X-User-Id(身份未验证)"
else
    PASS=$((PASS+1)); echo "  PASS  API Key 降级响应无 X-User-Id"
fi
resp=$(curl -s -i --max-time 3 -H "Cookie: sid=dg-sid-001" "http://127.0.0.1:$PORT/api/user")
if printf '%s' "$resp" | grep -qi '^X-User-Id:'; then
    FAIL=$((FAIL+1)); echo "  FAIL  Session 降级响应不应携带 X-User-Id(身份未验证)"
else
    PASS=$((PASS+1)); echo "  PASS  Session 降级响应无 X-User-Id"
fi
echo "== 3. 恢复 Redis =="
run_sudo systemctl start redis-server
sleep 0.8
check_leg "恢复 -> 200 无降级标记" 200 no "${AUTH[@]}"

redis-cli DEL "rl:127.0.0.1" "sess:dg-sid-001" "apikey:dg-key-001" >/dev/null
pkill -x auth_server 2>/dev/null
echo
echo "结果: $PASS 通过, $FAIL 失败"
[ "$FAIL" = 0 ]
