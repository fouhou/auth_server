#!/usr/bin/env bash
# 全量测试编排: 按各套件的服务启动要求统一启停, 串行跑 6 个套件并汇总
# 用法: ./tests/run_all_tests.sh
#   非交互环境把 sudo 密码带进环境变量给降级套件: SUDO_PASS=密码 ./tests/run_all_tests.sh
# 前置: redis-server 运行中; nginx 已按 deploy/nginx-auth.conf 配置(e2e 需要)
set -u
cd "$(dirname "$0")/.." || exit 1
PASS_SUITE=0; FAIL_SUITE=0; RESULTS=()

start_server() {   # start_server <日志文件> [ENV=值 ...] — 统一在 8081 启动
    local log=$1; shift
    pkill -x auth_server 2>/dev/null; sleep 0.5
    env "$@" nohup ./auth_server 8081 >"$log" 2>&1 &
    sleep 1
}
stop_server() { pkill -x auth_server 2>/dev/null; true; }

run_suite() {      # run_suite <名称> <命令...> — 以退出码判定套件成败
    local name=$1; shift
    echo; echo "======== $name ========"
    if "$@"; then
        RESULTS+=("PASS  $name"); PASS_SUITE=$((PASS_SUITE+1))
    else
        RESULTS+=("FAIL  $name"); FAIL_SUITE=$((FAIL_SUITE+1))
    fi
}

# 1) 主链路 + 2) 端到端: 默认限流 100(auth_test 的 429 用例依赖它), 同一服务复用
start_server /tmp/ra_auth.log RL_LIMIT=100 AUTH_SECRET=dev-secret-change-me
run_suite "auth_test          主链路 12 项"     bash tests/auth_test.sh
run_suite "nginx_e2e          端到端 7 项"      bash tests/nginx_e2e.sh

# 3) 三种鉴权 + 4) 解析器: RS256 公钥 + 失败阈值 5(锁定用例快速触发) + 高限流防误报
start_server /tmp/ra_methods.log RL_LIMIT=1000000 AUTHFAIL_LIMIT=5 \
             AUTH_PUBKEY=tests/keys/rs256.pub AUTH_SECRET=dev-secret-change-me
run_suite "auth_methods       三种鉴权 23 项"   bash tests/auth_methods_test.sh
run_suite "parser_regression  解析器 59 项"     bash tests/parser_regression.sh

# 5) 降级七段: 自带服务启停与系统 Redis 停启(SUDO_PASS 从调用环境继承)
run_suite "degrade_test       降级 7 项"        bash tests/degrade_test.sh

# 6) valgrind: 自带服务启停
run_suite "valgrind_run       内存检查"         bash tests/valgrind_run.sh

stop_server
echo; echo "======== 汇总 ========"
for r in "${RESULTS[@]}"; do echo "  $r"; done
echo "套件: $PASS_SUITE 通过, $FAIL_SUITE 失败"
[ "$FAIL_SUITE" = 0 ]
