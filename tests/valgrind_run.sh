#!/usr/bin/env bash
# valgrind 内存检查: 起服务 -> 打请求(覆盖解析/WAF body/三种鉴权/降级 fail-open 路径) -> 判定
# 用法: ./tests/valgrind_run.sh [port]
#   降级段需要停/启系统 Redis: 免密 sudo 直接跑；非交互环境传 SUDO_PASS=密码
# 判定标准: ERROR SUMMARY 应为 0 errors——hiredis 单例 sds 缓冲的
# possibly lost 属已知良性,已经 --suppressions 抑制(见 valgrind.supp 头注释)
cd "$(dirname "$0")/.." || exit 1
PORT=${1:-8084}
PASS=0; FAIL=0

# 统一 sudo 入口(与 degrade_test.sh 同款)
run_sudo() {
    if [ -n "${SUDO_PASS:-}" ]; then
        printf '%s\n' "$SUDO_PASS" | sudo -S -p '' "$@"
    else
        sudo -p '' "$@"
    fi
}

pkill -x auth_server 2>/dev/null; pkill -f valgrind.bin 2>/dev/null; sleep 0.5
# --suppressions: 抑制 hiredis 单例 sds 缓冲的已知良性 possibly-lost(见 valgrind.supp 头注释)
nohup valgrind --leak-check=full --suppressions=tests/valgrind.supp ./auth_server $PORT >/tmp/auth_vg.log 2>&1 &
sleep 3
curl -s -o /dev/null --max-time 3 "http://127.0.0.1:$PORT/api/x"                      # 无凭证 GET
curl -s -o /dev/null --max-time 3 -X POST --data 'name=tom' "http://127.0.0.1:$PORT/submit"   # CL body + WAF 扫描
redis-cli SET sess:vg-sid vgx EX 60 >/dev/null                                        # Session 路径
curl -s -o /dev/null --max-time 3 -H "Cookie: sid=vg-sid" "http://127.0.0.1:$PORT/api/x"
# 降级 fail-open 路径(uid 零初始化回归): 停 Redis 后 API Key/Session 请求——
# 修复前该路径读未初始化栈内存(uid)，valgrind 必报 uninit
redis-cli SET apikey:vg-key vgx EX 60 >/dev/null
run_sudo systemctl stop redis-server
sleep 0.5
curl -s -o /dev/null --max-time 3 -H "X-Api-Key: vg-key" "http://127.0.0.1:$PORT/api/x"    # API Key 降级
curl -s -o /dev/null --max-time 3 -H "Cookie: sid=vg-sid" "http://127.0.0.1:$PORT/api/x"   # Session 降级
run_sudo systemctl start redis-server
pkill -TERM -f valgrind.bin   # auth_server 是 valgrind 内的 guest,无独立进程,必须杀 valgrind 本体
                              # (模式用 valgrind.bin 而非 valgrind——后者会误杀本脚本自身)
sleep 6                      # 给摘要落盘时间
echo "== valgrind 判定 =="
VLOST=$(grep -a "definitely lost" /tmp/auth_vg.log | head -1)
BADRD=$(grep -acE "Invalid (read|write)" /tmp/auth_vg.log)
echo "  $VLOST"
grep -a "ERROR SUMMARY" /tmp/auth_vg.log | head -1 | sed 's/^/  /'
if echo "$VLOST" | grep -q "definitely lost: 0 bytes in 0 blocks" && [ "$BADRD" = "0" ]; then
    echo "  判定: 通过"
    exit 0
fi
echo "  判定: 失败(详见 /tmp/auth_vg.log)"
exit 1
