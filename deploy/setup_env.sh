#!/usr/bin/env bash
# auth_server 环境初始化: 装依赖 + 起 Redis + 部署 Nginx 站点(可选)
# 用法: sudo bash deploy/setup_env.sh [--with-nginx]
#   --with-nginx  同时部署 auth_request 网关配置(8080); 不加则只装依赖与 Redis
# 适用: Ubuntu/Debian(apt)。完成后按末尾提示启动 auth_server 即可使用。
set -e
cd "$(dirname "$0")/.." || exit 1

if [ "$(id -u)" != 0 ]; then echo "请用 sudo 运行"; exit 1; fi
if ! command -v apt >/dev/null; then echo "本脚本面向 Ubuntu/Debian(apt)；其他发行版请按 README 手动装依赖"; exit 1; fi

echo "== 1/3 安装编译与运行依赖 =="
apt-get update -qq
apt-get install -y -qq build-essential valgrind libssl-dev libhiredis-dev redis-server nginx curl >/dev/null
gcc --version | head -1
valgrind --version

echo "== 2/3 启动 Redis 并设置开机自启 =="
systemctl enable --now redis-server
redis-cli ping

if [ "${1:-}" = "--with-nginx" ]; then
    echo "== 3/3 部署 Nginx auth_request 网关(8080) =="
    apt-get install -y -qq nginx >/dev/null
    nginx -V 2>&1 | grep -q http_auth_request_module || { echo "警告: nginx 缺 auth_request 模块,跳过站点部署"; exit 0; }
    mkdir -p /var/www/authdemo
    cp deploy/index.html /var/www/authdemo/
    cp deploy/nginx-auth.conf /etc/nginx/sites-available/authdemo
    ln -sf /etc/nginx/sites-available/authdemo /etc/nginx/sites-enabled/authdemo
    rm -f /etc/nginx/sites-enabled/default
    nginx -t && systemctl reload nginx
    echo "Nginx 8080 已就绪"
else
    echo "== 3/3 跳过 Nginx(未指定 --with-nginx) =="
fi

cat <<'EOF'

========== 环境就绪, 启动 auth_server ==========
  make
  AUTH_SECRET=请换成真实随机密钥 RL_LIMIT=100 nohup ./auth_server 8081 &

验证: curl -i http://127.0.0.1:8080/          (预期 401, 未认证被网关拦截)
预置凭证: redis-cli SET sess:demo-sid-001 alice EX 120
          curl -i -H "Cookie: sid=demo-sid-001" http://127.0.0.1:8080/   (预期 200)
================================================
EOF
