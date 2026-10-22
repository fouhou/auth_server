#!/usr/bin/env bash
# 签发 RS256 测试 JWT: ./jwt_rs256_helper.sh [sub] [jti] [有效期秒,默认600] [私钥路径]
# 私钥默认 tests/keys/rs256.pem, 不入库(.gitignore 排除 *.pem); 首次使用时自动
# 生成 RSA-2048 配对密钥(私钥 + 同目录 rs256.pub), 公钥经 AUTH_PUBKEY 交给
# auth_server 加载, 与 HS256 版 jwt_helper.sh 平行使用
KEY=${4:-$(dirname "$0")/keys/rs256.pem}
PUB=$(dirname "$KEY")/rs256.pub
if [ ! -f "$KEY" ]; then
    echo "生成 RS256 测试密钥对: $KEY / $PUB" >&2
    mkdir -p "$(dirname "$KEY")"
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$KEY" 2>/dev/null
    openssl rsa -in "$KEY" -pubout -out "$PUB" 2>/dev/null
    chmod 600 "$KEY"
fi
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
sub=${1:-tester}
jti=${2:-rs-001}
off=${3:-600}
header='{"alg":"RS256","typ":"JWT"}'
payload="{\"sub\":\"$sub\",\"jti\":\"$jti\",\"exp\":$(( $(date +%s) + off ))}"
h=$(printf '%s' "$header" | b64url)
p=$(printf '%s' "$payload" | b64url)
s=$(printf '%s' "$h.$p" | openssl dgst -sha256 -sign "$KEY" | b64url)
echo "$h.$p.$s"
