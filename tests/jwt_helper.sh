#!/usr/bin/env bash
# 签发测试 JWT(HS256): ./jwt_helper.sh [sub] [jti] [有效期秒,默认600]
SECRET=${AUTH_SECRET:-dev-secret-change-me}
b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
sub=${1:-tester}
jti=${2:-helper-001}
off=${3:-600}
header='{"alg":"HS256","typ":"JWT"}'
payload="{\"sub\":\"$sub\",\"jti\":\"$jti\",\"exp\":$(( $(date +%s) + off ))}"
h=$(printf '%s' "$header" | b64url)
p=$(printf '%s' "$payload" | b64url)
s=$(printf '%s' "$h.$p" | openssl dgst -sha256 -hmac "$SECRET" -binary | b64url)
echo "$h.$p.$s"
