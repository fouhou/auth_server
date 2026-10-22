# auth_server — 基于 Nginx auth_request 的轻量鉴权网关

C 语言从零实现的 HTTP 鉴权网关，对接 Nginx `auth_request` 子请求机制，为静态资源/上游服务提供统一鉴权与攻击检测层。

```
客户端 ──> Nginx:8080 ── auth_request 子请求 /_auth ──> auth_server:8081
                 │                                      │
                 │ 200 放行(X-User-Id 透传)              │ 五层检测链:
                 ▼                                      │ ① HTTP 走私检测
          静态资源 / 上游服务                             │ ② WAF 规则(AC 自动机)
                                                        │ ③ 鉴权(JWT/Session/API Key)
                 ◀── 401/403/429(JSON 化) ──────────────┤ ④ Redis 黑名单
                                                        │ ⑤ 固定窗口限流
```

## 目录结构

```
auth_server/
├── src/
│   ├── http_parser.c/h   # 零拷贝 HTTP 状态机 + 走私证据采集
│   ├── security.c/h      # 走私判定 + WAF 规则引擎(AC 自动机)
│   ├── auth.c/h          # 三种鉴权方式分派 + 失败锁定 + 结果缓存
│   ├── jwt.c/h           # HS256/RS256 验签(算法白名单/常量时间比较)
│   ├── redis_client.c/h  # 黑名单/限流/会话/密钥查询/断线自愈
│   ├── util.c/h          # url_decode/html_decode/b64url/常量时间比较
│   └── main.c            # epoll 事件循环 + 检测链编排
├── deploy/
│   ├── setup_env.sh      # 环境初始化(依赖/Redis/Nginx 一键就绪)
│   ├── nginx-auth.conf   # Nginx auth_request 网关配置
│   ├── waf_rules.txt     # WAF 规则表(外部规则文件, 加载时构建 AC 自动机)
│   └── index.html        # 受保护资源示例
├── tests/
│   ├── keys/rs256.pub    # RS256 测试公钥(私钥不入库, jwt_rs256_helper.sh 首次使用自动生成配对密钥)
│   ├── run_all_tests.sh  # 一键编排: 统一启停服务跑全部套件并汇总
│   └── *.sh              # 直连/三方式/解析器/降级/端到端/内存 六套测试脚本
└── Makefile
```

## 功能

### 1. 三种鉴权方式（auth.c 统一分派，互斥先到先得）

| 方式      | 凭证来源                          | 校验路径                           | 适用场景    |
| ------- | ----------------------------- | ------------------------------ | ------- |
| JWT     | `Authorization: Bearer <jwt>` | 本地验签 + Redis 注销黑名单 + 结果缓存      | 无状态 API |
| Session | `Cookie: sid=<会话ID>`          | `GET sess:<sid>`（键 TTL 即会话有效期） | 传统 Web  |
| API Key | `X-Api-Key: <key>`            | `GET apikey:<key>`（运维预置）       | 服务间调用   |

校验成功统一透传 `X-User-Id` 给上游；附加防线：暴力破解锁定（失败按客户端标识计数 `authfail:<key>`，达阈值 `AUTHFAIL_LIMIT` 后窗口内全拒）+ IP 固定窗口限流（Lua 原子化）。

### 2. HTTP 请求走私检测（零拷贝状态机）

解析器在状态机内同步采集证据位图，检测五种走私手法：

| 手法               | 检测点                                            |
| ---------------- | ---------------------------------------------- |
| CL + TE 同现       | 同一请求同时含 `Content-Length` 与 `Transfer-Encoding` |
| 多 Content-Length | 重复 CL 头 / 逗号分隔多值                               |
| TE 混淆            | `Transfer-Encoding: identity`、TE 值含逗号等歧义形态     |
| 头名非法字符           | 头 token 中出现空格等非法字符（front-end/back-end 解析差异利用点） |
| trailer 藏 CL     | chunked 结尾 trailer 中携带 `Content-Length`        |

网关模式下auth_request子请求不带 body 且原始 CL 被清空——Nginx 以 `X-Original-CL/TE` 别名头透传客户端原始定界头，服务端做二次词法判罚，四类纯头证据走私在网关层同样可达。

### 3. WAF 规则引擎（AC 自动机 + 外部规则文件）

- 规则外置于 [deploy/waf_rules.txt](deploy/waf_rules.txt)（`编号|pattern` 每行一条），启动时加载并构建 AC 自动机，一次扫描 O(文本长度) 匹配全部规则
- 文件缺失/格式错误/零规则一律拒绝启动（fail-fast），pattern 加载时强制小写化
- 3 轮 URL 解码 + HTML 实体解码（多层解码），防 `%252e` 二次编码与 `&lt;script&gt;` 实体绕过；归一化产物内嵌 NUL 归一化，防匹配截断致盲
- CRLF 注入检测查原始串中的 `%0d%0a`
- 规则分组：SQL 注入(R1xxx) / XSS(R2xxx) / 路径穿越(R3xxx) / 命令执行(R4xxx) / Log4j(R9001)
- body 经 8KB 滚动窗口（64B 重叠）全量扫描

### 4. JWT 鉴权（HS256/RS256）

- 算法白名单：只接受显式 `"alg":"HS256"` / `"alg":"RS256"`，杜绝 alg:none / 降级混淆攻击；RS256 未配置公钥时声明即拒绝；`AUTH_ALG=rs256` 可锁定单算法模式
- HS256：HMAC-SHA256 重算 + **常量时间比较**，防时序侧信道
- RS256：`AUTH_PUBKEY` 注入 PEM 公钥（加载时校验 RSA 类型），`EVP_DigestVerify` 一步式验签
- `exp` 严格校验（溢出/残缺文本拒绝）；`sub`/`jti` 字符集白名单（防 Redis 键注入）
- 返回码分级：-1 格式错误→401 / -2 算法攻击→403 / -3 签名不符→401 / -4 过期→401

### 5. Redis 集成

- **注销黑名单**：`EXISTS blk:<jti>`，登出即失效
- **固定窗口限流**：Lua 原子 `INCR+EXPIRE`（`redis_incr_ttl`，与失败计数共用），超限 429 + `Retry-After`
- **鉴权结果缓存**：JWT 成功结果按 `sha256(token)` 指纹缓存 30s（`authcache:`），命中跳过验签与黑名单——注销生效延迟 ≤30s 的显式取舍
- 断线自愈重连（建连/读写超时 1s，网络黑洞有界失败）；宕机 fail-open 降级（`X-Auth-Degraded: 1` 标记，降级响应不透传未验证身份）

### 6. Nginx auth_request 对接

- `/_auth` internal 子请求，`proxy_pass_request_body off`（鉴权只看 URI/头）
- `X-Original-URI` / `X-Original-Method` 还原原始请求；`X-Real-IP` 透传真实客户端 IP（限流/锁定键）
- `TRUST_PROXY=1` 开启信任模式（键改用 X-Real-IP，监听同步收窄 127.0.0.1）；直连模式只信 socket 对端地址，忽略可伪造头
- `auth_request_set` 透传 `X-User-Id` 给上游
- **状态码语义还原**：auth_request 模块把子请求非 401/403 状态码一律转 500，429 限流语义需 `auth_request_set $auth_status $upstream_status` 捕获后在 error_page 中还原
- upstream keepalive 连接池

## 快速开始

```bash
# 一键装环境(推荐): 编译依赖 + Redis + Nginx 网关一条命令就绪
sudo bash deploy/setup_env.sh --with-nginx
# 或手动装依赖: gcc / valgrind / libssl-dev / libhiredis-dev / redis-server / nginx(with http_auth_request_module)

make
# 启动鉴权服务(8081; 密钥与下方令牌签发命令保持一致)
AUTH_SECRET=dev-secret-change-me RL_LIMIT=100 ./auth_server 8081
# RS256: AUTH_PUBKEY=tests/keys/rs256.pub(公钥文件缺失时由 tests/jwt_rs256_helper.sh 自动生成配对密钥)

# 对接 Nginx 网关(setup_env.sh --with-nginx 已部署则跳过)
sudo cp deploy/nginx-auth.conf /etc/nginx/sites-available/authdemo
sudo ln -sf ../sites-available/authdemo /etc/nginx/sites-enabled/
sudo mkdir -p /var/www/authdemo && sudo cp deploy/index.html /var/www/authdemo/
sudo nginx -t && sudo systemctl reload nginx

# 方式一: 签发测试 JWT 并访问(签名密钥与服务端 AUTH_SECRET 一致)
TOKEN=$(bash tests/jwt_helper.sh alice demo-001 600)
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/

# 方式二: 预置 Session 凭证并访问
redis-cli SET sess:demo-sid-001 alice EX 120
curl -H "Cookie: sid=demo-sid-001" http://127.0.0.1:8080/
```

环境变量：`AUTH_SECRET`（JWT HS256 密钥，缺省开发值并打印告警）、`AUTH_PUBKEY`（RS256 公钥 PEM 路径，缺省禁用 RS256）、`AUTH_ALG`（`rs256` 锁定单算法）、`TRUST_PROXY`（`1` 时限流/锁定键改用 X-Real-IP）、`WAF_RULES_FILE`（规则文件路径）、`REDIS_HOST`/`REDIS_PORT`、`RL_LIMIT`（每标识每窗口请求上限）、`AUTHFAIL_LIMIT`（锁定阈值，缺省 20）。测试凭证预置：`redis-cli SET sess:<sid> <user> EX 120` / `SET apikey:<key> <user>`。

## 测试

```bash
bash tests/run_all_tests.sh      # 一键全量: 按各套件要求统一启停服务,跑 6 套件 108 项并汇总
bash tests/auth_test.sh          # 直连全场景: JWT/黑名单/限流/WAF/走私 12 项
bash tests/auth_methods_test.sh  # 三种鉴权方式 + 缓存 + 锁定 + 信任边界 23 项
                                 # (需服务以 AUTH_PUBKEY+AUTHFAIL_LIMIT=5 启动, 见脚本头注释)
bash tests/parser_regression.sh  # 解析器/边界回归 59 项
bash tests/degrade_test.sh       # Redis 宕机降级 7 项(JWT/Session/API Key 全 fail-open)
bash tests/nginx_e2e.sh 8080     # Nginx 端到端 7 项(需 nginx + auth_server 运行中)
bash tests/valgrind_run.sh       # 内存检查(0 errors, hiredis 良性单例已抑制)
```

验证矩阵（全部通过）：

| 套件 | 覆盖 |
|---|---|
| 直连 12 项 | 无 token/合法/篡改签名/alg:none/过期/exp 溢出与残缺/黑名单/限流/清键恢复/WAF/走私 |
| 三种鉴权 23 项 | Session 有效/无效/超长/过期、API Key 有效/无效/超长/合法上限、RS256 合法/篡改/混淆攻击、结果缓存、失败锁定/恢复、HTML 实体解码、算法策略锁定、X-Real-IP 信任边界 |
| 解析器 59 项 | 流水线粘包/半关闭/分片/CL·TE 词法/chunked/长度上限/WAF 绕过面(NUL 对抗)/AC 语义/别名头证据/keep-alive |
| 降级 7 项 | Redis 正常 → 宕机 fail-open 标记(**JWT/Session/API Key 三种凭证全验证**, 降级不透传身份) → 恢复 |
| e2e 7 项 | 经 Nginx: 无 token 401 / 合法 200 / SQL 注入 403 / alg:none 403 / 过期 401 / 篡改 401 / 走私拒绝 |

## 压测

环境：Ubuntu 24.04 VM（4 vCPU / 4GB）、回环、wrk 4.1.0、`-t2 -c100 -d10s`：

| 链路                                       | QPS      | 说明                                   |
| ---------------------------------------- | -------- | ------------------------------------ |
| 直连 auth_server:8081（JWT 完整链路，缓存命中态）      | **2809** | 3 次 Redis 往返（锁定+缓存+限流）               |
| 经 Nginx auth_request（upstream keepalive） | **1082** | Nginx 转发 + auth_request 子请求鉴权的完整网关链路 |
| 直连 demo 对照（跳过鉴权与 Redis）                  | 45252    | 16× 差距，佐证同步 Redis 是唯一瓶颈              |

瓶颈归因：直连延迟与吞吐符合 Little's law，瓶颈为**同步 hiredis 阻塞事件循环**——每请求多次 Redis 同步往返将事件循环串行化，属显式设计取舍（见下表）。工业级改进方向：hiredis 异步适配器（`redisAsyncContext` 接入 epoll，官方推荐的事件集成方式）或 OpenResty cosocket 模式。

## 设计取舍与改进方向

| 决策                  | 取舍                                            | 改进方向                                                   |
| ------------------- | --------------------------------------------- | ---------------------------------------------------------------------------------- |
| Redis 宕机 fail-open  | 保可用性（登录流量不被 Redis 故障打死），带降级标记且不透传未验证身份        | 生产高安全场景应 fail-close，可配置                                                            |
| AC 自动机规则匹配          | 一次扫描 O(文本长度)，规则外部文件可扩展                        | 规则热更新（原子指针切换，单线程无撕裂读）；规则规模上千条时切换 Hyperscan——Intel 高性能多模式匹配库，Snort / Suricata 的生产方案 |
| 同步 Redis            | 实现简单、时序确定                                     | hiredis 异步适配器接入事件循环，或 OpenResty cosocket 模式                                        |
| JWT 无状态 + Redis 黑名单 | 兼顾无状态验证与主动注销                                  | jti 换刷新令牌轮转                                                                        |
| 网关模式信任边界            | X-Real-IP 仅在 TRUST_PROXY 开启时信任，直连只信 socket 对端 | 多层代理场景用 realip 模块按信任 CIDR 还原                                                       |
