# 渡口 Ferry

渡口在一个 Go 服务里提供中文管理后台、管理 API 和 SOCKS5／HTTP 代理。代理使用经过核验的 VPNGate 出口。网页的「使用教程」包含爬虫、自动选出口、指定地区、Hysteria 2、sing-box 和 Xray 的操作步骤。

## 在 Linux VPS 上启动

需要 Docker Engine、Docker Compose 和已存在的 `/dev/net/tun`。解压项目后，在含有 `compose.yaml` 的目录运行：

```bash
test -c /dev/net/tun
docker compose build
docker compose run --rm --no-deps ferry init-token
docker compose up -d
docker compose logs -f ferry
```

第一条命令失败时，需要在你的 VPS 产品中启用 TUN，再启动渡口。保存 `init-token` 输出的一次性凭据。初始化前重新运行此命令会作废旧凭据。Docker 使用普通 bridge 网络，容器内处理 TUN 和路由。管理与代理端口默认只发布到 VPS 的回环地址。

在你自己的电脑上打开到 VPS 的 SSH 转发。把 `user@your-vps` 换成你原来登录 VPS 的地址。

```bash
ssh -N -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:8787:127.0.0.1:8787 \
  -L 127.0.0.1:7928:127.0.0.1:7928 user@your-vps
```

用浏览器打开 [http://127.0.0.1:8787](http://127.0.0.1:8787)。第一次会看到「初始化渡口」。把 `init-token` 输出的凭据填入页面，并设置管理员密码。初始化凭据使用一次后失效。以后使用管理员密码登入。

进入后台后先按以下顺序操作：

1. **地区出口**。默认开启日本 JP。添加想用的地区，等待至少一个健康出口。列表中暂时没有节点时，界面会显示缺额。
2. **接入管理**。创建代理账号，勾选允许的地区，保存只展示一次的代理密码。
3. **使用教程**。先用 curl 查到出口 IP，再将同样的账号用于爬虫或已有代理。

同一台 VPS 上的 hy2、sing-box 或 Xray 若直接运行在宿主机，SOCKS 出站地址填 `127.0.0.1:7928`。这些核心各自在独立容器运行时，应通过同一受信任的 Docker 网络，连接渡口服务名和容器端口 `7928`。在两者的配置已备份时再合并出站规则。

若端口冲突，可以在项目目录的 `.env` 里设置 `FERRY_ADMIN_PORT=18787` 或 `FERRY_PROXY_PORT=17928`，再重建端口映射。相应调整 SSH 远端地址或宿主机上的出站地址。容器内端口仍为 8787 和 7928。后台教程和总览里显示的代理地址取自 `FERRY_PROXY_ADDRESS`，Compose 默认填 `127.0.0.1:${FERRY_PROXY_PORT}`。把代理发布到局域网地址时，把它改成客户端实际使用的地址，例如 `192.168.1.50:7928`。

## 在局域网的另一台 Mac 上用 Docker 测试

macOS 本身不能运行渡口的隧道部分，但 Docker Desktop 的 Linux 虚拟机可以。下面假设那台 Mac 已装好 Docker Desktop，局域网地址为 `192.168.1.50`。

在当前这台电脑的项目根目录把项目同步过去。把 `user@other-mac.local` 换成那台 Mac 的登录用户和主机名。`--exclude compose.yaml` 用于保留那边改过的端口配置，第一次同步时去掉这个参数：

```bash
rsync -av --exclude 预览 --exclude compose.yaml ./ user@other-mac.local:~/ferry/
```

在那台 Mac 的 `~/ferry/compose.yaml` 里，把端口改为发布到所有网卡，并把示例地址改成它的局域网地址：

```yaml
      FERRY_PROXY_ADDRESS: "192.168.1.50:7928"
    ports:
      - "0.0.0.0:${FERRY_ADMIN_PORT:-8787}:8787"
      - "0.0.0.0:${FERRY_PROXY_PORT:-7928}:7928"
```

然后在那台 Mac 的 `~/ferry` 目录下构建并启动。Mac 主机上没有 `/dev/net/tun`，跳过 Linux 部分的 `test -c` 检查即可，设备由 Docker Desktop 的虚拟机提供：

```bash
docker compose build
docker compose run --rm --no-deps ferry init-token
docker compose up -d
```

之后在本机浏览器打开 `http://192.168.1.50:8787`，代理使用 `192.168.1.50:7928`。之后每次同步代码后运行 `docker compose build && docker compose up -d`。

这种方式下后台密码和代理密码以明文 HTTP 在局域网中传输，只在受信任的家庭或办公网络中这样做。另外，Docker Desktop 会把外部请求的来源地址换成它的网关地址，后台的登录限流在这种情况下只能按全局计数，见「数据和管理员恢复」一节。

## 代理用户名怎么填

假设已创建名为 `crawler` 的账号，并授权日本和韩国。所有示例使用生成的同一个代理密码。

| 用户名 | 行为 |
|---|---|
| `crawler` | 在账号允许的健康出口里分配。账号模式为自动轮换时，优先使用当前连接较少且与上次不同的出口 |
| `crawler.JP` | 只选日本，优先使用日本主用出口 |
| `crawler.JP.会话ID` | 使用后台或 API 创建的会话绑定 |
| `crawler.auto.会话ID` | 同样使用会话绑定，地区由绑定决定 |

固定地区账号可省略地区后缀。固定会话账号需要填写会话 ID。没有合适的出口时连接失败。默认目标为每地区三个已建线角色，分别为主用、候选、备用。节点不足、出口重复或达到全局隧道数上限时会出现缺额。手动「验证后替换」需要至少一个额外的全局隧道位置。

入口支持 SOCKS5 TCP、标准 HTTP 代理和 HTTPS CONNECT。HTTPS 网站通过 CONNECT 或 SOCKS5 访问。SOCKS5 的 UDP 转发与 IPv6 出站暂未支持。自动模式按新建 SOCKS／CONNECT 隧道选择出口，普通 HTTP 明文代理按请求分配。已有 CONNECT 和 SOCKS 长连接保持原出口，直到结束或隧道断开。使用 `socks5h` 可让渡口经出口解析域名。

代理端口同时最多处理 512 个连接，超出时新连接会被直接关闭，日志每 10 秒最多记录一次。SOCKS 和 CONNECT 隧道在两个方向都 10 分钟没有数据时会被关闭，长时间静默的长连接需要客户端自行重连或发送保活数据。

出口健康通过外部 HTTPS 探测测量，公网 IP 再经 [Country.is](https://country.is/) 核验。地区服务不可用时，新出口继续等待验证。地区数据库与目标网站的判断可能不同。现有节点失效后，后台在同一地区尝试替换。

## 数据和管理员恢复

配置、代理账号、API 凭据摘要和有保留期限的事件存放在 Compose 的 `ferry_data` 卷。备份时先停服并妥善保护数据卷，其中包含管理员密码哈希和可选的二次验证密钥。活动隧道、连接、绑定、管理登录、任务和冷却状态随进程重启清空。

恢复管理员访问时，先停止渡口，再运行重置命令。这个操作重置管理员身份和二次验证，保留地区和代理账号。

```bash
docker compose stop ferry
docker compose run --rm --no-deps ferry reset-admin
docker compose run --rm --no-deps ferry init-token
docker compose up -d
```

后台和代理默认通过回环地址加 SSH 访问。直接通过 HTTP 对外暴露会使认证材料失去传输保护。需要自己的 HTTPS 接入时，在容器中挂载证书和密钥，再通过 `FERRY_TLS_CERT`、`FERRY_TLS_KEY` 指定路径。此模式下后台使用 HTTPS，代理端口同时识别 TLS 到 HTTP 代理以及常规 SOCKS5／HTTP，SOCKS5 对外仍需受信任的传输层。

登录、初始化和安全设置的失败尝试按来源地址限流：同一地址每分钟最多 8 次失败，所有地址合计每分钟最多 60 次失败，成功的尝试不计数。来源地址取自 TCP 连接本身，不读取 `X-Forwarded-For`。因此在 Docker Desktop 端口映射或反向代理后面，所有请求可能显示为同一个地址，限流会退化为对所有人共同计数；这时若有人反复猜密码，管理员需要等一分钟再登录。

事件在后台协程中批量写入数据卷。正常停止时会先写完再退出，进程被强制杀死时可能丢失最后几条事件。

## 管理 API

所有 `/api/v1/` 的状态与管理接口需要登录会话或 API 凭据。浏览器使用同源会话。自动化使用 `Authorization: Bearer <API_TOKEN>`，写操作同时发送 `X-Ferry-Request: 1` 和 `Content-Type: application/json`。只读凭据可查询，管理凭据可执行写操作，反馈凭据仅可创建会话及登记目标冷却。管理员密码、TOTP 和会话撤销仅接受浏览器会话。

- 状态查询：`GET /api/v1/status`、`/overview`、`/regions`、`/regions/JP`、`/exits`、`/nodes`、`/operations`、`/events`、`/sessions`、`/cooldowns`。
- 后台任务：探测、连线与替换提交后返回 202 和任务 ID，通过 `GET /api/v1/operations/{id}` 查询进度。
- 实时状态：`GET /api/v1/stream` 是 Server-Sent Events 流。状态变化时推送 `event: status`，数据与 `/status` 相同，另外每 30 秒推送一次心跳。
- 代理账号：`POST /api/v1/accounts/save`，新建时请求体为 `{"Name":"crawler","Mode":"rotate","Regions":["JP","KR"],"Limit":20,"Enabled":true,"Days":30}`，返回只展示一次的代理密码。`Mode` 可选 `rotate`（自动轮换）、`region`（固定地区，`Regions` 只能有一个）和 `sticky`（固定会话）。修改已有账号时 `ID` 与 `Name` 都填账号名。`Days` 省略或为 0 时保持原有效期，大于 0 时从现在起重新计算，`"ClearExpiry":true` 改为长期，两者不能同时使用。从 `Regions` 去掉的地区，该账号在这些地区的连接会被断开，固定会话会被删除。另有 `accounts/delete` 和 `accounts/rotate`（重新生成密码），请求体为 `{"Name":"crawler"}`。
- 固定会话：`POST /api/v1/sessions`，请求体为 `{"Account":"crawler","Region":"JP","Minutes":15}`。返回唯一 ID 和绑定的出口。`GET /api/v1/sessions` 的每一项带 `ExitState`：`ok` 表示可用，`unavailable` 表示出口暂时不健康或地区已关闭，`lost` 表示出口已关闭或正在下线，需要新建会话。
- 反馈：`POST /api/v1/feedback`，请求体为 `{"ID":"会话ID","Target":"example.com","Minutes":5}`。只有该目标与绑定出口组合进入冷却。爬虫应按目标的 Retry-After 退避。代理无法从加密的 HTTPS 流量读取网站状态码。
- 健康检查：`GET /health/live` 确认进程工作，`GET /health/ready` 确认存在可分配出口。

## 项目结构与本地验证

| 目录 | 职责 |
|---|---|
| `cmd/ferry` | 命令行入口、启动管理后台和代理服务 |
| `internal/admin` | 管理 API、登录、内嵌网页和教程 |
| `internal/proxy` | SOCKS5、HTTP 和 HTTPS CONNECT 接入 |
| `internal/egress` | 地区选择、出口调度、健康检查和冷却 |
| `internal/vpngate` | VPNGate 目录、OpenVPN 和 Linux 隧道 |
| `internal/store` | 配置、凭据和事件持久化 |

`go test -race ./...` 覆盖代理协议、认证身份传播、地区约束、轮换、固定会话、目标冷却与空池拒绝，以及代理在 Accept 出错后继续工作、闲置隧道关闭、账号有效期修改、去掉地区后断开连接、会话出口状态、事件在锁外写盘、登录按来源限流、CSRF、状态推送和存储写入失败回滚。Linux amd64 与 arm64 均可交叉编译。

从项目根目录运行以下命令可以在 Mac 上试用后台。它只监听本机回环地址，关闭隧道，不修改系统代理、DNS 或路由。退出时清理临时数据。

```bash
(
  ferry_test_dir="$(mktemp -d)" || exit 1
  trap 'rm -rf -- "$ferry_test_dir"' EXIT
  export FERRY_DATA="$ferry_test_dir"
  export FERRY_ENABLE_TUNNELS=0
  export FERRY_ADMIN_LISTEN=127.0.0.1:18787
  export FERRY_PROXY_LISTEN=127.0.0.1:17928
  export FERRY_TLS_CERT="" FERRY_TLS_KEY=""
  go run ./cmd/ferry init-token && go run ./cmd/ferry
)
```

用浏览器打开 [本机渡口后台](http://127.0.0.1:18787)，输入命令输出的一次性凭据，设置管理员密码。此模式下后台、教程和代理鉴权可用，代理会拒绝需要 VPN 出口的连接。Linux TUN 建链、真实公网出口和故障切换可在 Linux Docker 环境中用内置教程验收。
