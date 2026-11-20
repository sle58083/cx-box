# cx-box 开发与运维操作手册

给接手开发的 AI / 开发者：构建、测试、推送、发版、线上排障的标准动作。项目铁律在 `AGENTS.md`，现状在 `docs/PROJECT_STATE.md`。

## 1. 本地开发

```bash
go build -o cx-box ./cmd/cx-box
go vet ./...
go test ./...
./cx-box run    # 数据目录在程序旁：db/cx-box.db、etc/config.json、bin/sing-box（首次运行自动下载内核）
```

- Go 1.22；前端是 `web/index.html` 单文件，`go:embed` 内嵌，改完重新 build 即生效，没有 npm 步骤。
- 数据库是 SQLite（WAL），本地调试可直接删 `db/` 重置。
- 写并发相关的 sqlite 单测注意：`:memory:` 库多 goroutine 场景要 `SetMaxOpenConns(1)`，否则会随机丢表。

## 2. 测试方法论

- **单元测试**：`go test ./...`，重点包 renderer / configsvc / sub / acme 都有回归测试，改这些包必须跑。
- **端到端测试**（历次发版的实际做法，脚本未随仓库分发，按此方法论自建）：
  1. 干净目录起面板，等 `/healthz` 就绪；
  2. 用 API 建入站/出站/客户端（注意：API 建用户入站要显式给 `is_user_inbound: true` 和端口，默认值不自动补；客户端创建必须给 email 字段）；
  3. 拉订阅、解码链接，把链接转成 sing-box 客户端出站配置；
  4. 用 sing-box 客户端经节点实际发请求（HTTP 回显服务验出口 IP、字节计数验流量归因），不要只看 `sing-box check` 通过——check 过不等于规则命中（auth_user 的坑就是这么藏住的）。
- **环境限制**：受限沙箱里 UDP 出网常被禁，Hysteria2 / TUIC 无法在沙箱内端到端验证，这两协议的改动必须在真实服务器上验。其余 TCP 协议可本地全验。
- 通过本地 HTTP 代理测本机 sing-box 时，curl 要带 `--noproxy ""`：环境 `no_proxy` 含 127.0.0.1 时，显式 `-x` 也会被绕过，出现「链路全通但内核零连接」的假象。

## 3. 推送代码（GitHub：sle58083/cx-box）

- 常规环境用 git 正常 push 到 `main`。
- 已知限制（通过 GitHub 连接器/MCP 操作时）：`push_files` 可能 403；连接器**不能**写 `.github/workflows/`、**不能**建 tag、**不能**管 Release——这些只能走 GitHub 网页。换工具时先小步验证一个文件再批量。
- 推送后逐个文件核对远端内容（blob sha / 提交记录），不要假设批量调用全成功；遇到 500 先查远端状态再决定是否重推，避免重复提交。

## 4. 发版流程（每一步都要所有者当轮批准后才执行）

1. 改版本号：`internal/server/server.go` 的 `const Version`；
2. `go vet ./...` + `go test ./...` + 端到端回归（第 2 节）；
3. 提交并推送到 main；
4. 在 GitHub 网页新建 Release：tag 填新版本号（如 `v0.5.19`）、指向 main、标题写版本号、**勾选 Set as the latest release**、Publish；
5. Actions 自动构建 5 个架构包（约 1 分钟），回 Release 页核验 **Assets = 7**（5 个架构包 + 2 个源码包）、Latest 标记正确；
6. 更新 `docs/PROJECT_STATE.md`（版本号、已完成清单、版本史加一行），随下一轮提交入库；
7. 向所有者汇报：版本号 + 提交号 + 资产数 + 实测证据。汇报要带证据，不要只说「已完成」。

注意：install.sh 从 Releases 拉最新正式版，Release 若留 draft 或没设 Latest，用户装到的就还是旧版。

## 5. 线上部署速查

```
/usr/local/cx-box/          安装目录（cx-box 主程序、bin/sing-box、db/、etc/）
/usr/bin/cx-box             管理菜单脚本（服务器上直接敲 cx-box）
systemd 服务名：cx-box      journalctl -u cx-box -f 看日志
etc/config.json             当前生效的内核配置（面板生成，勿手改，改了也会被下次应用覆盖）
```

常用 CLI（服务器上，`cx-box` 二进制子命令，与菜单脚本同名不同物、注意区分）：

| 命令 | 用途 |
|---|---|
| `cx-box setting -show / -port / -path / -subPort / -subPath / -reset` | 查看/改/重置面板与订阅设置 |
| `cx-box admin` / `cx-box admin -reset` / `-username X -password Y` | 查看/重置/设定管理员（密码只存 bcrypt，无法找回原文） |
| `cx-box token -desc <备注>` | 生成 API token（请求头 `Authorization: Bearer <token>` 或 `X-API-Token`） |
| `cx-box firewall -on / -off / -status / -sync` | 防火墙托管 |
| `cx-box uri` | 查看访问地址信息 |

## 6. 线上排障顺序（按真实事故频率排）

1. **节点全灭/-1**：先看最近保存有没有 `apply_error`（有 = 新配置被拒、在跑旧配置，按错误原文定位）；再看状态页内核是否运行；再查防火墙/安全组端口。
2. **某 TLS 协议有延迟打不开、其他协议正常**：查该入站绑的证书与 SNI 是否匹配（绑真证书 + SNI 填无关域名 + 无 insecure = 校验必挂）；解法是 SNI 改证书域名或解绑证书走自动兜底。
3. **订阅拉不到**：源站直连订阅端口验证服务本身；经 CDN 中转失败多为回源端口被网络层拦截，换 CDN 支持的端口（如 8080）验证。
4. **Reality 节点突然全挂且每次保存都应用失败**：查 Reality 入站是否被绑了证书（老版本 bug，升级到 ≥v0.5.13 即免疫）。
5. **面板打不开但 IP 可以、域名不行**：与证书无关（面板走 HTTP）；解析正确而连接被重置，多为本地网络对域名的在途过滤，用同 IP 加 Host 头的 curl 对比验证。
6. 定位不了就上服务器看 `journalctl -u cx-box` 与内核报错原文，不要隔空猜协议问题——历次事故的真因基本都在配置与环境层，不在协议本身。

## 7. 安全红线

- 服务器地址、面板路径、账号口令、API token、Cloudflare 令牌等**部署机密永不写入本仓库**（含文档与注释），也不写进提交信息。
- 证书私钥、api_secret、ACME 令牌在代码里一律 `json:"-"`，新加敏感字段照办（见 AGENTS.md 铁律 7）。
- 替所有者操作线上服务器时：用临时 token、事后删除；聊天里出现过的口令视为已暴露，提醒轮换。
