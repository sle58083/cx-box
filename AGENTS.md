# cx-box — AI 开发须知（接管必读）

cx-box 是 sing-box 单体单机 Web 面板，对标 Teminuosi/s-ui：单个 Go 二进制（前端内嵌）+ SQLite，systemd 托管，面板即节点。当前版本见 `internal/server/server.go` 的 `const Version`（写本文时为 0.5.18），内核 sing-box 1.14.4。

接手顺序：先读本文，再读 `docs/PROJECT_STATE.md`（现状与设计决策）、`docs/DEV_NOTES.md`（构建/测试/发版操作），最后看 `README.md`（产品说明）。

## 构建与测试

```bash
go build -o cx-box ./cmd/cx-box   # 前端 web/index.html 经 go:embed 内嵌，无构建步骤
go vet ./...
go test ./...
./cx-box run                       # 本地运行，数据落在程序旁 db/、etc/、bin/
```

Go 1.22，模块 `github.com/sle58083/cx-box`，Web 框架 Gin，ORM 为 GORM + glebarez/sqlite（WAL）。

## 仓库地图

| 路径 | 职责 |
|---|---|
| `cmd/cx-box/` | 入口与 CLI 子命令：run / setting / admin / token / firewall / migrate / uri |
| `internal/model/` | 中立数据模型（9 表：Setting、Admin、APIToken、Inbound、Outbound、Client、Certificate、TrafficRecord、RoutingRule） |
| `internal/renderer/` | 协议渲染器插件：每协议一个文件（RenderInbound / RenderOutbound / SubscriptionURI / Validate / Meta）+ `defaults.go` 默认模板 |
| `internal/configsvc/` | 配置生成与应用管线、生成器（含客户端路由/测速组/IP 封锁规则合成） |
| `internal/kernel/` | 内核托管：下载、启停 sing-box 子进程 |
| `internal/server/` | HTTP 服务：面板 API（面板路径 + /api）、订阅服务（独立监听）、双监听 |
| `internal/service/` | 业务服务（客户端、证书、设置等） |
| `internal/sub/` | 订阅生成：入站转出站视图、SNI/insecure 修正、派生链接 |
| `internal/traffic/` | 流量采集：订阅内核 api service 连接事件、按用户归因、落库、IP 限制判定 |
| `internal/acme/` | ACME 签发/续签（Cloudflare DNS-01，x/crypto/acme） |
| `internal/firewall/` | 防火墙抽象：ufw > firewalld > iptables 三后端 |
| `web/index.html` | 前端单文件（原生 JS，无框架无构建） |
| `install.sh` / `cx-box.sh` | 一键安装脚本 / 服务器管理菜单脚本（装到 /usr/bin/cx-box） |

## 架构铁律（改代码前先理解，条条都是踩坑换来的）

1. **中立模型 + 渲染器插件**：数据库存业务模型，不存内核 JSON。加新协议 = 新增一个 renderer 文件并在 `defaults.go` 加默认模板，不动管线。
2. **应用管线不可绕过**：一切变更经 `configsvc.Apply`——生成 → 写临时文件 → `sing-box check` → 通过才原子替换 `etc/config.json` → 重启内核。禁止先覆盖正式文件再校验（坏文件留盘会让内核下次重启直接起不来）。
3. **保存自动应用**：入站/出站/客户端/证书的增删改在 service 层保存后立即 Apply，失败以 `apply_error` 返回、前端红色提示，**绝不静默**。不要改回手动应用。
4. **Inbound 没有 Enable 字段**：启用状态是 `Status == "enabled"`，别到处找开关字段。
5. **按用户路由的字段是 `auth_user`，不是 `user`**：写 `user` 时 check 照样过、日志也能看到用户名，但规则永不命中且无任何报错。 sing-box 按认证用户匹配就认 `auth_user`（生成器在 `configsvc/generator.go`、`template.go`）。
6. **Reality 入站禁止注入证书**（双重防护，勿拆）：`configsvc.resolveCertBindings` 对 Reality 跳过证书注入；`renderer.renderTLS` 在 Reality 时剥离 certificate_path/key_path。Reality + 证书路径会让内核 FATAL「certificate is unavailable in reality」，且每次应用都失败、整机停在旧配置。
7. **密钥永不外泄**：证书私钥、Setting 里的 `api_secret`、ACME 令牌与账户私钥在模型层标 `json:"-"`，任何 API 不得输出。新增敏感字段照此办理。
8. **兜底出站恒存在**：生成器保证 `direct` 出站存在（路由兜底与直连规则都引用它）；`route.final` 的决定规则在 `resolveRouteFinal`：selector 优先，其次第一个非 direct 出站，**block 永不作默认**（曾有 bug 把 final 覆写成 block 导致全网被拒，已有单测钉住，别重构丢了）。
9. **订阅侧两条修正规则**（`internal/sub/sub.go`）：绑证书但没填 SNI 时用证书首域名补 SNI；生效证书为自签（含自动证书兜底）时链接加 `insecure=1`。绑真证书时不加 insecure，客户端做正规校验——此时 SNI 与证书不匹配是用户配置问题，不要在生成侧「帮忙」放宽。
10. **AnyTLS 密码约定是 base64，不是 bug**：cx-box 渲染 anytls 时入站 users、出站、订阅链接三处统一用 base64 编码后的密码（见 `internal/renderer/anytls.go` 注释引用的协议矩阵）。已与 anytls-go 官方客户端、mihomo、sing-box 三方互通实测通过。**不要「修复」成明文**，改一处就全链路对不上。
11. **Shadowsocks 2022 密钥模型**：入站 password=服务端 PSK、users[].password=uPSK，均为定长 base64 密钥；渲染时 PSK 取设置值或按入站 ID 确定性推导，客户端原始密码经 sha256 推导成 uPSK，订阅发「PSK:uPSK」组合。逻辑在 `internal/renderer/shadowsocks.go`，动之前先读懂。
12. **无凭据的经典 ss 入站要跳过生成**：没有客户端时内核以 missing password 拒绝整份配置；生成时跳过此类入站（2022 系列有 PSK，豁免）。
13. **空 listen 渲染 `"::"`**：不要把空监听地址丢给内核默认——在部分机器上只绑回环，曾导致全节点不可达。
14. **ACME 状态机**：`WaitOrder` 在订单 Ready（授权已过、待提交 CSR）时就返回，finalize 由 `CreateOrderCert` 内部完成。签发代码必须接受 Ready 为正常中间态（`internal/acme/issuer.go`，有假 ACME 全流程回归测试钉住）。
15. **防火墙同步走钩子**：`configsvc.AfterApply` → `firewall.Sync`，期望端口 = 面板+订阅+SSH+全部启用入站端口（tcp+udp）；开启时先加放行再启用本体（防锁死）；同步失败只记日志、不阻断应用。

## 前端约定

- 单文件 `web/index.html` 原生 JS，无构建；改完 `go build` 即生效。
- **能汉化的全部汉化，协议名与技术标识不汉化**（vless/urltest/UUID/SNI/TLS/Reality 等保持英文）——这是项目定版规则。
- 表单由后端下发的协议 Meta（FieldSchema）驱动，不同协议显示不同字段；新协议记得补 Meta 与模板。
- 前端 `api()` 有 30 秒超时与中文错误翻译，别去掉（曾有用户的浏览器走死节点代理导致界面假死）。

## 做事红线（项目所有者的决定，优先级高于你的判断）

- **未经所有者当轮明确批准，不推送代码、不打 tag、不发 Release。** 以前每一轮的批准只对那一轮有效。
- **已搁置/已否决，不要主动实现，也不要反复追问**：入站级指定出站（搁置）、direct 出站绑定本机第二 IP/网卡（「先不做」）。所有者自己提起时再做。
- **待所有者决策、未批准前不要动手**：普通 TLS 入站保存时校验 SNI 是否在所绑证书域名内并提示（Reality 除外）；防火墙无后端时管理菜单一键安装 ufw。
- 二进制名只叫 `cx-box`，环境变量只认 `CXBOX_AUTO`（不要恢复 sui / SUI_AUTO 等旧命名）。
- `install.sh` 装完**不**进管理菜单、**不**打印用法说明（所有者明确要求，保持现状）。
- API token 目前只能 CLI 生成（`cx-box token -desc <备注>`），列表/删除功能所有者明确说过先不做。

## 更多

- 现状快照、设计决策的来龙去脉、已知限制：`docs/PROJECT_STATE.md`
- 构建/测试/推送/发版/运维操作手册：`docs/DEV_NOTES.md`
- 给新接手 AI 的现成开场白：`docs/HANDOVER_PROMPT.md`
