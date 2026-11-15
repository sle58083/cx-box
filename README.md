# cx-box

sing-box 单体单机 Web 面板，对标 s-ui。一个 Go 二进制（内嵌前端）+ SQLite，systemd 托管，面板即节点。

## 特性

- 多协议：VLESS / VMess / Trojan / Shadowsocks / Hysteria2 / TUIC / ShadowTLS / Naive + XTLS
- 入站/出站高级配置、流量路由
- 客户端流量上限与到期时间
- 流量统计：订阅 sing-box 1.14 官方 api service 的连接事件，按用户实时归因落库（客户端已用流量、小时粒度时序、状态页累计流量）；超额或到期自动从内核配置剔除
- 系统状态查看（内核运行状态、版本、端口）
- 订阅服务（link 格式：base64 / 明文 + 流量信息头）
- 面板路径随机化 + 网页管理界面（登录、状态、入站/出站/客户端/证书管理、设置）
- 证书管理：一键自签 / PEM 导入，入站绑定后自动落盘并注入 TLS 路径
- Hysteria2 带宽（up/down_mbps）与 obfs 混淆透传（含订阅参数）
- `/apiv2` 兼容 API（token 鉴权）
- 一条命令安装，一核 1G 服务器可跑（部署零编译）

## 快速开始

```bash
# 全自动安装（随机账号密码 + 随机面板路径）
CXBOX_AUTO=1 bash <(curl -Ls https://raw.githubusercontent.com/sle58083/cx-box/main/install.sh)

# 交互式安装
bash <(curl -Ls https://raw.githubusercontent.com/sle58083/cx-box/main/install.sh)
```

安装后在服务器上输入 `cx-box` 打开管理菜单（或 `cx-box help` 查看子命令）：安装/更新/卸载、启动/停止/重启、查看日志、改面板设置、改/重置账号、生成 API token、BBR 管理等。彻底清除可用 `bash <(curl -Ls https://raw.githubusercontent.com/sle58083/cx-box/main/install.sh) purge`。

发布包由 GitHub Actions 在打 `v*` tag 时构建（`scripts/build-release.sh`），产物为 `cx-box-linux-<arch>.tar.gz`，install.sh 通过 GitHub Releases 下载安装。

## 默认配置

| 项 | 默认值 |
|---|---|
| 面板端口 | 2095 |
| 面板路径 | `/app/` |
| 订阅端口 | 2096 |
| 订阅路径 | `/sub/` |
| 账号/密码 | admin（全自动安装时随机）|

## 开发

```bash
# 构建（前端是 web/index.html 单文件，经 go:embed 内嵌，无需 Node 构建）
go build -o cx-box ./cmd/cx-box

# 测试
go test ./...
```

## License

仅供个人学习与交流。
