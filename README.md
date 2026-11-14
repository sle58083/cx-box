# cx-box

sing-box 单体单机 Web 面板，对标 s-ui。一个 Go 二进制（内嵌前端）+ SQLite，systemd 托管，面板即节点。

## 特性

- 多协议：VLESS / VMess / Trojan / Shadowsocks / Hysteria2 / TUIC / ShadowTLS / Naive + XTLS
- 入站/出站高级配置、流量路由
- 客户端流量上限与到期时间
- 流量统计 + 系统状态监控
- 订阅服务（link / json / clash + 外部订阅）
- 面板路径随机化 + 多语言 + 明暗主题
- `/apiv2` 兼容 API（token 鉴权）
- 一条命令安装，一核 1G 服务器可跑（部署零编译）

## 快速开始

```bash
# 全自动安装（随机账号密码 + 随机面板路径）
SUI_AUTO=1 bash <(curl -Ls https://raw.githubusercontent.com/sle58083/cx-box/main/install.sh)

# 交互式安装
bash <(curl -Ls https://raw.githubusercontent.com/sle58083/cx-box/main/install.sh)
```

安装后 `cx-box` 管理命令：启动/停止/重启、改设置、改账号、SSL、BBR 等。

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
# 后端
go build -o sui ./cmd/sui

# 前端（web/ 目录）
cd web && npm install && npm run build
```

## License

仅供个人学习与交流。
