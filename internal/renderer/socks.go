package renderer

import (
	"fmt"

	"github.com/sle58083/cx-box/internal/model"
)

// SocksRenderer 实现 socks 协议渲染（双向）：
//   - 出站：把买来的代理 IP（地址:端口:账号:密码，SOCKS5 / 4a / 4）作为落地出口；
//   - 入站：本机开一个 SOCKS5 代理端口供局域网设备/软件连接（网关式入站，
//     账号在 settings.users 里静态配置，不绑定面板客户端，订阅 URI 返回 ErrUnsupported）。
type SocksRenderer struct{}

func (r *SocksRenderer) Protocol() string { return "socks" }

// proxyUsers 提取 settings.users（sing-box 入站账号列表，{username, password} 形态）。
func proxyUsers(settings map[string]any) []map[string]any {
	return parseUsers(settings)
}

// validateProxyUsers 校验入站账号列表：每项必须同时有 username 与 password。
func validateProxyUsers(proto string, settings map[string]any) error {
	for i, u := range proxyUsers(settings) {
		if str(u, "username") == "" || str(u, fPassword) == "" {
			return fmt.Errorf("%s inbound: users[%d] 必须同时填 username 与 password", proto, i)
		}
	}
	return nil
}

func (r *SocksRenderer) RenderInbound(_ *RenderContext, cfg model.Inbound, _ []ProxyUser) (map[string]any, error) {
	out := map[string]any{}
	renderInboundCommon(out, cfg)

	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return nil, err
	}
	if us := proxyUsers(settings); len(us) > 0 {
		out[fUsers] = us
	}
	return out, nil
}

func (r *SocksRenderer) RenderOutbound(_ *RenderContext, cfg model.Outbound) (map[string]any, error) {
	out := map[string]any{}
	renderOutboundCommon(out, cfg)

	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return nil, err
	}
	out[fServer] = str(settings, fServer)
	if v := settings[fServerPort]; v != nil {
		out[fServerPort] = v
	}
	if v := str(settings, "version"); v != "" {
		out["version"] = v
	}
	if v := str(settings, "username"); v != "" {
		out["username"] = v
	}
	if pw := str(settings, fPassword); pw != "" {
		out[fPassword] = pw
	}
	// network 限定走代理的网络（tcp/udp），udp_over_tcp 让 UDP 经 TCP 隧道转发。
	passthrough(out, settings, fNetwork, "udp_over_tcp")
	return out, nil
}

func (r *SocksRenderer) ValidateInbound(cfg model.Inbound) error {
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return fmt.Errorf("socks inbound: listen_port 必须在 1-65535")
	}
	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return err
	}
	return validateProxyUsers("socks", settings)
}

func (r *SocksRenderer) ValidateOutbound(cfg model.Outbound) error {
	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return err
	}
	if str(settings, fServer) == "" {
		return fmt.Errorf("socks outbound: server 必填（代理 IP 地址）")
	}
	if p := intVal(settings, fServerPort); p <= 0 || p > 65535 {
		return fmt.Errorf("socks outbound: server_port 必须在 1-65535")
	}
	switch v := str(settings, "version"); v {
	case "", "5", "4", "4a":
	default:
		return fmt.Errorf("socks outbound: version 只能是 5 / 4a / 4")
	}
	if str(settings, fPassword) != "" && str(settings, "username") == "" {
		return fmt.Errorf("socks outbound: 填了密码时用户名必填")
	}
	return nil
}

func (r *SocksRenderer) SubscriptionURI(model.Outbound, ProxyUser) (string, error) {
	return "", ErrUnsupported
}

func (r *SocksRenderer) Meta() ProtocolMeta {
	return ProtocolMeta{
		Protocol:   "socks",
		Directions: []Direction{DirectionInbound, DirectionOutbound},
		TLSAllowed: []TLSMode{TLSModeNone},
		Inbound: []FieldSchema{
			{Key: "users", Label: "账号列表", Type: "array", Required: false,
				Help: "新建时自动随机生成（每行可点「随机」更换）；全部删空表示无认证（任何人可连，仅建议内网使用）"},
		},
		Outbound: []FieldSchema{
			{Key: "server", Label: "代理地址", Type: "text", Required: true},
			{Key: "server_port", Label: "代理端口", Type: "number", Required: true},
			{Key: "version", Label: "SOCKS 版本", Type: "select", Required: false, Default: defaultJSON("5"), Options: []FieldOption{
				{Label: "5（SOCKS5）", Value: "5"},
				{Label: "4a", Value: "4a"},
				{Label: "4", Value: "4"},
			}},
			{Key: "username", Label: "用户名", Type: "text", Required: false},
			{Key: "password", Label: "密码", Type: "text", Required: false, Encrypt: true},
		},
	}
}

func init() { Register(&SocksRenderer{}) }
