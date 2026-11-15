package renderer

import (
	"fmt"

	"github.com/sle58083/cx-box/internal/model"
)

// SocksRenderer 实现 socks 出站渲染（代理 IP 的主流协议：SOCKS5 / 4a / 4）。
// 只支持出站方向：把买来的代理 IP（地址:端口:账号:密码）作为落地出口，
// 入站方向与订阅 URI 返回 ErrUnsupported。
type SocksRenderer struct{}

func (r *SocksRenderer) Protocol() string { return "socks" }

func (r *SocksRenderer) RenderInbound(_ *RenderContext, _ model.Inbound, _ []ProxyUser) (map[string]any, error) {
	return nil, ErrUnsupported
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

func (r *SocksRenderer) ValidateInbound(model.Inbound) error { return ErrUnsupported }

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
		Directions: []Direction{DirectionOutbound},
		TLSAllowed: []TLSMode{TLSModeNone},
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
