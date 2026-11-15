package renderer

import (
	"fmt"

	"github.com/sle58083/cx-box/internal/model"
)

// HTTPRenderer 实现 http 出站渲染（代理 IP 的另一主流协议：HTTP / HTTPS 代理）。
// 只支持出站方向；HTTPS 代理通过出站 TLS 配置启用（仅普通 TLS，不支持 Reality/ECH），
// 入站方向与订阅 URI 返回 ErrUnsupported。
type HTTPRenderer struct{}

func (r *HTTPRenderer) Protocol() string { return "http" }

func (r *HTTPRenderer) RenderInbound(_ *RenderContext, _ model.Inbound, _ []ProxyUser) (map[string]any, error) {
	return nil, ErrUnsupported
}

func (r *HTTPRenderer) RenderOutbound(_ *RenderContext, cfg model.Outbound) (map[string]any, error) {
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
	if v := str(settings, "username"); v != "" {
		out["username"] = v
	}
	if pw := str(settings, fPassword); pw != "" {
		out[fPassword] = pw
	}
	if v := str(settings, "path"); v != "" {
		out["path"] = v
	}
	passthrough(out, settings, "headers")

	if t, err := renderTLS(cfg.TLS); err != nil {
		return nil, err
	} else if t != nil {
		out[fTLS] = t
	}
	return out, nil
}

func (r *HTTPRenderer) ValidateInbound(model.Inbound) error { return ErrUnsupported }

func (r *HTTPRenderer) ValidateOutbound(cfg model.Outbound) error {
	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return err
	}
	if str(settings, fServer) == "" {
		return fmt.Errorf("http outbound: server 必填（代理 IP 地址）")
	}
	if p := intVal(settings, fServerPort); p <= 0 || p > 65535 {
		return fmt.Errorf("http outbound: server_port 必须在 1-65535")
	}
	if str(settings, fPassword) != "" && str(settings, "username") == "" {
		return fmt.Errorf("http outbound: 填了密码时用户名必填")
	}
	return validateOutboundTLSCommon(cfg, []TLSMode{TLSModePlain}, false)
}

func (r *HTTPRenderer) SubscriptionURI(model.Outbound, ProxyUser) (string, error) {
	return "", ErrUnsupported
}

func (r *HTTPRenderer) Meta() ProtocolMeta {
	return ProtocolMeta{
		Protocol:   "http",
		Directions: []Direction{DirectionOutbound},
		TLSAllowed: []TLSMode{TLSModeNone, TLSModePlain},
		Outbound: []FieldSchema{
			{Key: "server", Label: "代理地址", Type: "text", Required: true},
			{Key: "server_port", Label: "代理端口", Type: "number", Required: true},
			{Key: "username", Label: "用户名", Type: "text", Required: false},
			{Key: "password", Label: "密码", Type: "text", Required: false, Encrypt: true},
			{Key: "path", Label: "路径", Type: "text", Required: false},
		},
	}
}

func init() { Register(&HTTPRenderer{}) }
