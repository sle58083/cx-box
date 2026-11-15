package renderer

import (
	"fmt"

	"github.com/sle58083/cx-box/internal/model"
)

// HTTPRenderer 实现 http 协议渲染（双向）：
//   - 出站：把买来的 HTTP / HTTPS 代理 IP 作为落地出口（HTTPS 走出站 TLS）；
//   - 入站：本机开一个 HTTP 代理端口供局域网设备/软件连接（网关式入站，
//     账号在 settings.users 里静态配置，不绑定面板客户端）；入站开启 TLS
//     即为 HTTPS 代理（证书可绑面板证书或应用时自动生成）。订阅 URI 返回 ErrUnsupported。
type HTTPRenderer struct{}

func (r *HTTPRenderer) Protocol() string { return "http" }

func (r *HTTPRenderer) RenderInbound(_ *RenderContext, cfg model.Inbound, _ []ProxyUser) (map[string]any, error) {
	out := map[string]any{}
	renderInboundCommon(out, cfg)

	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return nil, err
	}
	if us := proxyUsers(settings); len(us) > 0 {
		out[fUsers] = us
	}
	if t, err := renderTLS(cfg.TLS); err != nil {
		return nil, err
	} else if t != nil {
		out[fTLS] = t
	}
	return out, nil
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

func (r *HTTPRenderer) ValidateInbound(cfg model.Inbound) error {
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return fmt.Errorf("http inbound: listen_port 必须在 1-65535")
	}
	if err := validateInboundTLSCommon(cfg, []TLSMode{TLSModePlain}, false); err != nil {
		return err
	}
	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return err
	}
	return validateProxyUsers("http", settings)
}

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
		Directions: []Direction{DirectionInbound, DirectionOutbound},
		TLSAllowed: []TLSMode{TLSModeNone, TLSModePlain},
		Inbound: []FieldSchema{
			{Key: "users", Label: "账号列表", Type: "array", Required: false,
				Help: "每项 {username, password}；留空表示无认证（任何人可连，仅建议内网使用）"},
		},
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
