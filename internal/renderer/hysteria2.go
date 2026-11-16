package renderer

import (
	"fmt"
	"net/url"

	"github.com/sle58083/cx-box/internal/model"
)

// Hysteria2Renderer 实现 hysteria2 协议渲染（内置 QUIC TLS，必选 TLS，禁 Reality）。
type Hysteria2Renderer struct{}

func (r *Hysteria2Renderer) Protocol() string { return "hysteria2" }

func (r *Hysteria2Renderer) RenderInbound(_ *RenderContext, cfg model.Inbound, users []ProxyUser) (map[string]any, error) {
	out := map[string]any{}
	renderInboundCommon(out, cfg)

	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return nil, err
	}
	if cfg.IsUserInbound && len(users) > 0 {
		us := make([]map[string]any, 0, len(users))
		for _, u := range users {
			us = append(us, map[string]any{fName: u.Name, fPassword: u.Password})
		}
		out[fUsers] = us
	} else if static := parseUsers(settings); len(static) > 0 {
		out[fUsers] = static
	}

	if t, err := renderTLS(cfg.TLS); err != nil {
		return nil, err
	} else if t != nil {
		out[fTLS] = t
	}
	// 带宽与混淆：up_mbps/down_mbps（数字）、ignore_client_bandwidth（布尔）、
	// obfs（{type:"salamander",password}）、masquerade（字符串或对象）原样透传。
	passthrough(out, settings, "up_mbps", "down_mbps", "ignore_client_bandwidth", "obfs", "masquerade")
	return out, nil
}

func (r *Hysteria2Renderer) RenderOutbound(_ *RenderContext, cfg model.Outbound) (map[string]any, error) {
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
	out[fPassword] = str(settings, fPassword)
	passthrough(out, settings, "up_mbps", "down_mbps", "obfs")

	if t, err := renderTLS(cfg.TLS); err != nil {
		return nil, err
	} else if t != nil {
		out[fTLS] = t
	}
	return out, nil
}

// validateObfs 校验 settings.obfs（存在时）：sing-box 仅支持 salamander 且密码必填。
func validateObfs(settings map[string]any) error {
	v, ok := settings["obfs"]
	if !ok || v == nil {
		return nil
	}
	obfs, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("hysteria2: settings.obfs 必须是对象 {type, password}")
	}
	if t := str(obfs, "type"); t != "salamander" {
		return fmt.Errorf("hysteria2: settings.obfs.type 仅支持 salamander")
	}
	if str(obfs, fPassword) == "" {
		return fmt.Errorf("hysteria2: settings.obfs.password 不能为空")
	}
	return nil
}

func (r *Hysteria2Renderer) ValidateInbound(cfg model.Inbound) error {
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return fmt.Errorf("hysteria2 inbound: listen_port 必须在 1-65535")
	}
	if err := validateInboundTLSCommon(cfg, []TLSMode{TLSModePlain}, true); err != nil {
		return err
	}
	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return err
	}
	if err := validateObfs(settings); err != nil {
		return err
	}
	if cfg.IsUserInbound {
		return nil
	}
	us := parseUsers(settings)
	if len(us) == 0 {
		return fmt.Errorf("hysteria2 inbound: settings.users 不能为空（或标记 is_user_inbound）")
	}
	for i, u := range us {
		if str(u, fPassword) == "" {
			return fmt.Errorf("hysteria2 inbound: users[%d].password 不能为空", i)
		}
	}
	return nil
}

func (r *Hysteria2Renderer) ValidateOutbound(cfg model.Outbound) error {
	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return err
	}
	if str(settings, fServer) == "" || intVal(settings, fServerPort) <= 0 {
		return fmt.Errorf("hysteria2 outbound: server/server_port 必填")
	}
	if str(settings, fPassword) == "" {
		return fmt.Errorf("hysteria2 outbound: password 必填")
	}
	if err := validateObfs(settings); err != nil {
		return err
	}
	return validateOutboundTLSCommon(cfg, []TLSMode{TLSModePlain}, true)
}

func (r *Hysteria2Renderer) SubscriptionURI(cfg model.Outbound, user ProxyUser) (string, error) {
	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return "", err
	}
	server, port := str(settings, fServer), portStr(settings, fServerPort)
	if server == "" || port == "" || user.Password == "" {
		return "", fmt.Errorf("hysteria2: 订阅 URI 缺少 server/port/password")
	}
	q := url.Values{}
	if sni := sniFromTLS(cfg); sni != "" {
		q.Set("sni", sni)
	}
	if insecureFromTLS(cfg) {
		q.Set("insecure", "1")
	}
	if obfs, ok := settings["obfs"].(map[string]any); ok {
		if t := str(obfs, "type"); t != "" {
			q.Set("obfs", t)
		}
		if p := str(obfs, fPassword); p != "" {
			q.Set("obfs-password", p)
		}
	}
	return fmt.Sprintf("hysteria2://%s@%s:%s?%s#%s", url.PathEscape(user.Password), server, port, q.Encode(), cfg.Name), nil
}

func (r *Hysteria2Renderer) Meta() ProtocolMeta {
	return ProtocolMeta{
		Protocol:    "hysteria2",
		Directions:  []Direction{DirectionInbound, DirectionOutbound},
		TLSAllowed:  []TLSMode{TLSModePlain},
		TLSRequired: true,
		MultiUser:   true,
		Inbound: []FieldSchema{
			{Key: "password", Label: "密码", Type: "text", Required: true, Encrypt: true},
			{Key: "up_mbps", Label: "上行带宽 Mbps", Type: "number", Required: false},
			{Key: "down_mbps", Label: "下行带宽 Mbps", Type: "number", Required: false},
			{Key: "masquerade", Label: "伪装站点", Type: "text", Required: false},
		},
		Outbound: []FieldSchema{
			{Key: "server", Label: "服务器地址", Type: "text", Required: true},
			{Key: "server_port", Label: "端口", Type: "number", Required: true},
			{Key: "password", Label: "密码", Type: "text", Required: true, Encrypt: true},
			{Key: "up_mbps", Label: "上行带宽 Mbps", Type: "number", Required: false},
			{Key: "down_mbps", Label: "下行带宽 Mbps", Type: "number", Required: false},
		},
	}
}

func init() { Register(&Hysteria2Renderer{}) }
