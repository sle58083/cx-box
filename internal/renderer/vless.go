package renderer

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/google/uuid"
	"github.com/sle58083/cx-box/internal/model"
)

// VLESSRenderer 实现 vless 协议渲染。
type VLESSRenderer struct{}

func (r *VLESSRenderer) Protocol() string { return "vless" }

func (r *VLESSRenderer) RenderInbound(_ *RenderContext, cfg model.Inbound, users []ProxyUser) (map[string]any, error) {
	out := map[string]any{}
	renderInboundCommon(out, cfg)

	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return nil, err
	}
	// 用户入口：解密注入的 proxy users；静态入口：settings.users[]。
	if cfg.IsUserInbound && len(users) > 0 {
		flow := str(settings, fFlow)
		us := make([]map[string]any, 0, len(users))
		for _, u := range users {
			m := map[string]any{fName: u.Name, fUUID: u.UUID}
			if flow != "" {
				m[fFlow] = flow
			}
			us = append(us, m)
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
	if tr, err := renderTransport(cfg.Transport); err != nil {
		return nil, err
	} else if tr != nil {
		out[fTransport] = tr
	}
	return out, nil
}

func (r *VLESSRenderer) RenderOutbound(_ *RenderContext, cfg model.Outbound) (map[string]any, error) {
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
	out[fUUID] = str(settings, fUUID)
	if flow := str(settings, fFlow); flow != "" {
		out[fFlow] = flow
	}

	if t, err := renderTLS(cfg.TLS); err != nil {
		return nil, err
	} else if t != nil {
		out[fTLS] = t
	}
	if tr, err := renderTransport(cfg.Transport); err != nil {
		return nil, err
	} else if tr != nil {
		out[fTransport] = tr
	}
	return out, nil
}

// validateFlowCombo 拦截注定不可用的组合：xtls-rprx-vision 流控要求原始
// TCP/TLS 连接，配 ws/grpc/http 传输时 sing-box 客户端会直接报错
// （vision: not a valid supported TLS connection），保存时就拦下。
// 注意 Reality + ws/grpc 经实测在 sing-box 中可用，不在此拦截。
func validateFlowCombo(transport json.RawMessage, settings map[string]any) error {
	if str(settings, fFlow) != "xtls-rprx-vision" {
		return nil
	}
	tm, err := transportMap(transport)
	if err != nil {
		return err
	}
	if tt := str(tm, fType); tt != "" && tt != "tcp" {
		return fmt.Errorf("vless: xtls-rprx-vision 流控仅支持 TCP 直连传输，请将传输方式改为「TCP 直连」或清空流控")
	}
	return nil
}

func (r *VLESSRenderer) ValidateInbound(cfg model.Inbound) error {
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return fmt.Errorf("vless inbound: listen_port 必须在 1-65535")
	}
	if err := validateInboundTLSCommon(cfg, []TLSMode{TLSModeNone, TLSModePlain, TLSModeReality, TLSModeECH}, false); err != nil {
		return err
	}
	if inSettings, err := parseMap(cfg.Settings); err == nil {
		if err := validateFlowCombo(cfg.Transport, inSettings); err != nil {
			return err
		}
	}
	if cfg.IsUserInbound {
		return nil // 用户由代理用户注入
	}
	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return err
	}
	us := parseUsers(settings)
	if len(us) == 0 {
		return fmt.Errorf("vless inbound: settings.users 不能为空（或标记 is_user_inbound）")
	}
	for i, u := range us {
		if _, err := uuid.Parse(str(u, fUUID)); err != nil {
			return fmt.Errorf("vless inbound: users[%d].uuid 非法: %w", i, err)
		}
	}
	return nil
}

func (r *VLESSRenderer) ValidateOutbound(cfg model.Outbound) error {
	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return err
	}
	if str(settings, fServer) == "" || intVal(settings, fServerPort) <= 0 {
		return fmt.Errorf("vless outbound: server/server_port 必填")
	}
	if _, err := uuid.Parse(str(settings, fUUID)); err != nil {
		return fmt.Errorf("vless outbound: uuid 非法: %w", err)
	}
	if err := validateFlowCombo(cfg.Transport, settings); err != nil {
		return err
	}
	return validateOutboundTLSCommon(cfg, []TLSMode{TLSModeNone, TLSModePlain, TLSModeReality, TLSModeECH}, false)
}

func (r *VLESSRenderer) SubscriptionURI(cfg model.Outbound, user ProxyUser) (string, error) {
	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return "", err
	}
	server, port := str(settings, fServer), portStr(settings, fServerPort)
	if server == "" || port == "" || user.UUID == "" {
		return "", fmt.Errorf("vless: 订阅 URI 缺少 server/port/uuid")
	}
	q := url.Values{}
	q.Set("encryption", "none")
	// 传输层：默认 tcp；ws 时带 path/host。
	ttype := "tcp"
	if tm, err := transportMap(cfg.Transport); err == nil && tm != nil {
		if t := str(tm, fType); t != "" {
			ttype = t
		}
		if ttype == "ws" {
			if p := str(tm, "path"); p != "" {
				q.Set("path", p)
			}
			if h, ok := tm["headers"].(map[string]any); ok {
				if host := str(h, "Host"); host != "" {
					q.Set("host", host)
				}
			}
		}
	}
	q.Set("type", ttype)
	if flow := str(settings, fFlow); flow != "" {
		q.Set("flow", flow)
	}
	tls, _ := tlsMap(cfg.TLS)
	switch {
	case realityEnabled(tls):
		q.Set("security", "reality")
		if sni := str(tls, fServerName); sni != "" {
			q.Set("sni", sni)
		}
		if rm, ok := tls[fReality].(map[string]any); ok {
			if pk := str(rm, "public_key"); pk != "" {
				q.Set("pbk", pk)
			}
			if sid := str(rm, "short_id"); sid != "" {
				q.Set("sid", sid)
			}
		}
	case tlsEnabled(tls):
		q.Set("security", "tls")
		if sni := str(tls, fServerName); sni != "" {
			q.Set("sni", sni)
		}
		if insecureFromTLS(cfg) {
			q.Set("insecure", "1")
		}
	default:
		q.Set("security", "none")
	}
	return fmt.Sprintf("vless://%s@%s:%s?%s#%s", user.UUID, server, port, q.Encode(), cfg.Name), nil
}

func (r *VLESSRenderer) Meta() ProtocolMeta {
	return ProtocolMeta{
		Protocol:    "vless",
		Directions:  []Direction{DirectionInbound, DirectionOutbound},
		TLSAllowed:  []TLSMode{TLSModeNone, TLSModePlain, TLSModeReality, TLSModeECH},
		TLSRequired: false,
		MultiUser:   true,
		Inbound: []FieldSchema{
			{Key: "flow", Label: "流控 Flow", Type: "select", Required: false, Options: []FieldOption{{Label: "xtls-rprx-vision", Value: "xtls-rprx-vision"}}, Help: "vision 流控仅支持 TCP 直连传输"},
		},
		Outbound: []FieldSchema{
			{Key: "server", Label: "服务器地址", Type: "text", Required: true},
			{Key: "server_port", Label: "端口", Type: "number", Required: true},
			{Key: "uuid", Label: "UUID", Type: "text", Required: true, Encrypt: true},
			{Key: "flow", Label: "流控 Flow", Type: "select", Required: false, Options: []FieldOption{{Label: "xtls-rprx-vision", Value: "xtls-rprx-vision"}}, Help: "vision 流控仅支持 TCP 直连传输"},
		},
	}
}

func init() { Register(&VLESSRenderer{}) }
