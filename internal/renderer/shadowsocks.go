package renderer

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"

	"github.com/sle58083/cx-box/internal/model"
)

// ShadowsocksRenderer 实现 shadowsocks 协议渲染（单 method+password，无原生 TLS）。
type ShadowsocksRenderer struct{}

// SS2022KeyLen 返回 2022 系列加密的密钥字节数（第二返回值表示是否为
// 2022 系列）。2022 加密与经典加密的根本区别：密钥必须是定长随机字节的
// base64 编码，任意字符串密码会被 sing-box 直接拒绝。
func SS2022KeyLen(method string) (int, bool) {
	if !strings.HasPrefix(method, "2022-") {
		return 0, false
	}
	if strings.Contains(method, "aes-128") {
		return 16, true
	}
	// aes-256 与 chacha20 变体都是 32 字节。
	return 32, true
}

// validSS2022Key 判断字符串是否是合法的 2022 密钥（base64 解码后恰为
// keyLen 字节；兼容带/不带 padding 的写法）。
func validSS2022Key(s string, keyLen int) bool {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
		if raw, err := enc.DecodeString(s); err == nil && len(raw) == keyLen {
			return true
		}
	}
	return false
}

// SS2022ServerKey 推导入站实际生效的服务端密钥（PSK）：settings 里有
// 合法密钥时用它；否则按入站 ID 确定性推导——面板自动补齐，存量入站
// 升级后即自愈，生成配置与订阅两侧同源同值、无需落库。
func SS2022ServerKey(id string, method string, settings map[string]any) string {
	keyLen, ok := SS2022KeyLen(method)
	if !ok {
		return ""
	}
	if pw := str(settings, fPassword); validSS2022Key(pw, keyLen) {
		return pw
	}
	sum := sha256.Sum256([]byte("cx-box/ss2022/psk/" + id))
	return base64.StdEncoding.EncodeToString(sum[:keyLen])
}

// SS2022UserKey 把客户端的原始密码确定性推导成合法的 2022 用户密钥
// （uPSK）。客户端密码是面板生成的任意字符串，不能直接当 2022 密钥用；
// 推导在渲染与订阅两侧同源同值，客户端最终用「服务端密钥:用户密钥」
// 组合密码连接（sing-box 2022 多用户约定）。
func SS2022UserKey(method string, rawPassword string) string {
	keyLen, ok := SS2022KeyLen(method)
	if !ok {
		return rawPassword
	}
	sum := sha256.Sum256([]byte("cx-box/ss2022/user/" + rawPassword))
	return base64.StdEncoding.EncodeToString(sum[:keyLen])
}

func (r *ShadowsocksRenderer) Protocol() string { return "shadowsocks" }

func (r *ShadowsocksRenderer) RenderInbound(_ *RenderContext, cfg model.Inbound, users []ProxyUser) (map[string]any, error) {
	out := map[string]any{}
	renderInboundCommon(out, cfg)

	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return nil, err
	}
	method := str(settings, fMethod)
	out[fMethod] = method
	if _, is2022 := SS2022KeyLen(method); is2022 {
		// 2022 加密：入站必须带服务端密钥（PSK），缺失时 sing-box 以
		// missing psk 拒绝整份配置。settings 没填合法密钥时按入站 ID
		// 自动推导补齐（SS2022ServerKey），用户入口与静态入站都覆盖。
		out[fPassword] = SS2022ServerKey(cfg.ID.String(), method, settings)
	} else if !(cfg.IsUserInbound && len(users) > 0) {
		out[fPassword] = str(settings, fPassword)
	}
	if cfg.IsUserInbound && len(users) > 0 {
		// 多用户模式：每个代理用户一个密码（SS 多用户用 users[]，method 共享）。
		// 2022 时用户密码须先推导成合法密钥（SS2022UserKey）。
		us := make([]map[string]any, 0, len(users))
		for _, u := range users {
			pw := u.Password
			if _, is2022 := SS2022KeyLen(method); is2022 {
				pw = SS2022UserKey(method, u.Password)
			}
			us = append(us, map[string]any{fName: u.Name, fPassword: pw})
		}
		out[fUsers] = us
	}

	if tr, err := renderTransport(cfg.Transport); err != nil {
		return nil, err
	} else if tr != nil {
		out[fTransport] = tr
	}
	return out, nil
}

func (r *ShadowsocksRenderer) RenderOutbound(_ *RenderContext, cfg model.Outbound) (map[string]any, error) {
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
	out[fMethod] = str(settings, fMethod)
	out[fPassword] = str(settings, fPassword)
	return out, nil
}

func (r *ShadowsocksRenderer) ValidateInbound(cfg model.Inbound) error {
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return fmt.Errorf("shadowsocks inbound: listen_port 必须在 1-65535")
	}
	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return err
	}
	if str(settings, fMethod) == "" {
		return fmt.Errorf("shadowsocks inbound: method 必填")
	}
	// is_user_inbound：密码由代理用户注入，settings 无需提供 password。
	if cfg.IsUserInbound {
		return nil
	}
	if str(settings, fPassword) == "" {
		return fmt.Errorf("shadowsocks inbound: password 必填")
	}
	return nil
}

func (r *ShadowsocksRenderer) ValidateOutbound(cfg model.Outbound) error {
	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return err
	}
	if str(settings, fServer) == "" || intVal(settings, fServerPort) <= 0 {
		return fmt.Errorf("shadowsocks outbound: server/server_port 必填")
	}
	if str(settings, fMethod) == "" || str(settings, fPassword) == "" {
		return fmt.Errorf("shadowsocks outbound: method/password 必填")
	}
	return nil
}

func (r *ShadowsocksRenderer) SubscriptionURI(cfg model.Outbound, user ProxyUser) (string, error) {
	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return "", err
	}
	server, port := str(settings, fServer), portStr(settings, fServerPort)
	method := str(settings, fMethod)
	// 优先用代理用户的密码；为空则回退 settings 静态密码。
	password := user.Password
	if password == "" {
		password = str(settings, fPassword)
	}
	if _, is2022 := SS2022KeyLen(method); is2022 && user.Password != "" {
		// 2022 多用户：客户端密码是「服务端密钥:用户密钥」组合，两侧
		// 密钥与入站渲染同源推导（SS2022ServerKey / SS2022UserKey）。
		// cfg.ID 是订阅侧 inboundAsOutbound 带入的入站 ID。
		password = SS2022ServerKey(cfg.ID.String(), method, settings) + ":" + SS2022UserKey(method, user.Password)
	}
	if server == "" || port == "" || method == "" || password == "" {
		return "", fmt.Errorf("shadowsocks: 订阅 URI 缺少 server/port/method/password")
	}
	userinfo := base64.StdEncoding.EncodeToString([]byte(method + ":" + password))
	return fmt.Sprintf("ss://%s@%s:%s#%s", userinfo, server, port, url.PathEscape(cfg.Name)), nil
}

func (r *ShadowsocksRenderer) Meta() ProtocolMeta {
	return ProtocolMeta{
		Protocol:    "shadowsocks",
		Directions:  []Direction{DirectionInbound, DirectionOutbound},
		TLSAllowed:  []TLSMode{TLSModeNone},
		TLSRequired: false,
		MultiUser:   true,
		Inbound: []FieldSchema{
			{Key: "method", Label: "加密方式", Type: "select", Required: true, Default: defaultJSON("aes-128-gcm"), Options: []FieldOption{
				{Label: "2022-blake3-aes-128-gcm", Value: "2022-blake3-aes-128-gcm"},
				{Label: "2022-blake3-aes-256-gcm", Value: "2022-blake3-aes-256-gcm"},
				{Label: "aes-128-gcm", Value: "aes-128-gcm"},
				{Label: "aes-256-gcm", Value: "aes-256-gcm"},
				{Label: "chacha20-ietf-poly1305", Value: "chacha20-ietf-poly1305"},
			}},
			{Key: "password", Label: "密码", Type: "text", Required: false, Encrypt: true,
				Help: "用户入口模式可留空（客户端各自使用自己的密码）；静态入站必填。2022-blake3 系列的密钥须是 base64 编码的定长密钥（16/32 字节），留空时系统自动生成"},
		},
		Outbound: []FieldSchema{
			{Key: "server", Label: "服务器地址", Type: "text", Required: true},
			{Key: "server_port", Label: "端口", Type: "number", Required: true},
			{Key: "method", Label: "加密方式", Type: "select", Required: true, Default: defaultJSON("aes-128-gcm"), Options: []FieldOption{
				{Label: "2022-blake3-aes-128-gcm", Value: "2022-blake3-aes-128-gcm"},
				{Label: "2022-blake3-aes-256-gcm", Value: "2022-blake3-aes-256-gcm"},
				{Label: "aes-128-gcm", Value: "aes-128-gcm"},
				{Label: "aes-256-gcm", Value: "aes-256-gcm"},
				{Label: "chacha20-ietf-poly1305", Value: "chacha20-ietf-poly1305"},
			}},
			{Key: "password", Label: "密码", Type: "text", Required: true, Encrypt: true},
		},
	}
}

func init() { Register(&ShadowsocksRenderer{}) }
