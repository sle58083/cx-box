package renderer

import (
	"fmt"
	"time"

	"github.com/sle58083/cx-box/internal/model"
)

// Clash 系客户端（Mihomo / Clash Verge / Stash 等）使用 YAML 配置订阅，
// 与 base64 分享链接是两套完全不同的编码：每个协议在 Mihomo 里的字段名、
// 传输层选项结构都与分享链接参数不同，无法靠字符串替换转换。本文件为各
// 协议渲染器补上 ClashProxy 方法，把「出站视图 + 代理用户」映射成 Mihomo
// 的 proxies 条目（字段语义以 Mihomo 文档为准），订阅包据此组装 YAML。
// 协议编码规则仍由渲染器唯一负责，与 SubscriptionURI 同级。

// ClashProxyRenderer 是可选接口：支持 Clash 订阅输出的协议实现它。
type ClashProxyRenderer interface {
	ClashProxy(cfg model.Outbound, user ProxyUser) (map[string]any, error)
}

// ClashProxyFor 返回某出站视图在 Clash 订阅里的 proxies 条目；
// 协议未实现 Clash 映射（socks / http 等网关协议本就没有订阅）时返回 ErrUnsupported。
func ClashProxyFor(cfg model.Outbound, user ProxyUser) (map[string]any, error) {
	r, ok := Get(cfg.Type)
	if !ok {
		return nil, ErrUnsupported
	}
	cp, ok := r.(ClashProxyRenderer)
	if !ok {
		return nil, ErrUnsupported
	}
	return cp.ClashProxy(cfg, user)
}

// clashBase 解析出站视图的通用部分（settings + server/port 校验 + 基础条目）。
func clashBase(cfg model.Outbound, typ string) (map[string]any, map[string]any, error) {
	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return nil, nil, err
	}
	server := str(settings, fServer)
	port := intVal(settings, fServerPort)
	if server == "" || port <= 0 {
		return nil, nil, fmt.Errorf("%s: clash 条目缺少 server/port", typ)
	}
	p := map[string]any{
		fName:   cfg.Name,
		fType:   typ,
		fServer: server,
		"port":  port,
	}
	return p, settings, nil
}

// clashTransport 把 sing-box 的 transport 视图映射为 Mihomo 的 network 与
// 对应 *-opts。返回 network 名与 opts 的键名/内容（无 opts 时后两项为空）。
func clashTransport(cfg model.Outbound) (string, string, map[string]any) {
	tm, err := transportMap(cfg.Transport)
	if err != nil || tm == nil {
		return "tcp", "", nil
	}
	switch str(tm, fType) {
	case "ws":
		opts := map[string]any{}
		if p := str(tm, "path"); p != "" {
			opts["path"] = p
		}
		if h, ok := tm["headers"].(map[string]any); ok && len(h) > 0 {
			opts["headers"] = h
		}
		return "ws", "ws-opts", opts
	case "httpupgrade":
		// Mihomo 的 httpupgrade 借道 ws-opts + v2ray-http-upgrade 标记。
		opts := map[string]any{"v2ray-http-upgrade": true}
		if p := str(tm, "path"); p != "" {
			opts["path"] = p
		}
		if h := str(tm, "host"); h != "" {
			opts["host"] = h
		}
		return "ws", "ws-opts", opts
	case "grpc":
		opts := map[string]any{}
		if sn := str(tm, "service_name"); sn != "" {
			opts["grpc-service-name"] = sn
		}
		return "grpc", "grpc-opts", opts
	case "http":
		opts := map[string]any{}
		switch host := tm["host"].(type) {
		case []any:
			if len(host) > 0 {
				opts["host"] = host
			}
		case string:
			if host != "" {
				opts["host"] = []string{host}
			}
		}
		if p := str(tm, "path"); p != "" {
			opts["path"] = p
		}
		return "h2", "h2-opts", opts
	default:
		return "tcp", "", nil
	}
}

// clashApplyTransport 把 clashTransport 的结果写入条目（tcp 直连不写 opts）。
func clashApplyTransport(p map[string]any, cfg model.Outbound) {
	network, key, opts := clashTransport(cfg)
	if network != "" && network != "tcp" {
		p[fNetwork] = network
	}
	if key != "" && len(opts) > 0 {
		p[key] = opts
	}
}

// clashALPN 提取 TLS 视图里的 alpn 列表（字符串数组形态）。
func clashALPN(cfg model.Outbound) []string {
	tls, err := tlsMap(cfg.TLS)
	if err != nil || tls == nil {
		return nil
	}
	list, ok := tls["alpn"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// clashFingerprint 提取 TLS 视图里的 uTLS 指纹（utls.fingerprint）。
func clashFingerprint(cfg model.Outbound) string {
	tls, err := tlsMap(cfg.TLS)
	if err != nil || tls == nil {
		return ""
	}
	if utls, ok := tls["utls"].(map[string]any); ok {
		return str(utls, "fingerprint")
	}
	return ""
}

// clashSkipVerify 自签兜底时订阅视图的 TLS 带 insecure 标记，
// Mihomo 对应 skip-cert-verify。
func clashSkipVerify(p map[string]any, cfg model.Outbound) {
	if insecureFromTLS(cfg) {
		p["skip-cert-verify"] = true
	}
}

// ---- vless ----

func (r *VLESSRenderer) ClashProxy(cfg model.Outbound, user ProxyUser) (map[string]any, error) {
	p, settings, err := clashBase(cfg, "vless")
	if err != nil {
		return nil, err
	}
	if user.UUID == "" {
		return nil, fmt.Errorf("vless: clash 条目缺少 uuid")
	}
	p[fUUID] = user.UUID
	p["udp"] = true
	if flow := str(settings, fFlow); flow != "" {
		p[fFlow] = flow
	}
	clashApplyTransport(p, cfg)
	tls, _ := tlsMap(cfg.TLS)
	switch {
	case realityEnabled(tls):
		p["tls"] = true
		if sni := str(tls, fServerName); sni != "" {
			p["servername"] = sni
		}
		if rm, ok := tls[fReality].(map[string]any); ok {
			opts := map[string]any{}
			if pk := str(rm, "public_key"); pk != "" {
				opts["public-key"] = pk
			}
			if sid := str(rm, "short_id"); sid != "" {
				opts["short-id"] = sid
			}
			if len(opts) > 0 {
				p["reality-opts"] = opts
			}
		}
		// Reality / vision 在 Mihomo 里需要 uTLS 指纹，缺省用 chrome。
		if fp := clashFingerprint(cfg); fp != "" {
			p["client-fingerprint"] = fp
		} else {
			p["client-fingerprint"] = "chrome"
		}
	case tlsEnabled(tls):
		p["tls"] = true
		if sni := str(tls, fServerName); sni != "" {
			p["servername"] = sni
		}
		clashSkipVerify(p, cfg)
		if fp := clashFingerprint(cfg); fp != "" {
			p["client-fingerprint"] = fp
		}
	}
	return p, nil
}

// ---- vmess ----

func (r *VMessRenderer) ClashProxy(cfg model.Outbound, user ProxyUser) (map[string]any, error) {
	p, settings, err := clashBase(cfg, "vmess")
	if err != nil {
		return nil, err
	}
	if user.UUID == "" {
		return nil, fmt.Errorf("vmess: clash 条目缺少 uuid")
	}
	p[fUUID] = user.UUID
	p["alterId"] = intVal(settings, "alter_id")
	p["cipher"] = "auto"
	p["udp"] = true
	clashApplyTransport(p, cfg)
	if tls, _ := tlsMap(cfg.TLS); tlsEnabled(tls) {
		p["tls"] = true
		if sni := str(tls, fServerName); sni != "" {
			p["servername"] = sni
		}
		clashSkipVerify(p, cfg)
	}
	return p, nil
}

// ---- trojan ----

func (r *TrojanRenderer) ClashProxy(cfg model.Outbound, user ProxyUser) (map[string]any, error) {
	p, settings, err := clashBase(cfg, "trojan")
	if err != nil {
		return nil, err
	}
	pw := user.Password
	if pw == "" {
		pw = str(settings, fPassword)
	}
	if pw == "" {
		return nil, fmt.Errorf("trojan: clash 条目缺少密码")
	}
	p[fPassword] = pw
	p["udp"] = true
	if sni := sniFromTLS(cfg); sni != "" {
		p["sni"] = sni
	}
	clashSkipVerify(p, cfg)
	if alpn := clashALPN(cfg); len(alpn) > 0 {
		p["alpn"] = alpn
	}
	clashApplyTransport(p, cfg)
	return p, nil
}

// ---- shadowsocks ----

func (r *ShadowsocksRenderer) ClashProxy(cfg model.Outbound, user ProxyUser) (map[string]any, error) {
	p, settings, err := clashBase(cfg, "ss")
	if err != nil {
		return nil, err
	}
	method := str(settings, fMethod)
	if method == "" {
		return nil, fmt.Errorf("shadowsocks: clash 条目缺少 method")
	}
	// 密码解析与 SubscriptionURI 完全同源：优先代理用户密码，
	// 2022 系列拼「服务端密钥:用户密钥」组合（两侧同源推导）。
	pw := user.Password
	if pw == "" {
		pw = str(settings, fPassword)
	}
	if _, is2022 := SS2022KeyLen(method); is2022 && user.Password != "" {
		pw = SS2022ServerKey(cfg.ID.String(), method, settings) + ":" + SS2022UserKey(method, user.Password)
	}
	if pw == "" {
		return nil, fmt.Errorf("shadowsocks: clash 条目缺少密码")
	}
	p["cipher"] = method
	p[fPassword] = pw
	p["udp"] = true
	return p, nil
}

// ---- hysteria2 ----

func (r *Hysteria2Renderer) ClashProxy(cfg model.Outbound, user ProxyUser) (map[string]any, error) {
	p, settings, err := clashBase(cfg, "hysteria2")
	if err != nil {
		return nil, err
	}
	pw := user.Password
	if pw == "" {
		pw = str(settings, fPassword)
	}
	if pw == "" {
		return nil, fmt.Errorf("hysteria2: clash 条目缺少密码")
	}
	p[fPassword] = pw
	if sni := sniFromTLS(cfg); sni != "" {
		p["sni"] = sni
	}
	clashSkipVerify(p, cfg)
	if obfs, ok := settings["obfs"].(map[string]any); ok {
		if t := str(obfs, "type"); t != "" {
			p["obfs"] = t
		}
		if op := str(obfs, fPassword); op != "" {
			p["obfs-password"] = op
		}
	}
	// Mihomo 的带宽字段是「数值 + 单位」字符串（如 100 Mbps）。
	if v := intVal(settings, "up_mbps"); v > 0 {
		p["up"] = fmt.Sprintf("%d Mbps", v)
	}
	if v := intVal(settings, "down_mbps"); v > 0 {
		p["down"] = fmt.Sprintf("%d Mbps", v)
	}
	if alpn := clashALPN(cfg); len(alpn) > 0 {
		p["alpn"] = alpn
	}
	return p, nil
}

// ---- tuic ----

func (r *TUICRenderer) ClashProxy(cfg model.Outbound, user ProxyUser) (map[string]any, error) {
	p, settings, err := clashBase(cfg, "tuic")
	if err != nil {
		return nil, err
	}
	if user.UUID == "" {
		return nil, fmt.Errorf("tuic: clash 条目缺少 uuid")
	}
	// 密码来源与 SubscriptionURI 一致：settings 优先、代理用户兜底。
	pw := str(settings, fPassword)
	if pw == "" {
		pw = user.Password
	}
	if pw == "" {
		return nil, fmt.Errorf("tuic: clash 条目缺少密码")
	}
	p[fUUID] = user.UUID
	p[fPassword] = pw
	if sni := sniFromTLS(cfg); sni != "" {
		p["sni"] = sni
	}
	clashSkipVerify(p, cfg)
	// ALPN 与订阅链接同规则：TLS 没写时按 TUIC 惯例补 h3，
	// 否则入站要求 h3 时客户端协商必然失败。
	if alpn := clashALPN(cfg); len(alpn) > 0 {
		p["alpn"] = alpn
	} else {
		p["alpn"] = []string{"h3"}
	}
	if cc := str(settings, "congestion_control"); cc != "" {
		p["congestion-controller"] = cc
	}
	if mode := str(settings, "udp_relay_mode"); mode != "" {
		p["udp-relay-mode"] = mode
	}
	return p, nil
}

// ---- anytls ----

func (r *AnyTLSRenderer) ClashProxy(cfg model.Outbound, user ProxyUser) (map[string]any, error) {
	p, settings, err := clashBase(cfg, "anytls")
	if err != nil {
		return nil, err
	}
	pw := user.Password
	if pw == "" {
		pw = str(settings, fPassword)
	}
	if pw == "" {
		return nil, fmt.Errorf("anytls: clash 条目缺少密码")
	}
	// 与 anytls 的统一约定一致：密码字段用 base64 编码形态
	//（入站渲染 / 分享链接 / Mihomo 三处同值，见 anytls.go 注释）。
	p[fPassword] = base64Encode(pw)
	p["udp"] = true
	if sni := sniFromTLS(cfg); sni != "" {
		p["sni"] = sni
	}
	clashSkipVerify(p, cfg)
	if alpn := clashALPN(cfg); len(alpn) > 0 {
		p["alpn"] = alpn
	}
	// 会话池：sing-box 侧是 duration 字符串，Mihomo 侧是秒数整数。
	for _, kv := range [][2]string{
		{"idle_session_check_interval", "idle-session-check-interval"},
		{"idle_session_timeout", "idle-session-timeout"},
	} {
		if s := str(settings, kv[0]); s != "" {
			if d, err := time.ParseDuration(s); err == nil && d > 0 {
				p[kv[1]] = int(d.Seconds())
			}
		}
	}
	if _, ok := settings["min_idle_session"]; ok {
		p["min-idle-session"] = intVal(settings, "min_idle_session")
	}
	return p, nil
}
