package renderer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ParsedLink 是把一条分享链接（vless://、ss:// 等）解析出的出站草稿：
// Settings/TLS/Transport 三段 JSON 与出站模型同构，可直接喂给
// OutboundService 落库——用于把别的机场/面板的节点链接导入为落地出站。
type ParsedLink struct {
	Protocol  string          `json:"protocol"`
	Name      string          `json:"name"`
	Settings  json.RawMessage `json:"settings"`
	TLS       json.RawMessage `json:"tls,omitempty"`
	Transport json.RawMessage `json:"transport,omitempty"`
}

// ParseLink 解析主流客户端的分享链接（vless/vmess/trojan/ss/hysteria2/
// tuic/anytls/socks/http），是各 renderer SubscriptionURI 的逆操作，
// 同时兼容 v2rayN 等客户端导出的常见变体（ss 旧式全编码、socks 账密
// base64、anytls 明文密码等）。
func ParseLink(raw string) (*ParsedLink, error) {
	raw = strings.TrimSpace(raw)
	scheme, _, found := strings.Cut(raw, "://")
	if !found || scheme == "" {
		return nil, fmt.Errorf("链接格式不正确（缺少协议头）")
	}
	scheme = strings.ToLower(scheme)
	switch scheme {
	case "ss":
		return parseSS(raw)
	case "vmess":
		return parseVMess(raw)
	case "socks":
		return parseSocks(raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("链接解析失败: %v", err)
	}
	host := u.Hostname()
	port, perr := strconv.Atoi(u.Port())
	if host == "" || perr != nil || port <= 0 {
		return nil, fmt.Errorf("链接缺少服务器地址或端口")
	}
	q := u.Query()
	name := strings.TrimSpace(u.Fragment)
	p := &linkParts{host: host, port: port, q: q}
	switch scheme {
	case "vless":
		err = p.vless(u)
	case "trojan":
		err = p.trojan(u)
	case "hysteria2", "hy2":
		scheme = "hysteria2"
		err = p.hysteria2(u)
	case "tuic":
		err = p.tuic(u)
	case "anytls":
		err = p.anytls(u)
	case "http", "https":
		err = p.httpProxy(u, scheme == "https")
		if scheme == "https" {
			scheme = "http" // sing-box 只有一个 http 出站类型，HTTPS = http + TLS
		}
	default:
		return nil, fmt.Errorf("暂不支持导入 %s 链接", scheme)
	}
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = scheme + "-" + host
	}
	return &ParsedLink{
		Protocol:  scheme,
		Name:      name,
		Settings:  rawJSON(p.settings),
		TLS:       rawJSON(p.tls),
		Transport: rawJSON(p.transport),
	}, nil
}

// linkParts 累积解析结果（三段 map），用索引赋值逐项填，避免遗漏字段。
type linkParts struct {
	host      string
	port      int
	q         url.Values
	settings  map[string]any
	tls       map[string]any
	transport map[string]any
}

func rawJSON(m map[string]any) json.RawMessage {
	if len(m) == 0 {
		return nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil
	}
	return b
}

func (p *linkParts) serverSettings() map[string]any {
	if p.settings == nil {
		p.settings = map[string]any{}
	}
	p.settings["server"] = p.host
	p.settings["server_port"] = p.port
	return p.settings
}

func (p *linkParts) ensureTLS() map[string]any {
	if p.tls == nil {
		p.tls = map[string]any{}
	}
	p.tls["enabled"] = true
	return p.tls
}

// applyCommonTLS 把 sni/insecure/alpn 等通用查询参数落到 TLS 段。
func (p *linkParts) applyCommonTLS(insecureKeys ...string) {
	sni := p.q.Get("sni")
	if sni == "" {
		sni = p.q.Get("peer")
	}
	if sni != "" {
		p.ensureTLS()["server_name"] = sni
	}
	for _, k := range insecureKeys {
		if v := p.q.Get(k); v == "1" || v == "true" {
			p.ensureTLS()["insecure"] = true
		}
	}
	if alpn := p.q.Get("alpn"); alpn != "" {
		parts := []any{}
		for _, s := range strings.Split(alpn, ",") {
			if s = strings.TrimSpace(s); s != "" {
				parts = append(parts, s)
			}
		}
		if len(parts) > 0 {
			p.ensureTLS()["alpn"] = parts
		}
	}
}

// applyTransport 把 type/path/host/serviceName 等参数落到传输段（vless/
// trojan/vmess 共用的 Xray 系参数约定）。tcp 时不生成传输段。
func (p *linkParts) applyTransport() {
	ttype := strings.ToLower(p.q.Get("type"))
	switch ttype {
	case "", "tcp", "none":
		return
	case "ws", "websocket":
		tr := map[string]any{}
		tr["type"] = "ws"
		if path := p.q.Get("path"); path != "" {
			tr["path"] = path
		}
		if host := p.q.Get("host"); host != "" {
			h := map[string]any{}
			h["Host"] = host
			tr["headers"] = h
		}
		p.transport = tr
	case "grpc":
		tr := map[string]any{}
		tr["type"] = "grpc"
		if sn := p.q.Get("serviceName"); sn != "" {
			tr["service_name"] = sn
		}
		p.transport = tr
	case "http", "h2":
		tr := map[string]any{}
		tr["type"] = "http"
		if path := p.q.Get("path"); path != "" {
			tr["path"] = path
		}
		if host := p.q.Get("host"); host != "" {
			tr["host"] = []any{host}
		}
		p.transport = tr
	}
}

func (p *linkParts) vless(u *url.URL) error {
	uuid := ""
	if u.User != nil {
		uuid = u.User.Username()
	}
	if uuid == "" {
		return fmt.Errorf("vless 链接缺少 UUID")
	}
	s := p.serverSettings()
	s["uuid"] = uuid
	if flow := p.q.Get("flow"); flow != "" {
		s["flow"] = flow
	}
	switch strings.ToLower(p.q.Get("security")) {
	case "reality":
		t := p.ensureTLS()
		if sni := p.q.Get("sni"); sni != "" {
			t["server_name"] = sni
		}
		reality := map[string]any{}
		reality["enabled"] = true
		if pbk := p.q.Get("pbk"); pbk != "" {
			reality["public_key"] = pbk
		}
		if sid := p.q.Get("sid"); sid != "" {
			reality["short_id"] = sid
		}
		t["reality"] = reality
		fp := p.q.Get("fp")
		if fp == "" {
			fp = "chrome"
		}
		utls := map[string]any{}
		utls["enabled"] = true
		utls["fingerprint"] = fp
		t["utls"] = utls
	case "tls":
		p.applyCommonTLS("insecure", "allowInsecure")
		p.ensureTLS()
		if fp := p.q.Get("fp"); fp != "" {
			utls := map[string]any{}
			utls["enabled"] = true
			utls["fingerprint"] = fp
			p.tls["utls"] = utls
		}
	case "", "none":
		// 明文，无 TLS 段。
	default:
		p.ensureTLS()
	}
	p.applyTransport()
	return nil
}

func (p *linkParts) trojan(u *url.URL) error {
	pw := ""
	if u.User != nil {
		pw = u.User.Username()
		if v, ok := u.User.Password(); ok && pw == "" {
			pw = v
		}
	}
	if pw == "" {
		return fmt.Errorf("trojan 链接缺少密码")
	}
	s := p.serverSettings()
	s["password"] = pw
	// trojan 恒走 TLS（本面板校验亦然）。
	p.applyCommonTLS("insecure", "allowInsecure")
	p.ensureTLS()
	p.applyTransport()
	return nil
}

func (p *linkParts) hysteria2(u *url.URL) error {
	pw := ""
	if u.User != nil {
		pw = u.User.Username()
	}
	if pw == "" {
		return fmt.Errorf("hysteria2 链接缺少密码")
	}
	s := p.serverSettings()
	s["password"] = pw
	if obfs := p.q.Get("obfs"); obfs != "" {
		o := map[string]any{}
		o["type"] = obfs
		if op := p.q.Get("obfs-password"); op != "" {
			o["password"] = op
		}
		s["obfs"] = o
	}
	for _, kv := range [][2]string{{"upmbps", "up_mbps"}, {"downmbps", "down_mbps"}, {"up", "up_mbps"}, {"down", "down_mbps"}} {
		if v := p.q.Get(kv[0]); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				s[kv[1]] = n
			}
		}
	}
	p.applyCommonTLS("insecure")
	t := p.ensureTLS()
	if t["alpn"] == nil {
		t["alpn"] = []any{"h3"}
	}
	return nil
}

func (p *linkParts) tuic(u *url.URL) error {
	uuid, pw := "", ""
	if u.User != nil {
		uuid = u.User.Username()
		pw, _ = u.User.Password()
	}
	if uuid == "" || pw == "" {
		return fmt.Errorf("tuic 链接缺少 UUID 或密码")
	}
	s := p.serverSettings()
	s["uuid"] = uuid
	s["password"] = pw
	if cc := p.q.Get("congestion_control"); cc != "" {
		s["congestion_control"] = cc
	}
	if mode := p.q.Get("udp_relay_mode"); mode != "" {
		s["udp_relay_mode"] = mode
	}
	p.applyCommonTLS("allow_insecure", "insecure")
	t := p.ensureTLS()
	if t["alpn"] == nil {
		t["alpn"] = []any{"h3"} // TUIC 客户端不带 ALPN 必然握手失败，缺省补 h3
	}
	return nil
}

func (p *linkParts) anytls(u *url.URL) error {
	raw := ""
	if u.User != nil {
		raw = u.User.Username()
	}
	if raw == "" {
		return fmt.Errorf("anytls 链接缺少密码")
	}
	s := p.serverSettings()
	s["password"] = decodeAnyTLSPassword(raw)
	p.applyCommonTLS("insecure")
	p.ensureTLS()
	return nil
}

// decodeAnyTLSPassword 区分 anytls 密码的两种形态：本面板生成的链接把
// 密码 base64 后放在 userinfo，而 v2rayN 等客户端用明文。能严格往返
// base64 且解码结果可打印时按 base64 处理，否则按明文。
func decodeAnyTLSPassword(raw string) string {
	if dec, err := base64.StdEncoding.DecodeString(raw); err == nil && len(dec) > 0 &&
		base64.StdEncoding.EncodeToString(dec) == raw && isPrintable(string(dec)) {
		return string(dec)
	}
	if dec, err := base64.RawStdEncoding.DecodeString(raw); err == nil && len(dec) > 0 &&
		base64.RawStdEncoding.EncodeToString(dec) == raw && isPrintable(string(dec)) {
		return string(dec)
	}
	return raw
}

// isPrintable 判断解码结果是否为可打印 ASCII（密码的常见字符集）。
// 必须先验 UTF-8 有效性：非法字节被 range 解成 U+FFFD 会骗过 IsPrint，
// 曾把明文密码 plainpw 误判成 base64 解码结果。
func isPrintable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func (p *linkParts) httpProxy(u *url.URL, secure bool) error {
	s := p.serverSettings()
	if u.User != nil {
		if name := u.User.Username(); name != "" {
			s["username"] = name
		}
		if pw, ok := u.User.Password(); ok && pw != "" {
			s["password"] = pw
		}
	}
	if secure {
		t := p.ensureTLS()
		sni := p.q.Get("sni")
		if sni == "" {
			sni = p.host
		}
		t["server_name"] = sni
		if v := p.q.Get("insecure"); v == "1" || v == "true" {
			t["insecure"] = true
		}
	}
	return nil
}

// parseVMess 解析 vmess://<base64 JSON> 形态。
func parseVMess(raw string) (*ParsedLink, error) {
	body := strings.TrimSpace(raw[len("vmess://"):])
	dec, err := b64DecodeLoose(body)
	if err != nil {
		return nil, fmt.Errorf("vmess 链接解码失败: %v", err)
	}
	var j map[string]any
	if err := json.Unmarshal(dec, &j); err != nil {
		return nil, fmt.Errorf("vmess 链接 JSON 无效: %v", err)
	}
	host := str(j, "add")
	port := 0
	switch v := j["port"].(type) {
	case float64:
		port = int(v)
	case string:
		port, _ = strconv.Atoi(v)
	}
	if host == "" || port <= 0 {
		return nil, fmt.Errorf("vmess 链接缺少服务器地址或端口")
	}
	p := &linkParts{host: host, port: port, q: url.Values{}}
	s := p.serverSettings()
	s["uuid"] = str(j, "id")
	if aid := str(j, "aid"); aid != "" {
		if n, err := strconv.Atoi(aid); err == nil {
			s["alter_id"] = n
		}
	}
	// 传输：net/path/host 与 Xray 系参数同名，借道 applyTransport。
	p.q.Set("type", str(j, "net"))
	if v := str(j, "path"); v != "" {
		p.q.Set("path", v)
		p.q.Set("serviceName", v) // grpc 时 path 即服务名（v2rayN 约定）
	}
	if v := str(j, "host"); v != "" {
		p.q.Set("host", v)
	}
	p.applyTransport()
	if str(j, "tls") == "tls" {
		t := p.ensureTLS()
		sni := str(j, "sni")
		if sni == "" {
			sni = str(j, "host")
		}
		if sni != "" {
			t["server_name"] = sni
		}
	}
	name := strings.TrimSpace(str(j, "ps"))
	if name == "" {
		name = "vmess-" + host
	}
	return &ParsedLink{
		Protocol:  "vmess",
		Name:      name,
		Settings:  rawJSON(p.settings),
		TLS:       rawJSON(p.tls),
		Transport: rawJSON(p.transport),
	}, nil
}

// parseSS 解析 ss:// 链接：SIP002（userinfo 为 base64(method:password)
// 或明文 method:password）与旧式全编码（整体 base64）两种形态。
func parseSS(raw string) (*ParsedLink, error) {
	body := strings.TrimSpace(raw[len("ss://"):])
	name := ""
	if i := strings.LastIndex(body, "#"); i >= 0 {
		if n, err := url.PathUnescape(body[i+1:]); err == nil {
			name = strings.TrimSpace(n)
		}
		body = body[:i]
	}
	if i := strings.Index(body, "?"); i >= 0 {
		body = body[:i] // plugin 等参数暂不映射（渲染器未支持 ss 插件出站）
	}
	var method, pw, hostport string
	if strings.Contains(body, "@") {
		userinfo, hp, _ := strings.Cut(body, "@")
		hostport = hp
		if strings.Contains(userinfo, ":") {
			m, v, _ := strings.Cut(userinfo, ":")
			method, pw = m, v
			if dec, err := url.PathUnescape(pw); err == nil {
				pw = dec
			}
		} else if dec, err := b64DecodeLoose(userinfo); err == nil {
			m, v, ok := strings.Cut(string(dec), ":")
			if !ok {
				return nil, fmt.Errorf("ss 链接凭据格式不正确")
			}
			method, pw = m, v
		} else {
			return nil, fmt.Errorf("ss 链接凭据解码失败")
		}
	} else {
		dec, err := b64DecodeLoose(body)
		if err != nil {
			return nil, fmt.Errorf("ss 链接解码失败: %v", err)
		}
		cred, hp, ok := strings.Cut(string(dec), "@")
		if !ok {
			return nil, fmt.Errorf("ss 链接格式不正确")
		}
		hostport = hp
		m, v, ok := strings.Cut(cred, ":")
		if !ok {
			return nil, fmt.Errorf("ss 链接凭据格式不正确")
		}
		method, pw = m, v
	}
	host, portStr, err := splitHostPort(hostport)
	if err != nil || host == "" {
		return nil, fmt.Errorf("ss 链接缺少服务器地址或端口")
	}
	port, _ := strconv.Atoi(portStr)
	s := map[string]any{}
	s["server"] = host
	s["server_port"] = port
	s["method"] = method
	s["password"] = pw
	if name == "" {
		name = "shadowsocks-" + host
	}
	return &ParsedLink{Protocol: "shadowsocks", Name: name, Settings: rawJSON(s)}, nil
}

// parseSocks 解析 socks:// 链接：账密明文或 base64 两种 userinfo 形态。
func parseSocks(raw string) (*ParsedLink, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("链接解析失败: %v", err)
	}
	host := u.Hostname()
	port, perr := strconv.Atoi(u.Port())
	if host == "" || perr != nil || port <= 0 {
		return nil, fmt.Errorf("socks 链接缺少服务器地址或端口")
	}
	s := map[string]any{}
	s["server"] = host
	s["server_port"] = port
	s["version"] = "5"
	if u.User != nil {
		user := u.User.Username()
		pw, hasPw := u.User.Password()
		switch {
		case hasPw:
			s["username"] = user
			s["password"] = pw
		case strings.Contains(user, ":"):
			name, v, _ := strings.Cut(user, ":")
			s["username"] = name
			s["password"] = v
		case user != "":
			if dec, err := b64DecodeLoose(user); err == nil && strings.Contains(string(dec), ":") {
				name, v, _ := strings.Cut(string(dec), ":")
				s["username"] = name
				s["password"] = v
			} else {
				s["username"] = user
			}
		}
	}
	name := strings.TrimSpace(u.Fragment)
	if name == "" {
		name = "socks-" + host
	}
	return &ParsedLink{Protocol: "socks", Name: name, Settings: rawJSON(s)}, nil
}

func splitHostPort(s string) (string, string, error) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", "", fmt.Errorf("缺少端口")
	}
	return strings.Trim(s[:i], "[]"), s[i+1:], nil
}

// b64DecodeLoose 依次尝试标准/URL 安全/无填充的 base64 解码。
func b64DecodeLoose(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("base64 解码失败")
}
