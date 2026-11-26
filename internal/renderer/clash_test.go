package renderer

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/sle58083/cx-box/internal/model"
)

func clashOB(typ, settings, tls, transport string) model.Outbound {
	ob := model.Outbound{Name: "node-" + typ, Type: typ}
	ob.ID = uuid.New()
	if settings != "" {
		ob.Settings = json.RawMessage(settings)
	}
	if tls != "" {
		ob.TLS = json.RawMessage(tls)
	}
	if transport != "" {
		ob.Transport = json.RawMessage(transport)
	}
	return ob
}

func TestClashVLESSReality(t *testing.T) {
	ob := clashOB("vless",
		`{"server":"203.0.113.7","server_port":443,"flow":"xtls-rprx-vision"}`,
		`{"enabled":true,"server_name":"www.microsoft.com","reality":{"enabled":true,"public_key":"PUBKEY","short_id":"ab12"}}`,
		"")
	p, err := ClashProxyFor(ob, ProxyUser{UUID: "11111111-2222-3333-4444-555555555555"})
	if err != nil {
		t.Fatalf("clash vless: %v", err)
	}
	if p["type"] != "vless" || p["server"] != "203.0.113.7" || p["port"] != 443 {
		t.Fatalf("base fields wrong: %v", p)
	}
	if p["tls"] != true || p["servername"] != "www.microsoft.com" || p["flow"] != "xtls-rprx-vision" {
		t.Fatalf("tls/flow wrong: %v", p)
	}
	ro, ok := p["reality-opts"].(map[string]any)
	if !ok || ro["public-key"] != "PUBKEY" || ro["short-id"] != "ab12" {
		t.Fatalf("reality-opts wrong: %v", p["reality-opts"])
	}
	if p["client-fingerprint"] != "chrome" {
		t.Fatalf("client-fingerprint = %v, want chrome", p["client-fingerprint"])
	}
}

func TestClashVLESSWSInsecure(t *testing.T) {
	ob := clashOB("vless",
		`{"server":"example.com","server_port":8443}`,
		`{"enabled":true,"server_name":"example.com","insecure":true}`,
		`{"type":"ws","path":"/ws","headers":{"Host":"cdn.example.com"}}`)
	p, err := ClashProxyFor(ob, ProxyUser{UUID: "11111111-2222-3333-4444-555555555555"})
	if err != nil {
		t.Fatalf("clash vless ws: %v", err)
	}
	if p["network"] != "ws" {
		t.Fatalf("network = %v", p["network"])
	}
	wo, ok := p["ws-opts"].(map[string]any)
	if !ok || wo["path"] != "/ws" {
		t.Fatalf("ws-opts wrong: %v", p["ws-opts"])
	}
	if p["skip-cert-verify"] != true {
		t.Fatalf("skip-cert-verify missing: %v", p)
	}
}

func TestClashVMessWS(t *testing.T) {
	ob := clashOB("vmess",
		`{"server":"example.com","server_port":8443,"alter_id":0}`,
		"",
		`{"type":"ws","path":"/vmess","headers":{"Host":""}}`)
	p, err := ClashProxyFor(ob, ProxyUser{UUID: "11111111-2222-3333-4444-555555555555"})
	if err != nil {
		t.Fatalf("clash vmess: %v", err)
	}
	if p["cipher"] != "auto" || p["alterId"] != 0 || p["network"] != "ws" {
		t.Fatalf("vmess fields wrong: %v", p)
	}
	if _, hasTLS := p["tls"]; hasTLS {
		t.Fatalf("vmess without tls should not set tls: %v", p)
	}
}

func TestClashTrojan(t *testing.T) {
	ob := clashOB("trojan",
		`{"server":"example.com","server_port":4443}`,
		`{"enabled":true,"server_name":"tr.example.com","alpn":["h2","http/1.1"]}`,
		"")
	p, err := ClashProxyFor(ob, ProxyUser{Password: "userpw"})
	if err != nil {
		t.Fatalf("clash trojan: %v", err)
	}
	if p[fPassword] != "userpw" || p["sni"] != "tr.example.com" {
		t.Fatalf("trojan fields wrong: %v", p)
	}
	if alpn, ok := p["alpn"].([]string); !ok || len(alpn) != 2 {
		t.Fatalf("trojan alpn wrong: %v", p["alpn"])
	}
}

func TestClashSSClassicAnd2022(t *testing.T) {
	ob := clashOB("shadowsocks",
		`{"server":"example.com","server_port":8388,"method":"aes-128-gcm"}`,
		"", "")
	p, err := ClashProxyFor(ob, ProxyUser{Password: "userpw"})
	if err != nil {
		t.Fatalf("clash ss: %v", err)
	}
	if p["type"] != "ss" || p["cipher"] != "aes-128-gcm" || p[fPassword] != "userpw" {
		t.Fatalf("ss fields wrong: %v", p)
	}

	ob2 := clashOB("shadowsocks",
		`{"server":"example.com","server_port":8389,"method":"2022-blake3-aes-128-gcm"}`,
		"", "")
	p2, err := ClashProxyFor(ob2, ProxyUser{Password: "userpw"})
	if err != nil {
		t.Fatalf("clash ss2022: %v", err)
	}
	settings, _ := parseMap(ob2.Settings)
	want := SS2022ServerKey(ob2.ID.String(), "2022-blake3-aes-128-gcm", settings) +
		":" + SS2022UserKey("2022-blake3-aes-128-gcm", "userpw")
	if p2[fPassword] != want {
		t.Fatalf("ss2022 combined = %v, want %v", p2[fPassword], want)
	}
}

func TestClashHysteria2(t *testing.T) {
	ob := clashOB("hysteria2",
		`{"server":"example.com","server_port":36712,"up_mbps":100,"down_mbps":50,"obfs":{"type":"salamander","password":"obfspw"}}`,
		`{"enabled":true,"server_name":"hy.example.com","insecure":true,"alpn":["h3"]}`,
		"")
	p, err := ClashProxyFor(ob, ProxyUser{Password: "userpw"})
	if err != nil {
		t.Fatalf("clash hy2: %v", err)
	}
	if p[fPassword] != "userpw" || p["sni"] != "hy.example.com" || p["skip-cert-verify"] != true {
		t.Fatalf("hy2 fields wrong: %v", p)
	}
	if p["obfs"] != "salamander" || p["obfs-password"] != "obfspw" {
		t.Fatalf("hy2 obfs wrong: %v", p)
	}
	if p["up"] != "100 Mbps" || p["down"] != "50 Mbps" {
		t.Fatalf("hy2 bandwidth wrong: up=%v down=%v", p["up"], p["down"])
	}
}

func TestClashTUIC(t *testing.T) {
	ob := clashOB("tuic",
		`{"server":"example.com","server_port":10443,"congestion_control":"bbr"}`,
		`{"enabled":true,"server_name":"tu.example.com"}`,
		"")
	p, err := ClashProxyFor(ob, ProxyUser{UUID: "11111111-2222-3333-4444-555555555555", Password: "userpw"})
	if err != nil {
		t.Fatalf("clash tuic: %v", err)
	}
	if p[fUUID] == "" || p[fPassword] != "userpw" || p["congestion-controller"] != "bbr" {
		t.Fatalf("tuic fields wrong: %v", p)
	}
	if alpn, ok := p["alpn"].([]string); !ok || len(alpn) != 1 || alpn[0] != "h3" {
		t.Fatalf("tuic alpn should default to h3: %v", p["alpn"])
	}
}

func TestClashAnyTLS(t *testing.T) {
	ob := clashOB("anytls",
		`{"server":"example.com","server_port":9443,"idle_session_check_interval":"30s","idle_session_timeout":"60s","min_idle_session":2}`,
		`{"enabled":true,"server_name":"at.example.com","insecure":true}`,
		"")
	p, err := ClashProxyFor(ob, ProxyUser{Password: "plainpw"})
	if err != nil {
		t.Fatalf("clash anytls: %v", err)
	}
	wantPW := base64.StdEncoding.EncodeToString([]byte("plainpw"))
	if p[fPassword] != wantPW {
		t.Fatalf("anytls pw = %v, want base64 %v", p[fPassword], wantPW)
	}
	if p["idle-session-check-interval"] != 30 || p["idle-session-timeout"] != 60 || p["min-idle-session"] != 2 {
		t.Fatalf("anytls session pool wrong: %v", p)
	}
	if p["sni"] != "at.example.com" || p["skip-cert-verify"] != true {
		t.Fatalf("anytls tls wrong: %v", p)
	}
}

func TestClashUnsupported(t *testing.T) {
	ob := clashOB("socks", `{"server":"example.com","server_port":1080}`, "", "")
	_, err := ClashProxyFor(ob, ProxyUser{})
	if err == nil {
		t.Fatal("socks should not have a clash proxy entry")
	}
	if !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("err = %v", err)
	}
}
