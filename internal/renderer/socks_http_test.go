package renderer

import (
	"encoding/json"
	"testing"

	"github.com/sle58083/cx-box/internal/model"
)

func TestSocksOutboundRender(t *testing.T) {
	r := &SocksRenderer{}
	cfg := model.Outbound{
		Name:     "proxy-ip",
		Type:     "socks",
		Settings: json.RawMessage(`{"server":"1.2.3.4","server_port":1080,"version":"5","username":"u1","password":"p1","udp_over_tcp":true}`),
	}
	out, err := r.RenderOutbound(&RenderContext{}, cfg)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if out["type"] != "socks" || out["tag"] != "proxy-ip" {
		t.Fatalf("common fields wrong: %v", out)
	}
	if out["server"] != "1.2.3.4" || out["server_port"] != float64(1080) {
		t.Fatalf("server fields wrong: %v", out)
	}
	if out["version"] != "5" || out["username"] != "u1" || out["password"] != "p1" {
		t.Fatalf("auth fields wrong: %v", out)
	}
	if out["udp_over_tcp"] != true {
		t.Fatalf("udp_over_tcp not passed: %v", out)
	}
}

func TestSocksOutboundRenderNoAuth(t *testing.T) {
	r := &SocksRenderer{}
	cfg := model.Outbound{
		Name:     "proxy-ip",
		Type:     "socks",
		Settings: json.RawMessage(`{"server":"1.2.3.4","server_port":1080}`),
	}
	out, err := r.RenderOutbound(&RenderContext{}, cfg)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	// 无账号密码（IP 白名单授权）时不得输出空的 username/password/version。
	for _, k := range []string{"username", "password", "version"} {
		if _, ok := out[k]; ok {
			t.Fatalf("key %s should be omitted: %v", k, out)
		}
	}
}

func TestSocksOutboundValidation(t *testing.T) {
	r := &SocksRenderer{}
	mk := func(s string) model.Outbound {
		return model.Outbound{Name: "x", Type: "socks", Settings: json.RawMessage(s)}
	}
	if err := r.ValidateOutbound(mk(`{"server_port":1080}`)); err == nil {
		t.Fatal("missing server should fail")
	}
	if err := r.ValidateOutbound(mk(`{"server":"1.2.3.4","server_port":0}`)); err == nil {
		t.Fatal("port 0 should fail")
	}
	if err := r.ValidateOutbound(mk(`{"server":"1.2.3.4","server_port":1080,"version":"6"}`)); err == nil {
		t.Fatal("version 6 should fail")
	}
	if err := r.ValidateOutbound(mk(`{"server":"1.2.3.4","server_port":1080,"password":"p"}`)); err == nil {
		t.Fatal("password without username should fail")
	}
	if err := r.ValidateOutbound(mk(`{"server":"1.2.3.4","server_port":1080,"version":"4a","username":"u","password":"p"}`)); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestSocksInboundRender(t *testing.T) {
	r := &SocksRenderer{}
	cfg := model.Inbound{
		Name: "lan-socks", Type: "socks", Port: 1080,
		Settings: json.RawMessage(`{"users":[{"username":"u1","password":"p1"},{"username":"u2","password":"p2"}]}`),
	}
	out, err := r.RenderInbound(&RenderContext{}, cfg, nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if out["type"] != "socks" || out["listen_port"] != 1080 {
		t.Fatalf("common fields wrong: %v", out)
	}
	us, ok := out["users"].([]map[string]any)
	if !ok || len(us) != 2 || us[0]["username"] != "u1" || us[1]["password"] != "p2" {
		t.Fatalf("users not passed: %v", out["users"])
	}
	// 无账号（内网无认证）时不输出 users 键。
	cfg.Settings = json.RawMessage(`{}`)
	out, err = r.RenderInbound(&RenderContext{}, cfg, nil)
	if err != nil {
		t.Fatalf("render noauth: %v", err)
	}
	if _, ok := out["users"]; ok {
		t.Fatalf("users should be omitted when empty: %v", out)
	}
}

func TestSocksInboundValidation(t *testing.T) {
	r := &SocksRenderer{}
	mk := func(port int, s string) model.Inbound {
		return model.Inbound{Name: "x", Type: "socks", Port: port, Settings: json.RawMessage(s)}
	}
	if err := r.ValidateInbound(mk(0, `{}`)); err == nil {
		t.Fatal("port 0 should fail")
	}
	if err := r.ValidateInbound(mk(1080, `{"users":[{"username":"u1"}]}`)); err == nil {
		t.Fatal("user without password should fail")
	}
	if err := r.ValidateInbound(mk(1080, `{"users":[{"password":"p1"}]}`)); err == nil {
		t.Fatal("user without username should fail")
	}
	if err := r.ValidateInbound(mk(1080, `{}`)); err != nil {
		t.Fatalf("no-auth inbound should pass: %v", err)
	}
	if err := r.ValidateInbound(mk(1080, `{"users":[{"username":"u1","password":"p1"}]}`)); err != nil {
		t.Fatalf("valid inbound rejected: %v", err)
	}
}

func TestHTTPOutboundRender(t *testing.T) {
	r := &HTTPRenderer{}
	cfg := model.Outbound{
		Name:     "proxy-ip",
		Type:     "http",
		Settings: json.RawMessage(`{"server":"5.6.7.8","server_port":8080,"username":"u1","password":"p1","path":"/proxy","headers":{"X-Test":"1"}}`),
		TLS:      json.RawMessage(`{"enabled":true,"server_name":"5.6.7.8"}`),
	}
	out, err := r.RenderOutbound(&RenderContext{}, cfg)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if out["type"] != "http" || out["server"] != "5.6.7.8" || out["server_port"] != float64(8080) {
		t.Fatalf("server fields wrong: %v", out)
	}
	if out["username"] != "u1" || out["password"] != "p1" || out["path"] != "/proxy" {
		t.Fatalf("auth/path fields wrong: %v", out)
	}
	if _, ok := out["headers"].(map[string]any); !ok {
		t.Fatalf("headers not passed: %v", out)
	}
	tlsMap, ok := out["tls"].(map[string]any)
	if !ok || tlsMap["enabled"] != true {
		t.Fatalf("tls not rendered: %v", out["tls"])
	}
}

func TestHTTPOutboundValidation(t *testing.T) {
	r := &HTTPRenderer{}
	mk := func(s string) model.Outbound {
		return model.Outbound{Name: "x", Type: "http", Settings: json.RawMessage(s)}
	}
	if err := r.ValidateOutbound(mk(`{"server_port":8080}`)); err == nil {
		t.Fatal("missing server should fail")
	}
	if err := r.ValidateOutbound(mk(`{"server":"5.6.7.8","server_port":8080,"password":"p"}`)); err == nil {
		t.Fatal("password without username should fail")
	}
	if err := r.ValidateOutbound(mk(`{"server":"5.6.7.8","server_port":8080,"username":"u","password":"p"}`)); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	// HTTPS 代理的普通 TLS 允许，Reality 不允许。
	reality := mk(`{"server":"5.6.7.8","server_port":8443}`)
	reality.TLS = json.RawMessage(`{"enabled":true,"reality":{"enabled":true,"public_key":"x"}}`)
	if err := r.ValidateOutbound(reality); err == nil {
		t.Fatal("reality tls should fail for http outbound")
	}
}

func TestHTTPInboundRender(t *testing.T) {
	r := &HTTPRenderer{}
	cfg := model.Inbound{
		Name:     "lan-http",
		Type:     "http",
		Port:     8080,
		Settings: json.RawMessage(`{"users":[{"username":"u1","password":"p1"}]}`),
		TLS:      json.RawMessage(`{"enabled":true,"server_name":"proxy.example.com"}`),
	}
	out, err := r.RenderInbound(&RenderContext{}, cfg, nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if out["type"] != "http" || out["listen_port"] != 8080 {
		t.Fatalf("common fields wrong: %v", out)
	}
	us, ok := out["users"].([]map[string]any)
	if !ok || len(us) != 1 || us[0]["username"] != "u1" {
		t.Fatalf("users not passed: %v", out["users"])
	}
	tlsMap, ok := out["tls"].(map[string]any)
	if !ok || tlsMap["enabled"] != true {
		t.Fatalf("tls not rendered (HTTPS inbound): %v", out["tls"])
	}
}

func TestHTTPInboundValidation(t *testing.T) {
	r := &HTTPRenderer{}
	mk := func(port int, s string) model.Inbound {
		return model.Inbound{Name: "x", Type: "http", Port: port, Settings: json.RawMessage(s)}
	}
	if err := r.ValidateInbound(mk(0, `{}`)); err == nil {
		t.Fatal("port 0 should fail")
	}
	if err := r.ValidateInbound(mk(8080, `{"users":[{"username":"u1"}]}`)); err == nil {
		t.Fatal("user without password should fail")
	}
	if err := r.ValidateInbound(mk(8080, `{"users":[{"username":"u1","password":"p1"}]}`)); err != nil {
		t.Fatalf("valid inbound rejected: %v", err)
	}
	// 入站普通 TLS（HTTPS 代理）允许，Reality 不允许。
	https := mk(8443, `{}`)
	https.TLS = json.RawMessage(`{"enabled":true}`)
	if err := r.ValidateInbound(https); err != nil {
		t.Fatalf("plain TLS inbound should pass: %v", err)
	}
	https.TLS = json.RawMessage(`{"enabled":true,"reality":{"enabled":true,"private_key":"x"}}`)
	if err := r.ValidateInbound(https); err == nil {
		t.Fatal("reality tls should fail for http inbound")
	}
}
