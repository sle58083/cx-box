package renderer

import (
	"encoding/json"
	"errors"
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
	if _, err := r.RenderInbound(&RenderContext{}, model.Inbound{}, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("socks inbound should be unsupported, got %v", err)
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
	if _, err := r.RenderInbound(&RenderContext{}, model.Inbound{}, nil); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("http inbound should be unsupported, got %v", err)
	}
}
