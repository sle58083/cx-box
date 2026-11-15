package renderer

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sle58083/cx-box/internal/model"
)

func TestHysteria2InboundPassthrough(t *testing.T) {
	r := &Hysteria2Renderer{}
	cfg := model.Inbound{
		Name: "hy2", Type: "hysteria2", Port: 443, IsUserInbound: true,
		Settings: json.RawMessage(`{"up_mbps":100,"down_mbps":200,"ignore_client_bandwidth":true,"obfs":{"type":"salamander","password":"obfs-pw"},"masquerade":"https://www.bing.com"}`),
		TLS:      json.RawMessage(`{"enabled":true,"certificate_path":"/c.pem","key_path":"/k.pem"}`),
	}
	out, err := r.RenderInbound(&RenderContext{}, cfg, []ProxyUser{{Name: "a@b.c", Password: "pw"}})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if out["up_mbps"] != float64(100) || out["down_mbps"] != float64(200) {
		t.Fatalf("bandwidth not passed: %v", out)
	}
	if out["ignore_client_bandwidth"] != true {
		t.Fatalf("ignore_client_bandwidth not passed: %v", out)
	}
	obfs, ok := out["obfs"].(map[string]any)
	if !ok || obfs["type"] != "salamander" {
		t.Fatalf("obfs not passed: %v", out["obfs"])
	}
	if out["masquerade"] != "https://www.bing.com" {
		t.Fatalf("masquerade = %v", out["masquerade"])
	}
}

func TestHysteria2ObfsValidation(t *testing.T) {
	r := &Hysteria2Renderer{}
	base := model.Inbound{
		Name: "hy2", Type: "hysteria2", Port: 443, IsUserInbound: true,
		TLS: json.RawMessage(`{"enabled":true}`),
	}
	bad := base
	bad.Settings = json.RawMessage(`{"obfs":{"type":"salamander"}}`)
	if err := r.ValidateInbound(bad); err == nil {
		t.Fatal("obfs without password should fail")
	}
	good := base
	good.Settings = json.RawMessage(`{"obfs":{"type":"salamander","password":"x"}}`)
	if err := r.ValidateInbound(good); err != nil {
		t.Fatalf("valid obfs rejected: %v", err)
	}
}

func TestHysteria2SubscriptionURIObfs(t *testing.T) {
	r := &Hysteria2Renderer{}
	cfg := model.Outbound{
		Name:     "hy2",
		Type:     "hysteria2",
		Settings: json.RawMessage(`{"server":"1.2.3.4","server_port":443,"obfs":{"type":"salamander","password":"obfs-pw"}}`),
		TLS:      json.RawMessage(`{"enabled":true,"server_name":"example.com"}`),
	}
	uri, err := r.SubscriptionURI(cfg, ProxyUser{Password: "user-pw"})
	if err != nil {
		t.Fatalf("uri: %v", err)
	}
	for _, want := range []string{"hysteria2://user-pw@1.2.3.4:443", "obfs=salamander", "obfs-password=obfs-pw", "sni=example.com"} {
		if !strings.Contains(uri, want) {
			t.Fatalf("uri %q missing %q", uri, want)
		}
	}
}
