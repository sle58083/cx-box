package renderer

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sle58083/cx-box/internal/model"
)

// 每个已注册协议都必须有默认模板，且模板本身是合法 JSON。
func TestDefaultsCoverAllProtocols(t *testing.T) {
	defs := Defaults()
	for _, m := range Metas() {
		d, ok := defs[m.Protocol]
		if !ok {
			t.Fatalf("protocol %s missing defaults", m.Protocol)
		}
		for name, dirD := range map[string]*DirectionDefaults{"inbound": d.Inbound, "outbound": d.Outbound} {
			if dirD == nil {
				continue
			}
			for field, raw := range map[string]json.RawMessage{
				"settings": dirD.Settings, "tls": dirD.TLS, "transport": dirD.Transport,
			} {
				if len(raw) > 0 && !json.Valid(raw) {
					t.Fatalf("%s %s %s: invalid JSON %s", m.Protocol, name, field, raw)
				}
			}
		}
	}
}

// 入站默认模板（用户入口模式）必须能通过各自 renderer 的入站校验。
func TestInboundDefaultsPassValidation(t *testing.T) {
	defs := Defaults()
	for proto, d := range defs {
		if d.Inbound == nil {
			continue
		}
		r, ok := Get(proto)
		if !ok {
			continue
		}
		cfg := model.Inbound{
			Name: "test-in", Type: proto, Port: d.Inbound.Port,
			IsUserInbound: true, Status: "enabled",
			Settings: d.Inbound.Settings, TLS: d.Inbound.TLS, Transport: d.Inbound.Transport,
		}
		if cfg.Port == 0 {
			cfg.Port = 443
		}
		// anytls 入站要求证书路径或绑定证书：默认使用形态是绑定证书（路径由面板注入）。
		if proto == "anytls" {
			cid := "00000000-0000-0000-0000-000000000001"
			cfg.CertID = &cid
		}
		if err := r.ValidateInbound(cfg); err != nil {
			t.Fatalf("%s inbound default fails validation: %v", proto, err)
		}
	}
}

// 出站默认模板：填上占位服务器信息后应通过出站校验（direct/block/selector/urltest 除外）。
func TestOutboundDefaultsPassValidation(t *testing.T) {
	defs := Defaults()
	fill := func(raw json.RawMessage) json.RawMessage {
		s := string(raw)
		s = strings.ReplaceAll(s, `"server": ""`, `"server": "example.com"`)
		s = strings.ReplaceAll(s, `"server_name": ""`, `"server_name": "example.com"`)
		s = strings.ReplaceAll(s, `"uuid": ""`, `"uuid": "11111111-2222-3333-4444-555555555555"`)
		s = strings.ReplaceAll(s, `"password": ""`, `"password": "test-pw"`)
		return json.RawMessage(s)
	}
	for proto, d := range defs {
		if d.Outbound == nil {
			continue
		}
		r, ok := Get(proto)
		if !ok {
			continue
		}
		cfg := model.Outbound{
			Name: "test-out", Type: proto, Status: "enabled",
			Settings: fill(d.Outbound.Settings), TLS: fill(d.Outbound.TLS), Transport: d.Outbound.Transport,
		}
		if err := r.ValidateOutbound(cfg); err != nil {
			t.Fatalf("%s outbound default fails validation: %v", proto, err)
		}
	}
}

func TestVLESSSubscriptionURIReality(t *testing.T) {
	r := &VLESSRenderer{}
	cfg := model.Outbound{
		Name:     "vless-out",
		Type:     "vless",
		Settings: json.RawMessage(`{"server":"1.2.3.4","server_port":443,"flow":"xtls-rprx-vision"}`),
		TLS:      json.RawMessage(`{"enabled":true,"server_name":"www.microsoft.com","reality":{"enabled":true,"public_key":"PUBKEY","short_id":"ab12"}}`),
	}
	uri, err := r.SubscriptionURI(cfg, ProxyUser{UUID: "11111111-2222-3333-4444-555555555555"})
	if err != nil {
		t.Fatalf("uri: %v", err)
	}
	for _, want := range []string{"security=reality", "pbk=PUBKEY", "sid=ab12", "sni=www.microsoft.com", "flow=xtls-rprx-vision"} {
		if !strings.Contains(uri, want) {
			t.Fatalf("uri %q missing %q", uri, want)
		}
	}
}
