package renderer

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sle58083/cx-box/internal/model"
)

// TestSubscriptionURIInsecure 自签证书场景下各 TLS 协议链接必须带跳过校验参数，
// 否则客户端校验证书必然失败（x509: certificate signed by unknown authority）。
func TestSubscriptionURIInsecure(t *testing.T) {
	mkOut := func(typ, settings, tls string) model.Outbound {
		return model.Outbound{Name: "n", Type: typ,
			Settings: json.RawMessage(settings), TLS: json.RawMessage(tls)}
	}
	const tlsInsecure = `{"enabled":true,"server_name":"example.com","insecure":true}`
	const tlsPlain = `{"enabled":true,"server_name":"example.com"}`

	cases := []struct {
		proto    string
		settings string
		user     ProxyUser
		want     string
	}{
		{"trojan", `{"server":"h","server_port":4443}`, ProxyUser{Password: "pw"}, "insecure=1"},
		{"anytls", `{"server":"h","server_port":9443}`, ProxyUser{Password: "pw"}, "insecure=1"},
		{"hysteria2", `{"server":"h","server_port":36712}`, ProxyUser{Password: "pw"}, "insecure=1"},
		{"tuic", `{"server":"h","server_port":10443,"password":"pw"}`, ProxyUser{UUID: "11111111-2222-3333-4444-555555555555"}, "allow_insecure=1"},
		{"tuic", `{"server":"h","server_port":10443,"password":"pw"}`, ProxyUser{UUID: "11111111-2222-3333-4444-555555555555"}, "alpn=h3"},
		{"trojan", `{"server":"h","server_port":4443}`, ProxyUser{Password: "pw"}, "allowInsecure=1"},
		{"vless", `{"server":"h","server_port":443,"flow":""}`, ProxyUser{UUID: "11111111-2222-3333-4444-555555555555"}, "insecure=1"},
	}
	for _, c := range cases {
		r, ok := Get(c.proto)
		if !ok {
			t.Fatalf("renderer %s not registered", c.proto)
		}
		uri, err := r.SubscriptionURI(mkOut(c.proto, c.settings, tlsInsecure), c.user)
		if err != nil {
			t.Fatalf("%s uri: %v", c.proto, err)
		}
		if !strings.Contains(uri, c.want) {
			t.Fatalf("%s uri %q missing %s", c.proto, uri, c.want)
		}
		uri2, err := r.SubscriptionURI(mkOut(c.proto, c.settings, tlsPlain), c.user)
		if err != nil {
			t.Fatalf("%s uri (plain): %v", c.proto, err)
		}
		if strings.Contains(uri2, "insecure") {
			t.Fatalf("%s uri %q should not contain insecure without the flag", c.proto, uri2)
		}
	}
}
