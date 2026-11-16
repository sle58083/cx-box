package renderer

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/sle58083/cx-box/internal/model"
)

func mustParse(t *testing.T, uri string) *ParsedLink {
	t.Helper()
	p, err := ParseLink(uri)
	if err != nil {
		t.Fatalf("ParseLink(%q): %v", uri, err)
	}
	return p
}

func settingsOf(t *testing.T, p *ParsedLink) map[string]any {
	t.Helper()
	m, err := parseMap(p.Settings)
	if err != nil {
		t.Fatalf("settings 解析失败: %v", err)
	}
	return m
}

func tlsOf(t *testing.T, p *ParsedLink) map[string]any {
	t.Helper()
	m, err := parseMap(p.TLS)
	if err != nil {
		t.Fatalf("tls 解析失败: %v", err)
	}
	return m
}

// TestParseLinkRoundTrip 用各 renderer 的 SubscriptionURI 生成链接再解析
// 回来，核心字段必须无损往返（这是导入功能与订阅生成的对偶契约）。
func TestParseLinkRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		proto string
		cfg   model.Outbound
		user  ProxyUser
		check func(t *testing.T, p *ParsedLink)
	}{
		{
			name: "vless-reality", proto: "vless",
			cfg: model.Outbound{Name: "落地A", Settings: json.RawMessage(`{"server":"1.2.3.4","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","flow":"xtls-rprx-vision"}`),
				TLS: json.RawMessage(`{"enabled":true,"server_name":"www.microsoft.com","reality":{"enabled":true,"public_key":"PKPK","short_id":"ab12"},"utls":{"enabled":true,"fingerprint":"chrome"}}`)},
			user: ProxyUser{UUID: "11111111-2222-3333-4444-555555555555"},
			check: func(t *testing.T, p *ParsedLink) {
				s := settingsOf(t, p)
				if s["server"] != "1.2.3.4" || s["uuid"] != "11111111-2222-3333-4444-555555555555" || s["flow"] != "xtls-rprx-vision" {
					t.Errorf("settings 不符: %v", s)
				}
				tls := tlsOf(t, p)
				r, _ := tls["reality"].(map[string]any)
				if r == nil || r["public_key"] != "PKPK" || r["short_id"] != "ab12" {
					t.Errorf("reality 不符: %v", tls)
				}
			},
		},
		{
			name: "vmess-ws", proto: "vmess",
			cfg: model.Outbound{Name: "vm节点", Settings: json.RawMessage(`{"server":"vm.example.com","server_port":8443,"uuid":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","alter_id":0}`),
				Transport: json.RawMessage(`{"type":"ws","path":"/vmess","headers":{"Host":"cdn.example.com"}}`)},
			user: ProxyUser{UUID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
			check: func(t *testing.T, p *ParsedLink) {
				s := settingsOf(t, p)
				if s["server"] != "vm.example.com" || s["uuid"] != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
					t.Errorf("settings 不符: %v", s)
				}
				tr, err := parseMap(p.Transport)
				if err != nil || tr["type"] != "ws" || tr["path"] != "/vmess" {
					t.Errorf("transport 不符: %v %v", tr, err)
				}
			},
		},
		{
			name: "trojan", proto: "trojan",
			cfg: model.Outbound{Name: "tj", Settings: json.RawMessage(`{"server":"tj.example.com","server_port":4443}`),
				TLS: json.RawMessage(`{"enabled":true,"server_name":"tj.example.com","insecure":true}`)},
			user: ProxyUser{},
			check: func(t *testing.T, p *ParsedLink) {
				s := settingsOf(t, p)
				if s["server"] != "tj.example.com" {
					t.Errorf("settings 不符: %v", s)
				}
				if pw, _ := s["password"].(string); pw != "linkpw123" {
					t.Errorf("trojan 密码不符: %v", s)
				}
				tls := tlsOf(t, p)
				if tls["server_name"] != "tj.example.com" || tls["insecure"] != true {
					t.Errorf("tls 不符: %v", tls)
				}
			},
		},
		{
			name: "hysteria2-obfs", proto: "hysteria2",
			cfg: model.Outbound{Name: "hy", Settings: json.RawMessage(`{"server":"hy.example.com","server_port":36712,"obfs":{"type":"salamander","password":"obpw"}}`),
				TLS: json.RawMessage(`{"enabled":true,"server_name":"hy.example.com","insecure":true,"alpn":["h3"]}`)},
			user: ProxyUser{},
			check: func(t *testing.T, p *ParsedLink) {
				s := settingsOf(t, p)
				obfs, _ := s["obfs"].(map[string]any)
				if obfs == nil || obfs["type"] != "salamander" {
					t.Errorf("obfs 不符: %v", s)
				}
				if pw, _ := obfs["password"].(string); pw != "obpw" {
					t.Errorf("obfs 密码不符: %v", obfs)
				}
				if pw, _ := s["password"].(string); pw != "linkpw123" {
					t.Errorf("hy2 密码不符: %v", s)
				}
			},
		},
		{
			name: "tuic", proto: "tuic",
			cfg: model.Outbound{Name: "tu", Settings: json.RawMessage(`{"server":"tu.example.com","server_port":10443,"uuid":"99999999-8888-7777-6666-555555555555","password":"tupw","congestion_control":"bbr"}`),
				TLS: json.RawMessage(`{"enabled":true,"server_name":"tu.example.com","alpn":["h3"],"insecure":true}`)},
			user: ProxyUser{UUID: "99999999-8888-7777-6666-555555555555"},
			check: func(t *testing.T, p *ParsedLink) {
				s := settingsOf(t, p)
				if s["uuid"] != "99999999-8888-7777-6666-555555555555" || s["congestion_control"] != "bbr" {
					t.Errorf("settings 不符: %v", s)
				}
				if pw, _ := s["password"].(string); pw != "tupw" {
					t.Errorf("密码不符: %v", s)
				}
				tls := tlsOf(t, p)
				alpn, _ := tls["alpn"].([]any)
				if len(alpn) != 1 || alpn[0] != "h3" {
					t.Errorf("alpn 不符: %v", tls)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, ok := Get(tc.proto)
			if !ok {
				t.Fatalf("Get(%s) 未注册", tc.proto)
			}
			user := tc.user
			// trojan/hy2 的链接凭据来自 user.Password，测试里统一给值。
			if user.Password == "" {
				user.Password = "linkpw123"
			}
			uri, err := r.SubscriptionURI(tc.cfg, user)
			if err != nil {
				t.Fatalf("SubscriptionURI: %v", err)
			}
			p := mustParse(t, uri)
			if p.Protocol != tc.proto {
				t.Fatalf("protocol = %s, want %s (uri=%s)", p.Protocol, tc.proto, uri)
			}
			tc.check(t, p)
		})
	}
}

// TestParseLinkShadowsocks 单独覆盖 ss 的两种编码形态与 anytls 明文形态。
func TestParseLinkShadowsocks(t *testing.T) {
	// SIP002：userinfo 为 base64(method:password)。
	ui := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:sspw"))
	p := mustParse(t, "ss://"+ui+"@ss.example.com:8388#我的节点")
	s := settingsOf(t, p)
	if p.Protocol != "shadowsocks" || s["method"] != "aes-128-gcm" || s["server"] != "ss.example.com" {
		t.Errorf("SIP002 解析不符: %+v %v", p, s)
	}
	if pw, _ := s["password"].(string); pw != "sspw" {
		t.Errorf("ss 密码不符: %v", s)
	}
	if p.Name != "我的节点" {
		t.Errorf("名称不符: %q", p.Name)
	}
	// 旧式：整体 base64(method:password@host:port)。
	full := base64.StdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:pw2@old.example.com:8399"))
	p2 := mustParse(t, "ss://"+full+"#old")
	s2 := settingsOf(t, p2)
	if s2["method"] != "chacha20-ietf-poly1305" || s2["server"] != "old.example.com" {
		t.Errorf("旧式 ss 解析不符: %v", s2)
	}
	if pw, _ := s2["password"].(string); pw != "pw2" {
		t.Errorf("旧式 ss 密码不符: %v", s2)
	}
}

// TestParseLinkForeignForms 覆盖外部客户端的常见链接变体。
func TestParseLinkForeignForms(t *testing.T) {
	// vless + ws + tls（机场常见形态）。
	p := mustParse(t, "vless://11111111-2222-3333-4444-555555555555@hk.example.com:443?encryption=none&security=tls&type=ws&path=%2Fws&host=cdn.example.com&sni=hk.example.com#香港")
	s := settingsOf(t, p)
	if s["server"] != "hk.example.com" || p.Name != "香港" {
		t.Errorf("vless 变体不符: %+v", p)
	}
	tr, err := parseMap(p.Transport)
	if err != nil || tr["type"] != "ws" || tr["path"] != "/ws" {
		t.Errorf("vless ws 传输不符: %v %v", tr, err)
	}
	// anytls 明文密码（v2rayN 形态）。
	p2 := mustParse(t, "anytls://plainpw@at.example.com:9443?sni=at.example.com&insecure=1#at")
	s2 := settingsOf(t, p2)
	if pw, _ := s2["password"].(string); pw != "plainpw" {
		t.Errorf("anytls 明文密码不符: %v", s2)
	}
	// anytls 本面板形态（base64 密码）。
	b64pw := base64.StdEncoding.EncodeToString([]byte("secret-pw"))
	p3 := mustParse(t, "anytls://"+b64pw+"@at.example.com:9443?sni=at.example.com#at2")
	s3 := settingsOf(t, p3)
	if pw, _ := s3["password"].(string); pw != "secret-pw" {
		t.Errorf("anytls base64 密码不符: %v", s3)
	}
	// socks 账密明文。
	p4 := mustParse(t, "socks://user1:pass1@10.0.0.1:1080#落地")
	s4 := settingsOf(t, p4)
	if s4["username"] != "user1" || s4["server"] != "10.0.0.1" {
		t.Errorf("socks 解析不符: %v", s4)
	}
	if pw, _ := s4["password"].(string); pw != "pass1" {
		t.Errorf("socks 密码不符: %v", s4)
	}
	// http 代理链接。
	p5 := mustParse(t, "http://user2:pass2@10.0.0.2:8080#http落地")
	if p5.Protocol != "http" {
		t.Errorf("http 协议不符: %s", p5.Protocol)
	}
	s5 := settingsOf(t, p5)
	if s5["username"] != "user2" {
		t.Errorf("http 解析不符: %v", s5)
	}
	// 错误形态必须报错而不是静默产出空出站。
	if _, err := ParseLink("not-a-link"); err == nil {
		t.Error("非法链接应报错")
	}
	if _, err := ParseLink("vless://@host.example.com:443"); err == nil {
		t.Error("缺 UUID 的 vless 链接应报错")
	}
}
