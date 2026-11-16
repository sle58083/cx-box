package renderer

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/sle58083/cx-box/internal/model"
)

// TestSS2022KeyLen 钉住 2022 系列的密钥长度映射与经典方法的区分。
func TestSS2022KeyLen(t *testing.T) {
	cases := []struct {
		method string
		len    int
		ok     bool
	}{
		{"2022-blake3-aes-128-gcm", 16, true},
		{"2022-blake3-aes-256-gcm", 32, true},
		{"2022-blake3-chacha20-poly1305", 32, true},
		{"aes-128-gcm", 0, false},
		{"aes-256-gcm", 0, false},
		{"chacha20-ietf-poly1305", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		gotLen, gotOK := SS2022KeyLen(c.method)
		if gotLen != c.len || gotOK != c.ok {
			t.Errorf("SS2022KeyLen(%q) = %d,%v want %d,%v", c.method, gotLen, gotOK, c.len, c.ok)
		}
	}
}

// TestSS2022UserKey 用户密钥推导：确定性、长度合法、不同原始密码不同结果。
func TestSS2022UserKey(t *testing.T) {
	k1 := SS2022UserKey("2022-blake3-aes-128-gcm", "client-secret-1")
	if k1 != SS2022UserKey("2022-blake3-aes-128-gcm", "client-secret-1") {
		t.Fatal("同一输入应推导出同一密钥")
	}
	raw, err := base64.StdEncoding.DecodeString(k1)
	if err != nil || len(raw) != 16 {
		t.Fatalf("aes-128 用户密钥应是 16 字节 base64, got %q (err=%v)", k1, err)
	}
	k256 := SS2022UserKey("2022-blake3-aes-256-gcm", "client-secret-1")
	if raw, err := base64.StdEncoding.DecodeString(k256); err != nil || len(raw) != 32 {
		t.Fatalf("aes-256 用户密钥应是 32 字节 base64, got %q (err=%v)", k256, err)
	}
	if SS2022UserKey("2022-blake3-aes-128-gcm", "client-secret-2") == k1 {
		t.Fatal("不同原始密码应推导出不同密钥")
	}
	if got := SS2022UserKey("aes-128-gcm", "plain"); got != "plain" {
		t.Fatalf("经典方法应原样返回, got %q", got)
	}
}

// TestSS2022ServerKey 服务端密钥：合法的 settings 密钥优先；缺失/非法时
// 按入站 ID 确定性推导（稳定、随 ID 不同而不同、长度合法）。
func TestSS2022ServerKey(t *testing.T) {
	method := "2022-blake3-aes-128-gcm"
	valid := base64.StdEncoding.EncodeToString(make([]byte, 16))
	settings := map[string]any{fMethod: method, fPassword: valid}
	if got := SS2022ServerKey("in-1", method, settings); got != valid {
		t.Fatalf("合法 settings 密钥应被沿用, got %q", got)
	}
	derived := SS2022ServerKey("in-1", method, map[string]any{fMethod: method})
	if derived == "" || derived == valid {
		t.Fatalf("缺失时应推导新密钥, got %q", derived)
	}
	if raw, err := base64.StdEncoding.DecodeString(derived); err != nil || len(raw) != 16 {
		t.Fatalf("推导密钥应是 16 字节 base64, got %q (err=%v)", derived, err)
	}
	if derived != SS2022ServerKey("in-1", method, map[string]any{fMethod: method}) {
		t.Fatal("推导应确定性稳定")
	}
	if derived == SS2022ServerKey("in-2", method, map[string]any{fMethod: method}) {
		t.Fatal("不同入站应推导出不同密钥")
	}
	// settings 里是普通字符串（非合法密钥）时也走推导，不把坏密钥交给内核。
	bad := map[string]any{fMethod: method, fPassword: "not-a-key"}
	if got := SS2022ServerKey("in-1", method, bad); got != derived {
		t.Fatalf("非法 settings 密钥应回落推导, got %q want %q", got, derived)
	}
	if got := SS2022ServerKey("in-1", "aes-128-gcm", settings); got != "" {
		t.Fatalf("经典方法应返回空, got %q", got)
	}
}

// TestSS2022RenderAndLinkConsistency 核心不变量：同一入站同一用户，
// 入站渲染里的服务端密钥/用户密钥与订阅链接里的组合密码必须完全一致，
// 否则客户端拿着链接连不上（服务端密钥不一致直接握手失败）。
func TestSS2022RenderAndLinkConsistency(t *testing.T) {
	r := &ShadowsocksRenderer{}
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		in := model.Inbound{
			Base:          model.Base{ID: model.NewID()},
			Type:          "shadowsocks",
			Name:          "ss-in",
			Port:          8388,
			IsUserInbound: true,
			Settings:      raw(`{"method":"` + method + `"}`),
		}
		pw1, pw2 := "client-one-secret", "client-two-secret"
		users := []ProxyUser{{ID: "c1", Name: "c1"}, {ID: "c2", Name: "c2"}}
		users[0].Password = pw1
		users[1].Password = pw2
		out, err := r.RenderInbound(&RenderContext{}, in, users)
		if err != nil {
			t.Fatalf("%s RenderInbound: %v", method, err)
		}
		serverKey, _ := out[fPassword].(string)
		keyLen, _ := SS2022KeyLen(method)
		if raw, err := base64.StdEncoding.DecodeString(serverKey); err != nil || len(raw) != keyLen {
			t.Fatalf("%s 服务端密钥应是 %d 字节 base64, got %q", method, keyLen, serverKey)
		}
		us, ok := out[fUsers].([]map[string]any)
		if !ok || len(us) != 2 {
			t.Fatalf("%s users 渲染错误: %#v", method, out[fUsers])
		}
		// 订阅侧：outbound 视图带入站 ID 与入站 settings（同 sub 的做法）。
		ob := model.Outbound{
			Base:     model.Base{ID: in.ID},
			Name:     "ss-in",
			Type:     "shadowsocks",
			Settings: raw(`{"method":"` + method + `","server":"203.0.113.7","server_port":8388}`),
		}
		for i, u := range users {
			uri, err := r.SubscriptionURI(ob, u)
			if err != nil {
				t.Fatalf("%s SubscriptionURI: %v", method, err)
			}
			ui := strings.SplitN(strings.TrimPrefix(uri, "ss://"), "@", 2)[0]
			dec, err := base64.StdEncoding.DecodeString(ui)
			if err != nil {
				t.Fatalf("%s 链接 userinfo 不是合法 base64: %v", method, err)
			}
			parts := strings.SplitN(string(dec), ":", 2)
			if len(parts) != 2 || parts[0] != method {
				t.Fatalf("%s 链接 method:password 结构错误: %q", method, string(dec))
			}
			want := serverKey + ":" + us[i][fPassword].(string)
			if parts[1] != want {
				t.Fatalf("%s 链接组合密码与渲染不一致:\n got %q\nwant %q", method, parts[1], want)
			}
		}
	}
}

// TestSSLegacyRenderUnchanged 经典方法行为不变：用户入口不带顶层密码、
// 用户密码原样、链接密码原样。
func TestSSLegacyRenderUnchanged(t *testing.T) {
	r := &ShadowsocksRenderer{}
	in := model.Inbound{
		Base:          model.Base{ID: model.NewID()},
		Type:          "shadowsocks",
		Name:          "ss-in",
		Port:          8388,
		IsUserInbound: true,
		Settings:      raw(`{"method":"aes-128-gcm"}`),
	}
	u := ProxyUser{ID: "c1", Name: "c1"}
	u.Password = "plain-secret"
	out, err := r.RenderInbound(&RenderContext{}, in, []ProxyUser{u})
	if err != nil {
		t.Fatalf("RenderInbound: %v", err)
	}
	if _, has := out[fPassword]; has {
		t.Fatalf("经典方法用户入口不应带顶层密码: %#v", out)
	}
	us := out[fUsers].([]map[string]any)
	if us[0][fPassword] != "plain-secret" {
		t.Fatalf("经典方法用户密码应原样, got %q", us[0][fPassword])
	}
	ob := model.Outbound{
		Base:     model.Base{ID: in.ID},
		Name:     "ss-in",
		Type:     "shadowsocks",
		Settings: raw(`{"method":"aes-128-gcm","server":"203.0.113.7","server_port":8388}`),
	}
	uri, err := r.SubscriptionURI(ob, u)
	if err != nil {
		t.Fatalf("SubscriptionURI: %v", err)
	}
	ui := strings.SplitN(strings.TrimPrefix(uri, "ss://"), "@", 2)[0]
	dec, _ := base64.StdEncoding.DecodeString(ui)
	if string(dec) != "aes-128-gcm:plain-secret" {
		t.Fatalf("经典方法链接应原样, got %q", string(dec))
	}
}
