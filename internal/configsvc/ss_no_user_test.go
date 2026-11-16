package configsvc

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/sle58083/cx-box/internal/model"
	"github.com/sle58083/cx-box/internal/renderer"
)

// TestGenerateSkipsCredentialLessSSInbound 覆盖自动应用暴露的启动顺序
// 问题：先建 ss 用户入口、还没建客户端时，生成的配置若带上这个无凭据
// 入站，sing-box 会以 missing password 拒绝整份配置。生成器应跳过它；
// 有客户端或设了静态密码后必须正常生成。
func TestGenerateSkipsCredentialLessSSInbound(t *testing.T) {
	mkInbound := func(settings string) model.Inbound {
		return model.Inbound{
			Base:          model.Base{ID: model.NewID()},
			Type:          "shadowsocks",
			Name:          "ss-in",
			Port:          8388,
			Settings:      json.RawMessage(settings),
			IsUserInbound: true,
			Status:        model.StatusEnabled,
		}
	}
	count := func(ctx *NodeConfigContext) int {
		doc, err := NewGenerator().Generate(ctx)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		list, _ := doc["inbounds"].([]map[string]any)
		return len(list)
	}

	// 无客户端、无静态密码 → 跳过。
	if n := count(&NodeConfigContext{
		Global:   DefaultGlobalSettings(),
		Inbounds: []model.Inbound{mkInbound(`{"method":"aes-128-gcm"}`)},
	}); n != 0 {
		t.Fatalf("无凭据 ss 入站应被跳过, got %d inbounds", n)
	}

	// 有客户端 → 生成（users 注入）。
	user := renderer.ProxyUser{ID: "c1", Name: "u1"}
	user.Password = "pw1"
	if n := count(&NodeConfigContext{
		Global:     DefaultGlobalSettings(),
		Inbounds:   []model.Inbound{mkInbound(`{"method":"aes-128-gcm"}`)},
		ProxyUsers: []renderer.ProxyUser{user},
	}); n != 1 {
		t.Fatalf("有客户端时 ss 入站应生成, got %d inbounds", n)
	}

	// 设了静态密码 → 无客户端也生成。
	if n := count(&NodeConfigContext{
		Global:   DefaultGlobalSettings(),
		Inbounds: []model.Inbound{mkInbound(`{"method":"aes-128-gcm","password":"staticpw"}`)},
	}); n != 1 {
		t.Fatalf("有静态密码时 ss 入站应生成, got %d inbounds", n)
	}
}

// TestGenerateSS2022NoUserNotSkipped 2022 入站无客户端时不再跳过：服务端
// 密钥由渲染器自动推导补齐，PSK-only 配置合法（旧行为会 missing psk）。
func TestGenerateSS2022NoUserNotSkipped(t *testing.T) {
	in := model.Inbound{
		Base:          model.Base{ID: model.NewID()},
		Type:          "shadowsocks",
		Name:          "ss-in",
		Port:          8388,
		Settings:      json.RawMessage(`{"method":"2022-blake3-aes-128-gcm"}`),
		IsUserInbound: true,
		Status:        model.StatusEnabled,
	}
	doc, err := NewGenerator().Generate(&NodeConfigContext{
		Global:   DefaultGlobalSettings(),
		Inbounds: []model.Inbound{in},
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	list, _ := doc["inbounds"].([]map[string]any)
	if len(list) != 1 {
		t.Fatalf("2022 无客户端入站应生成, got %d inbounds", len(list))
	}
	pw, _ := list[0]["password"].(string)
	if pw == "" {
		t.Fatal("2022 入站应带自动推导的服务端密钥")
	}
	raw, err := base64.StdEncoding.DecodeString(pw)
	if err != nil || len(raw) != 16 {
		t.Fatalf("服务端密钥应是 16 字节 base64, got %q (err=%v)", pw, err)
	}
}
