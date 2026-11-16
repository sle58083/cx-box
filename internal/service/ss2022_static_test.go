package service

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/sle58083/cx-box/internal/model"
)

// TestEnsureSS2022StaticKey 静态 ss 入站 2022 留空保存时自动生成合法
// 服务端密钥并写回 settings；已有密码、用户入口、经典方法都不动。
func TestEnsureSS2022StaticKey(t *testing.T) {
	mk := func(isUser bool, settings string) *model.Inbound {
		return &model.Inbound{
			Type:          "shadowsocks",
			Name:          "ss-static",
			Port:          8388,
			IsUserInbound: isUser,
			Settings:      json.RawMessage(settings),
		}
	}
	getPW := func(in *model.Inbound) string {
		var s map[string]any
		if err := json.Unmarshal(in.Settings, &s); err != nil {
			t.Fatalf("settings 不是合法 JSON: %v", err)
		}
		pw, _ := s["password"].(string)
		return pw
	}

	// 静态 + 2022-256 + 留空 → 生成 32 字节密钥。
	in := mk(false, `{"method":"2022-blake3-aes-256-gcm"}`)
	ensureSS2022StaticKey(in)
	raw, err := base64.StdEncoding.DecodeString(getPW(in))
	if err != nil || len(raw) != 32 {
		t.Fatalf("应生成 32 字节 base64 密钥, got %q (err=%v)", getPW(in), err)
	}
	// 再次调用不覆盖（已有密码）。
	first := getPW(in)
	ensureSS2022StaticKey(in)
	if getPW(in) != first {
		t.Fatal("已有密钥不应被覆盖")
	}
	// 静态 + 2022-128 + 留空 → 16 字节。
	in128 := mk(false, `{"method":"2022-blake3-aes-128-gcm"}`)
	ensureSS2022StaticKey(in128)
	if raw, err := base64.StdEncoding.DecodeString(getPW(in128)); err != nil || len(raw) != 16 {
		t.Fatalf("应生成 16 字节 base64 密钥, got %q (err=%v)", getPW(in128), err)
	}
	// 用户入口不处理（其服务端密钥走渲染推导，不落库）。
	inUser := mk(true, `{"method":"2022-blake3-aes-128-gcm"}`)
	ensureSS2022StaticKey(inUser)
	if getPW(inUser) != "" {
		t.Fatal("用户入口不应被写入静态密钥")
	}
	// 经典方法不处理。
	inLegacy := mk(false, `{"method":"aes-128-gcm"}`)
	ensureSS2022StaticKey(inLegacy)
	if getPW(inLegacy) != "" {
		t.Fatal("经典方法不应被写入密钥")
	}
}
