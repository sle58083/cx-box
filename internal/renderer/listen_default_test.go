package renderer

import (
	"testing"

	"github.com/sle58083/cx-box/internal/model"
)

// TestRenderInboundCommonListenDefault 锁定关键行为：入站未填 listen 时
// 生成配置必须显式带 "::" 通配监听。sing-box 1.14 省略 listen 时只绑
// 127.0.0.1，外部客户端永远连不上（曾导致全版本节点测速 -1）。
func TestRenderInboundCommonListenDefault(t *testing.T) {
	out := map[string]any{}
	renderInboundCommon(out, model.Inbound{Type: "vless", Name: "in-a", Port: 443})
	if out[fListen] != "::" {
		t.Fatalf("empty listen should render ::, got %v", out[fListen])
	}
	out2 := map[string]any{}
	renderInboundCommon(out2, model.Inbound{Type: "vless", Name: "in-b", Port: 443, Listen: "192.168.1.2"})
	if out2[fListen] != "192.168.1.2" {
		t.Fatalf("explicit listen should pass through, got %v", out2[fListen])
	}
}
