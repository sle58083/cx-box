package sub

import (
	"encoding/json"
	"testing"

	"github.com/sle58083/cx-box/internal/model"
)

// TestInboundAsOutboundNullSettings 回归：入站 settings 存的是 JSON 字面量
// null 时，inboundAsOutbound 曾因 Unmarshal 把 map 置 nil 而 panic
// （真机订阅接口 500）。
func TestInboundAsOutboundNullSettings(t *testing.T) {
	in := model.Inbound{
		Name:     "anytls",
		Type:     "anytls",
		Port:     9443,
		Settings: json.RawMessage(`null`),
		TLS:      json.RawMessage(`null`),
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("inboundAsOutbound panicked: %v", r)
		}
	}()
	ob, err := inboundAsOutbound(in, "203.0.113.7")
	if err != nil {
		t.Fatalf("inboundAsOutbound: %v", err)
	}
	var settings map[string]any
	if err := json.Unmarshal(ob.Settings, &settings); err != nil {
		t.Fatal(err)
	}
	if settings["server"] != "203.0.113.7" || int(settings["server_port"].(float64)) != 9443 {
		t.Fatalf("server not injected: %v", settings)
	}
}
