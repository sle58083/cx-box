package renderer

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestValidateFlowCombo vision 流控 + 非 TCP 传输是注定不可用的组合，必须拦；
// Reality + ws 经实测可用，不拦。
func TestValidateFlowCombo(t *testing.T) {
	vision := map[string]any{"flow": "xtls-rprx-vision"}
	noFlow := map[string]any{}
	ws := json.RawMessage(`{"type":"ws","path":"/ws"}`)
	grpc := json.RawMessage(`{"type":"grpc","service_name":"g"}`)
	tcp := json.RawMessage(`{"type":"tcp"}`)

	if err := validateFlowCombo(ws, vision); err == nil || !strings.Contains(err.Error(), "仅支持 TCP 直连") {
		t.Fatalf("vision+ws should be rejected: %v", err)
	}
	if err := validateFlowCombo(grpc, vision); err == nil {
		t.Fatal("vision+grpc should be rejected")
	}
	if err := validateFlowCombo(tcp, vision); err != nil {
		t.Fatalf("vision+tcp should pass: %v", err)
	}
	if err := validateFlowCombo(nil, vision); err != nil {
		t.Fatalf("vision+no transport should pass: %v", err)
	}
	if err := validateFlowCombo(ws, noFlow); err != nil {
		t.Fatalf("no flow + ws should pass: %v", err)
	}
}
