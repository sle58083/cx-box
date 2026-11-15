package configsvc

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sle58083/cx-box/internal/model"
)

// TestGenerateBoundCertWithNullTLS 回归：入站绑了证书但 TLS 列存的是 JSON
// 字面量 null 时，resolveCertBindings 曾因 Unmarshal 把 map 置 nil 而
// panic（assignment to entry in nil map），导致应用配置 500。
// 复刻真机数据：vmess 入站误绑证书 + TLS 为 null。
func TestGenerateBoundCertWithNullTLS(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	cert := &model.Certificate{
		Name: "c1", Type: "self_signed", Status: "valid",
		CertPEM: "-----BEGIN CERTIFICATE-----\ndummy\n-----END CERTIFICATE-----\n",
		KeyPEM:  "-----BEGIN PRIVATE KEY-----\ndummy\n-----END PRIVATE KEY-----\n",
	}
	if err := svc.db.Create(cert).Error; err != nil {
		t.Fatal(err)
	}
	certID := cert.ID.String()
	in := &model.Inbound{
		Name: "vmess", Type: "vmess", Port: 8443, Status: model.StatusEnabled,
		IsUserInbound: true, CertID: &certID,
		Settings: json.RawMessage(`{"security":"auto"}`),
		TLS:      json.RawMessage(`null`),
	}
	if err := svc.db.Create(in).Error; err != nil {
		t.Fatal(err)
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Generate panicked: %v", r)
		}
	}()
	doc, err := svc.Generate(ctx)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	ins := doc["inbounds"].([]map[string]any)
	if len(ins) != 1 {
		t.Fatalf("inbounds = %d", len(ins))
	}
}
