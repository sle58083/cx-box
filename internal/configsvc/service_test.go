package configsvc

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/db"
	"github.com/sle58083/cx-box/internal/kernel"
	"github.com/sle58083/cx-box/internal/model"
)

// openTestDB 打开测试数据库并迁移。
func openTestDB(t *testing.T) (*gorm.DB, error) {
	t.Helper()
	g, err := db.Open(t.TempDir() + "/test.db")
	if err != nil {
		return nil, err
	}
	if err := db.Migrate(g); err != nil {
		return nil, err
	}
	// 关闭底层连接，避免 Windows 下 SQLite 文件被占用导致 TempDir 清理失败。
	t.Cleanup(func() {
		if sqlDB, err := g.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	return g, nil
}

// newTestService 构造测试用 Service（内存 SQLite）。
func newTestService(t *testing.T) *Service {
	t.Helper()
	g, err := openTestDB(t)
	if err != nil {
		t.Fatal(err)
	}
	km := kernel.New(t.TempDir(), "1.14.4")
	return NewService(g, km)
}

func TestGenerateInjectsDirectWhenNoOutbounds(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	// 创建一个 shadowsocks 入站
	in := model.Inbound{
		Base:     model.Base{ID: model.NewID()},
		Name:     "ss-test",
		Type:     "shadowsocks",
		Listen:   "0.0.0.0",
		Port:     10086,
		Settings: json.RawMessage(`{"method":"aes-128-gcm","password":"test-pass-123"}`),
		Status:   model.StatusEnabled,
	}
	if err := s.db.Create(&in).Error; err != nil {
		t.Fatal(err)
	}

	doc, err := s.Generate(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// 验证 outbounds 有 direct 兜底
	outbounds, ok := doc["outbounds"].([]map[string]any)
	if !ok {
		t.Fatalf("outbounds 类型错误: %T", doc["outbounds"])
	}
	if len(outbounds) != 1 {
		t.Fatalf("期望 1 个 outbound（direct 兜底），实际 %d", len(outbounds))
	}
	if outbounds[0]["type"] != "direct" {
		t.Errorf("期望 direct 兜底，实际 %v", outbounds[0]["type"])
	}

	// 验证 inbounds 有 ss-test
	inbounds, _ := doc["inbounds"].([]map[string]any)
	if len(inbounds) != 1 {
		t.Fatalf("期望 1 个 inbound，实际 %d", len(inbounds))
	}
	if inbounds[0]["type"] != "shadowsocks" {
		t.Errorf("期望 shadowsocks，实际 %v", inbounds[0]["type"])
	}
}

func TestGenerateMultiProtocol(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	// 创建多种协议的入站
	inbounds := []model.Inbound{
		{Base: model.Base{ID: model.NewID()}, Name: "vmess-1", Type: "vmess", Port: 10001,
			Settings: json.RawMessage(`{"users":[{"uuid":"12345678-1234-1234-1234-123456789abc"}]}`), Status: model.StatusEnabled},
		{Base: model.Base{ID: model.NewID()}, Name: "vless-1", Type: "vless", Port: 10002,
			Settings: json.RawMessage(`{"users":[{"uuid":"12345678-1234-1234-1234-123456789abc"}]}`), Status: model.StatusEnabled},
		{Base: model.Base{ID: model.NewID()}, Name: "trojan-1", Type: "trojan", Port: 10003,
			Settings: json.RawMessage(`{"users":[{"name":"u1","password":"pass"}]}`),
			TLS:      json.RawMessage(`{"enabled":true}`), Status: model.StatusEnabled},
	}
	for i := range inbounds {
		if err := s.db.Create(&inbounds[i]).Error; err != nil {
			t.Fatal(err)
		}
	}

	doc, err := s.Generate(ctx)
	if err != nil {
		t.Fatal(err)
	}

	got, _ := doc["inbounds"].([]map[string]any)
	if len(got) != 3 {
		t.Fatalf("期望 3 个 inbound，实际 %d", len(got))
	}
}

func TestGenerateDisabledInboundFiltered(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	// 一个 enabled + 一个 disabled
	en := model.Inbound{Base: model.Base{ID: model.NewID()}, Name: "on", Type: "shadowsocks", Port: 10001,
		Settings: json.RawMessage(`{"method":"aes-128-gcm","password":"p"}`), Status: model.StatusEnabled}
	dis := model.Inbound{Base: model.Base{ID: model.NewID()}, Name: "off", Type: "shadowsocks", Port: 10002,
		Settings: json.RawMessage(`{"method":"aes-128-gcm","password":"p"}`), Status: model.StatusDisabled}
	if err := s.db.Create(&en).Error; err != nil {
		t.Fatal(err)
	}
	if err := s.db.Create(&dis).Error; err != nil {
		t.Fatal(err)
	}

	doc, err := s.Generate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := doc["inbounds"].([]map[string]any)
	if len(got) != 1 {
		t.Fatalf("期望只渲染 1 个 enabled 入站，实际 %d", len(got))
	}
	if got[0]["tag"] != "on" {
		t.Errorf("期望 tag=on，实际 %v", got[0]["tag"])
	}
}

func TestGenerateInjectsBoundCertPaths(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	cert := &model.Certificate{
		Name: "ss", Type: "self_signed", Status: "valid",
		CertPEM: "-----BEGIN CERTIFICATE-----\ndummy\n-----END CERTIFICATE-----\n",
		KeyPEM:  "-----BEGIN PRIVATE KEY-----\ndummy\n-----END PRIVATE KEY-----\n",
	}
	if err := svc.db.Create(cert).Error; err != nil {
		t.Fatal(err)
	}
	certID := cert.ID.String()
	in := &model.Inbound{
		Name: "hy2", Type: "hysteria2", Port: 443, Status: model.StatusEnabled,
		IsUserInbound: true, CertID: &certID,
		TLS: json.RawMessage(`{"enabled":true,"server_name":"example.com"}`),
	}
	if err := svc.db.Create(in).Error; err != nil {
		t.Fatal(err)
	}
	doc, err := svc.Generate(ctx)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	ins := doc["inbounds"].([]map[string]any)
	if len(ins) != 1 {
		t.Fatalf("inbounds = %d", len(ins))
	}
	tls, ok := ins[0]["tls"].(map[string]any)
	if !ok {
		t.Fatalf("tls missing: %v", ins[0])
	}
	wantCert, wantKey := svc.kernel.CertPaths(certID)
	if tls["certificate_path"] != wantCert || tls["key_path"] != wantKey {
		t.Fatalf("tls paths = %v / %v, want %s / %s", tls["certificate_path"], tls["key_path"], wantCert, wantKey)
	}
	if _, err := os.Stat(wantCert); err != nil {
		t.Fatalf("cert file not written: %v", err)
	}
	if fi, err := os.Stat(wantKey); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode/err: %v %v", fi, err)
	}
}
