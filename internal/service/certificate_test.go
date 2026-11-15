package service

import (
	"context"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/model"
)

func certTestDB(t *testing.T) *CertificateService {
	t.Helper()
	g, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := g.AutoMigrate(&model.Certificate{}, &model.Inbound{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return NewCertificateService(g)
}

func TestSelfSignedCert(t *testing.T) {
	svc := certTestDB(t)
	ctx := context.Background()
	c, err := svc.SelfSigned(ctx, "ss", []string{"example.com", "1.2.3.4"}, 365)
	if err != nil {
		t.Fatalf("SelfSigned: %v", err)
	}
	if c.Type != "self_signed" || c.Status != "valid" {
		t.Fatalf("type/status = %s/%s", c.Type, c.Status)
	}
	if !strings.Contains(c.Domains, "example.com") || !strings.Contains(c.Domains, "1.2.3.4") {
		t.Fatalf("domains = %s", c.Domains)
	}
	if c.NotAfter == nil || c.NotBefore == nil {
		t.Fatal("validity not filled")
	}
	// API 序列化不得带出 PEM
	list, err := svc.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %v, %v", len(list), err)
	}
}

func TestManualImportMismatchRejected(t *testing.T) {
	svc := certTestDB(t)
	ctx := context.Background()
	a, err := svc.SelfSigned(ctx, "a", []string{"a.com"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.SelfSigned(ctx, "b", []string{"b.com"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	fullA, _ := svc.Get(ctx, a.ID.String())
	fullB, _ := svc.Get(ctx, b.ID.String())
	if _, err := svc.Create(ctx, "bad", fullA.CertPEM, fullB.KeyPEM); err == nil {
		t.Fatal("mismatched pair should be rejected")
	}
	okCert, err := svc.Create(ctx, "good", fullA.CertPEM, fullA.KeyPEM)
	if err != nil {
		t.Fatalf("matching pair rejected: %v", err)
	}
	if okCert.Type != "manual" {
		t.Fatalf("type = %s", okCert.Type)
	}
}

func TestDeleteReferencedCertBlocked(t *testing.T) {
	svc := certTestDB(t)
	ctx := context.Background()
	c, err := svc.SelfSigned(ctx, "ss", nil, 30)
	if err != nil {
		t.Fatal(err)
	}
	id := c.ID.String()
	in := &model.Inbound{Name: "hy2", Type: "hysteria2", Port: 443, CertID: &id, Status: "enabled"}
	in.ID = model.NewID()
	if err := svc.db.Create(in).Error; err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, id); err == nil {
		t.Fatal("deleting referenced cert should fail")
	}
	if err := svc.db.Delete(in).Error; err != nil {
		t.Fatal(err)
	}
	if err := svc.Delete(ctx, id); err != nil {
		t.Fatalf("delete after unbind: %v", err)
	}
}
