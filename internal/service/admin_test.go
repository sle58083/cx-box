package service

import (
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/model"
)

func newAdminTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	g, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := g.AutoMigrate(&model.Admin{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return g
}

func TestEnsureDefaultCreatesAdminOnce(t *testing.T) {
	svc := NewAdminService(newAdminTestDB(t))
	if err := svc.EnsureDefault(); err != nil {
		t.Fatal(err)
	}
	if err := svc.EnsureDefault(); err != nil {
		t.Fatal(err)
	}
	a, err := svc.Get()
	if err != nil {
		t.Fatal(err)
	}
	if a.Username != "admin" {
		t.Fatalf("username = %q, want admin", a.Username)
	}
	if !svc.Verify("admin", "admin") {
		t.Fatal("default admin/admin should verify")
	}
}

// 安装脚本的 `cx-box admin -username X -password Y` 必须改名到唯一的管理员行上：
// 改名后表里仍只能有一行，且 -show（Get）看到的是新用户名。
func TestSetCredentialsRenamesSingleAdmin(t *testing.T) {
	g := newAdminTestDB(t)
	svc := NewAdminService(g)
	if err := svc.EnsureDefault(); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetCredentials("randomuser", "randompass"); err != nil {
		t.Fatal(err)
	}
	var cnt int64
	g.Model(&model.Admin{}).Count(&cnt)
	if cnt != 1 {
		t.Fatalf("admin rows = %d, want 1", cnt)
	}
	a, err := svc.Get()
	if err != nil {
		t.Fatal(err)
	}
	if a.Username != "randomuser" {
		t.Fatalf("username = %q, want randomuser", a.Username)
	}
	if !svc.Verify("randomuser", "randompass") {
		t.Fatal("new credentials should verify")
	}
	if svc.Verify("admin", "admin") {
		t.Fatal("old credentials must not verify after rename")
	}
}

func TestSetCredentialsRejectsEmpty(t *testing.T) {
	svc := NewAdminService(newAdminTestDB(t))
	if err := svc.SetCredentials("", "x"); err == nil {
		t.Fatal("empty username should fail")
	}
	if err := svc.SetCredentials("x", ""); err == nil {
		t.Fatal("empty password should fail")
	}
}
