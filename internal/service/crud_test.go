package service

import (
	"encoding/json"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/model"
)

func newCRUDTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	g, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := g.AutoMigrate(&model.Inbound{}, &model.Outbound{}, &model.Client{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return g
}

func TestInboundServiceValidation(t *testing.T) {
	svc := NewInboundService(newCRUDTestDB(t))

	// 合法：vless 用户入口
	good := &model.Inbound{Name: "vless-in", Type: "vless", Port: 443, IsUserInbound: true}
	if err := svc.Create(good); err != nil {
		t.Fatalf("create valid inbound: %v", err)
	}
	if good.ID.String() == "" || good.Status != model.StatusEnabled {
		t.Fatalf("id/status not set: %+v", good)
	}

	// 非法协议
	if err := svc.Create(&model.Inbound{Name: "x", Type: "nope", Port: 1}); err == nil {
		t.Fatal("unknown protocol should fail")
	}
	// 非法端口
	if err := svc.Create(&model.Inbound{Name: "y", Type: "vless", Port: 0, IsUserInbound: true}); err == nil {
		t.Fatal("port 0 should fail")
	}
	// 同名（uniqueIndex）
	if err := svc.Create(&model.Inbound{Name: "vless-in", Type: "vless", Port: 8443, IsUserInbound: true}); err == nil {
		t.Fatal("duplicate name should fail")
	}
}

func TestClientServiceAutoFillAndUniqueness(t *testing.T) {
	svc := NewClientService(newCRUDTestDB(t))
	c := &model.Client{Email: "a@example.com", Enable: true}
	if err := svc.Create(c); err != nil {
		t.Fatalf("create client: %v", err)
	}
	if c.UUID == "" || c.SubID == "" {
		t.Fatalf("uuid/sub_id should be auto-generated: %+v", c)
	}
	pw := c.Password
	if pw == "" {
		t.Fatal("password should be auto-generated")
	}
	if err := svc.Create(&model.Client{Email: "a@example.com"}); err == nil {
		t.Fatal("duplicate email should fail")
	}
	got, err := svc.GetBySubID(c.SubID)
	if err != nil || got.Email != "a@example.com" {
		t.Fatalf("get by sub id: %v %+v", err, got)
	}
	// 设置 JSON 应可往返（订阅/渲染依赖）
	if _, err := json.Marshal(got); err != nil {
		t.Fatal(err)
	}
}
