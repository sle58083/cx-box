package configsvc

import (
	"context"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/model"
)

func TestGeneratorInjectsAPIService(t *testing.T) {
	gen := NewGenerator()
	doc, err := gen.Generate(&NodeConfigContext{APISecret: "s3cr3t"})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	svcs, ok := doc["services"].([]map[string]any)
	if !ok || len(svcs) != 1 {
		t.Fatalf("services = %v, want one api service", doc["services"])
	}
	s := svcs[0]
	if s["type"] != "api" || s["listen"] != "127.0.0.1" || s["listen_port"] != DefaultAPIPort || s["secret"] != "s3cr3t" {
		t.Fatalf("api service = %v", s)
	}

	doc2, err := gen.Generate(&NodeConfigContext{})
	if err != nil {
		t.Fatalf("Generate(no secret): %v", err)
	}
	if _, ok := doc2["services"]; ok {
		t.Fatalf("services must be absent without a secret: %v", doc2["services"])
	}
}

func TestActiveUsersFiltersExpiredAndOverQuota(t *testing.T) {
	g, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := g.AutoMigrate(&model.Client{}); err != nil {
		t.Fatal(err)
	}
	mk := func(email string, mutate func(*model.Client)) *model.Client {
		c := &model.Client{Email: email, SubID: "sub-" + email, Enable: true}
		c.ID = model.NewID()
		if mutate != nil {
			mutate(c)
		}
		if err := g.Create(c).Error; err != nil {
			t.Fatal(err)
		}
		return c
	}
	good := mk("good@x", nil)
	mk("expired@x", func(c *model.Client) { c.ExpiryTime = time.Now().Add(-time.Hour).Unix() })
	mk("over@x", func(c *model.Client) { c.TotalGB = 1; c.UsedBytes = 2 * 1024 * 1024 * 1024 })
	// 注：不测 enable=false——GORM 对带 default:true 的 bool 零值在 Create 时
	// 会套用数据库默认值，测试里造不出可靠的禁用行；enable 过滤在 SQL 层。

	svc := NewService(g, nil)
	users, err := svc.activeUsers(context.Background())
	if err != nil {
		t.Fatalf("activeUsers: %v", err)
	}
	if len(users) != 1 || users[0].ID != good.ID.String() {
		t.Fatalf("users = %+v, want only the good client", users)
	}
}
