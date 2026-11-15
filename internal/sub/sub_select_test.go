package sub

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/model"
	"github.com/sle58083/cx-box/internal/service"
)

// TestLinksInboundSelection 客户端入站选择（多选/单选/不限）在订阅侧的过滤。
func TestLinksInboundSelection(t *testing.T) {
	g, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := g.AutoMigrate(&model.Inbound{}, &model.Client{}, &model.Certificate{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	inSvc := service.NewInboundService(g)
	ssSettings := json.RawMessage(`{"method":"aes-128-gcm"}`)
	var idA, idB string
	for _, in := range []*model.Inbound{
		{Name: "ss-a", Type: "shadowsocks", Port: 8388, IsUserInbound: true, Settings: ssSettings},
		{Name: "ss-b", Type: "shadowsocks", Port: 8389, IsUserInbound: true, Settings: ssSettings},
	} {
		if err := inSvc.Create(in); err != nil {
			t.Fatalf("create inbound %s: %v", in.Name, err)
		}
		if in.Name == "ss-a" {
			idA = in.ID.String()
		} else {
			idB = in.ID.String()
		}
	}
	clSvc := service.NewClientService(g)
	mkClient := func(email string, mutate func(*model.Client)) *model.Client {
		c := &model.Client{Email: email, Enable: true}
		if mutate != nil {
			mutate(c)
		}
		if err := clSvc.Create(c); err != nil {
			t.Fatalf("create client %s: %v", email, err)
		}
		return c
	}
	linksOf := func(c *model.Client) []string {
		links, _, err := New(g).Links(c.SubID, "example.com")
		if err != nil {
			t.Fatalf("links %s: %v", c.Email, err)
		}
		return links
	}

	// 多选只选 B → 只有 B 的链接。
	multi := mkClient("multi@example.com", func(c *model.Client) { c.SetInboundIDs([]string{idB}) })
	if links := linksOf(multi); len(links) != 1 || !strings.Contains(links[0], "#ss-b") {
		t.Fatalf("multi-select should yield only ss-b: %v", links)
	}
	// 旧单选绑 A → 只有 A 的链接。
	single := mkClient("single@example.com", func(c *model.Client) { c.InboundID = &idA })
	if links := linksOf(single); len(links) != 1 || !strings.Contains(links[0], "#ss-a") {
		t.Fatalf("single binding should yield only ss-a: %v", links)
	}
	// 不选 → 全部用户入站。
	all := mkClient("all@example.com", nil)
	if links := linksOf(all); len(links) != 2 {
		t.Fatalf("no selection should yield both inbounds: %v", links)
	}
}
