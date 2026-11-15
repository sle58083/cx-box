package sub

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/model"
	"github.com/sle58083/cx-box/internal/service"
)

func seed(t *testing.T) (*Generator, *model.Client) {
	t.Helper()
	g, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := g.AutoMigrate(&model.Inbound{}, &model.Client{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	inSvc := service.NewInboundService(g)
	if err := inSvc.Create(&model.Inbound{
		Name: "vless-main", Type: "vless", Port: 443, IsUserInbound: true,
	}); err != nil {
		t.Fatalf("seed inbound: %v", err)
	}
	// 非用户入口不应出现在未绑定客户端的订阅里
	if err := inSvc.Create(&model.Inbound{
		Name: "ss-static", Type: "shadowsocks", Port: 8388,
		Settings: []byte(`{"method":"aes-128-gcm","password":"staticpw"}`),
	}); err != nil {
		t.Fatalf("seed ss inbound: %v", err)
	}
	clSvc := service.NewClientService(g)
	c := &model.Client{Email: "user@example.com", Enable: true}
	if err := clSvc.Create(c); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	return New(g), c
}

func TestLinksForClient(t *testing.T) {
	gen, c := seed(t)
	links, client, err := gen.Links(c.SubID, "example.com")
	if err != nil {
		t.Fatalf("links: %v", err)
	}
	if client.Email != "user@example.com" {
		t.Fatalf("client = %+v", client)
	}
	if len(links) != 1 {
		t.Fatalf("links = %v, want exactly the vless user inbound", links)
	}
	link := links[0]
	if !strings.HasPrefix(link, "vless://") ||
		!strings.Contains(link, "@example.com:443") ||
		!strings.Contains(link, c.UUID) ||
		!strings.HasSuffix(link, "#vless-main") {
		t.Fatalf("unexpected link: %s", link)
	}
}

func TestLinksUnknownAndDisabled(t *testing.T) {
	gen, c := seed(t)
	if _, _, err := gen.Links("not-exist", "example.com"); err == nil {
		t.Fatal("unknown sub id should fail")
	}
	clSvc := service.NewClientService(gen.db)
	c.Enable = false
	if err := clSvc.Update(c); err != nil {
		t.Fatal(err)
	}
	if _, _, err := gen.Links(c.SubID, "example.com"); err == nil {
		t.Fatal("disabled client should fail")
	}
}

func TestDeriveRealityPublic(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	privStr := enc.EncodeToString(priv.Bytes())
	wantPub := enc.EncodeToString(priv.PublicKey().Bytes())
	in := model.Inbound{
		Name: "vless-in", Type: "vless", Port: 443,
		TLS: json.RawMessage(`{"enabled":true,"server_name":"www.microsoft.com","reality":{"enabled":true,"private_key":"` + privStr + `","short_id":["ab12"]}}`),
	}
	out, err := inboundAsOutbound(in, "203.0.113.7")
	if err != nil {
		t.Fatalf("inboundAsOutbound: %v", err)
	}
	var tls map[string]any
	if err := json.Unmarshal(out.TLS, &tls); err != nil {
		t.Fatal(err)
	}
	reality := tls["reality"].(map[string]any)
	if reality["public_key"] != wantPub {
		t.Fatalf("public_key = %v, want %v", reality["public_key"], wantPub)
	}
	if reality["short_id"] != "ab12" {
		t.Fatalf("short_id = %v", reality["short_id"])
	}
}
