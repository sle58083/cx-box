package configsvc

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sle58083/cx-box/internal/model"
	"github.com/sle58083/cx-box/internal/renderer"
)

// TestResolveCertBindingsSkipsReality 复现真机事故：vless 入站开了
// Reality 又绑了证书时，证书路径绝不能注入 TLS——sing-box 会以
// "certificate is unavailable in reality" 拒绝整份配置，导致内核
// 一直跑旧配置、新客户端全部连不上。普通 TLS 入站照常注入。
func TestResolveCertBindingsSkipsReality(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	cert := model.Certificate{
		Name:    "测试证书",
		Type:    "manual",
		CertPEM: "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----",
		KeyPEM:  "-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----",
	}
	if err := s.db.WithContext(ctx).Create(&cert).Error; err != nil {
		t.Fatal(err)
	}
	certID := cert.ID.String()

	realityTLS := json.RawMessage(`{"enabled":true,"server_name":"www.microsoft.com","reality":{"enabled":true,"handshake":{"server":"www.microsoft.com","server_port":443},"private_key":"abc","short_id":[""]}}`)
	plainTLS := json.RawMessage(`{"enabled":true,"server_name":"example.com"}`)
	inbounds := []model.Inbound{
		{Name: "vless-reality", Type: "vless", TLS: realityTLS, CertID: &certID},
		{Name: "trojan-plain", Type: "trojan", TLS: plainTLS, CertID: &certID},
	}
	if err := s.resolveCertBindings(ctx, inbounds); err != nil {
		t.Fatalf("resolveCertBindings: %v", err)
	}
	var vlessTLS map[string]any
	if err := json.Unmarshal(inbounds[0].TLS, &vlessTLS); err != nil {
		t.Fatal(err)
	}
	if _, ok := vlessTLS["certificate_path"]; ok {
		t.Fatalf("Reality 入站被注入 certificate_path: %s", inbounds[0].TLS)
	}
	if _, ok := vlessTLS["key_path"]; ok {
		t.Fatalf("Reality 入站被注入 key_path: %s", inbounds[0].TLS)
	}
	var trojanTLS map[string]any
	if err := json.Unmarshal(inbounds[1].TLS, &trojanTLS); err != nil {
		t.Fatal(err)
	}
	if _, ok := trojanTLS["certificate_path"]; !ok {
		t.Fatalf("普通 TLS 入站应注入 certificate_path: %s", inbounds[1].TLS)
	}
}

// TestActiveUsersDerived 覆盖派生用户生成：选了多个出口的客户端在
// activeUsers 里除基础用户外，每个出口多一个派生用户，凭据与
// renderer 推导一致、路由字段指向单个出口。
func TestActiveUsersDerived(t *testing.T) {
	s := newTestService(t)
	ctx := context.Background()

	ob1, ob2 := model.NewID(), model.NewID()
	c := model.Client{
		Email:  "multi@example.com",
		UUID:   "11111111-2222-3333-4444-555555555555",
		Enable: true,
	}
	c.Password = "base-password-0123456789"
	c.SetOutboundIDs([]string{ob1.String(), ob2.String()})
	if err := s.db.WithContext(ctx).Create(&c).Error; err != nil {
		t.Fatal(err)
	}

	users, err := s.activeUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 3 {
		t.Fatalf("users = %d, want 3 (base + 2 derived)", len(users))
	}
	byName := map[string]renderer.ProxyUser{}
	for _, u := range users {
		byName[u.Name] = u
	}
	cid := c.ID.String()
	if _, ok := byName[cid]; !ok {
		t.Fatalf("基础用户缺失: %v", byName)
	}
	for _, obID := range []string{ob1.String(), ob2.String()} {
		du, ok := byName[renderer.DerivedUserName(cid, obID)]
		if !ok {
			t.Fatalf("派生用户缺失 (%s): %v", obID, byName)
		}
		if du.UUID != renderer.DerivedUUID(c.UUID, obID) {
			t.Fatalf("派生 UUID 不一致: %s", du.UUID)
		}
		wantPw := renderer.DerivedPassword(c.Password, obID)
		if du.Password != wantPw {
			t.Fatalf("派生密码不一致")
		}
		if len(du.OutboundIDs) != 1 || du.OutboundIDs[0] != obID || du.OutboundID != obID {
			t.Fatalf("派生用户路由字段错误: %+v", du)
		}
		if !strings.Contains(du.Name, renderer.DerivedSep) {
			t.Fatalf("派生用户名应含分隔符: %s", du.Name)
		}
	}
}
