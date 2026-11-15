package service

import (
	"strings"
	"testing"

	"github.com/sle58083/cx-box/internal/model"
)

// TestNameUniqueAcrossInOut 名称（tag）在入站/出站间全局唯一，重复时给中文提示
// 而不是数据库的 UNIQUE constraint 英文报错。
func TestNameUniqueAcrossInOut(t *testing.T) {
	g := newCRUDTestDB(t)
	inSvc := NewInboundService(g)
	outSvc := NewOutboundService(g)

	if err := inSvc.Create(&model.Inbound{Name: "yu", Type: "vless", Port: 443, IsUserInbound: true}); err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	// 同名入站 → 中文提示。
	err := inSvc.Create(&model.Inbound{Name: "yu", Type: "shadowsocks", Port: 8388, IsUserInbound: true,
		Settings: []byte(`{"method":"aes-128-gcm"}`)})
	if err == nil || !strings.Contains(err.Error(), "已被其他入站占用") {
		t.Fatalf("duplicate inbound name should give friendly error, got: %v", err)
	}
	if strings.Contains(err.Error(), "UNIQUE") {
		t.Fatalf("raw DB error leaked: %v", err)
	}
	// 同名出站 → 跨表占用提示。
	err = outSvc.Create(&model.Outbound{Name: "yu", Type: "direct"})
	if err == nil || !strings.Contains(err.Error(), "已被入站占用") {
		t.Fatalf("cross-table duplicate should be reported, got: %v", err)
	}
	// 不同名出站正常。
	if err := outSvc.Create(&model.Outbound{Name: "dir1", Type: "direct"}); err != nil {
		t.Fatalf("create outbound: %v", err)
	}
	// 更新为自己原名不算占用。
	list, err := inSvc.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %v", list, err)
	}
	upd := list[0]
	upd.Port = 8443
	if err := inSvc.Update(&upd); err != nil {
		t.Fatalf("update keeping own name should pass: %v", err)
	}
}

// TestNormalizeNullRawJSON 客户端把空字段发成 JSON null 时，落库前要归一
// 为空，否则读取方 Unmarshal 出 nil map 会 panic。
func TestNormalizeNullRawJSON(t *testing.T) {
	svc := NewInboundService(newCRUDTestDB(t))
	in := &model.Inbound{Name: "n1", Type: "vless", Port: 443, IsUserInbound: true,
		Settings: []byte("null"), TLS: []byte("null"), Transport: []byte("null")}
	if err := svc.Create(in); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := svc.Get(in.ID.String())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.Settings) != 0 || len(got.TLS) != 0 || len(got.Transport) != 0 {
		t.Fatalf("null raw fields should be normalized to empty, got settings=%s tls=%s transport=%s",
			got.Settings, got.TLS, got.Transport)
	}
}
