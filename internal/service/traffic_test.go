package service

import (
	"context"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/model"
)

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	g, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := g.AutoMigrate(&model.Client{}, &model.TrafficRecord{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return g
}

func TestTrafficRecordUsageAccumulates(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	client := &model.Client{Email: "a@example.com", SubID: "sub-a"}
	client.ID = model.NewID()
	if err := db.Create(client).Error; err != nil {
		t.Fatalf("create client: %v", err)
	}
	svc := NewTrafficService(db)
	deltas := []UsageDelta{{ClientID: client.ID.String(), InboundTag: "vless-in", Up: 100, Down: 200}}
	if err := svc.RecordUsage(ctx, deltas); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	if err := svc.RecordUsage(ctx, deltas); err != nil {
		t.Fatalf("RecordUsage(2): %v", err)
	}

	var got model.Client
	if err := db.First(&got, "id = ?", client.ID).Error; err != nil {
		t.Fatal(err)
	}
	if got.UsedBytes != 600 {
		t.Fatalf("used_bytes = %d, want 600", got.UsedBytes)
	}
	var recs []model.TrafficRecord
	if err := db.Find(&recs).Error; err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].UpBytes != 200 || recs[0].DownBytes != 400 {
		t.Fatalf("records = %+v, want one hourly bucket 200/400", recs)
	}
	up, down, err := svc.Totals(ctx)
	if err != nil || up != 200 || down != 400 {
		t.Fatalf("Totals = %d/%d err=%v", up, down, err)
	}

	// 入站级（无客户端）增量只写时序、不碰 clients。
	if err := svc.RecordUsage(ctx, []UsageDelta{{ClientID: "", InboundTag: "ss-in", Up: 5, Down: 6}}); err != nil {
		t.Fatalf("RecordUsage inbound-level: %v", err)
	}
	up, down, _ = svc.Totals(ctx)
	if up != 205 || down != 406 {
		t.Fatalf("Totals after inbound-level = %d/%d, want 205/406", up, down)
	}
}

func TestTrafficOverQuotaCount(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	over := &model.Client{Email: "over@example.com", SubID: "sub-over", Enable: true, TotalGB: 1, UsedBytes: 1024 * 1024 * 1024}
	over.ID = model.NewID()
	under := &model.Client{Email: "under@example.com", SubID: "sub-under", Enable: true, TotalGB: 1, UsedBytes: 10}
	under.ID = model.NewID()
	if err := db.Create(over).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(under).Error; err != nil {
		t.Fatal(err)
	}
	n, err := NewTrafficService(db).OverQuotaCount(ctx)
	if err != nil || n != 1 {
		t.Fatalf("OverQuotaCount = %d err=%v, want 1", n, err)
	}
}
