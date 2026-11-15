// Package service 提供设置与账号的业务逻辑。
package service

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/sle58083/cx-box/internal/model"
)

// UsageDelta 是一笔待落库的流量增量（采集器按连接事件聚合后批量提交）。
type UsageDelta struct {
	ClientID   string // sing-box 连接的 user 名即客户端 ID；空 = 无法归因到客户端（仅入站级统计）
	InboundTag string
	Up         int64
	Down       int64
}

// TrafficService 承接流量落库：客户端累计用量 + 小时粒度时序记录。
type TrafficService struct {
	db *gorm.DB
}

// NewTrafficService 构造流量服务。
func NewTrafficService(db *gorm.DB) *TrafficService { return &TrafficService{db: db} }

// RecordUsage 在一个事务里累加一批增量：
//   - clients.used_bytes += up+down（订阅 userinfo 头与配额判断都读它）
//   - traffic_records 按小时桶 upsert（同桶同客户端同入站累加）
func (s *TrafficService) RecordUsage(ctx context.Context, deltas []UsageDelta) error {
	bucket := time.Now().Truncate(time.Hour)
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, d := range deltas {
			if d.Up+d.Down <= 0 {
				continue
			}
			if d.ClientID != "" {
				if err := tx.Model(&model.Client{}).Where("id = ?", d.ClientID).
					UpdateColumn("used_bytes", gorm.Expr("used_bytes + ?", d.Up+d.Down)).Error; err != nil {
					return fmt.Errorf("traffic: 累加客户端用量失败: %w", err)
				}
			}
			rec := model.TrafficRecord{
				Ts:         bucket,
				ClientID:   d.ClientID,
				InboundTag: d.InboundTag,
				UpBytes:    d.Up,
				DownBytes:  d.Down,
			}
			err := tx.Clauses(clause.OnConflict{
				Columns: []clause.Column{{Name: "ts"}, {Name: "client_id"}, {Name: "inbound_tag"}},
				DoUpdates: clause.Assignments(map[string]any{
					"up_bytes":   gorm.Expr("up_bytes + ?", d.Up),
					"down_bytes": gorm.Expr("down_bytes + ?", d.Down),
				}),
			}).Create(&rec).Error
			if err != nil {
				return fmt.Errorf("traffic: 写时序记录失败: %w", err)
			}
		}
		return nil
	})
}

// OverQuotaCount 返回「已启用但用量已达上限」的客户端数量。
// 采集器据此触发重新应用配置，把超额客户端从内核配置里剔除。
func (s *TrafficService) OverQuotaCount(ctx context.Context) (int64, error) {
	var n int64
	err := s.db.WithContext(ctx).Model(&model.Client{}).
		Where("enable = ? AND total_gb > 0 AND used_bytes >= total_gb * 1073741824", true).
		Count(&n).Error
	return n, err
}

// Totals 返回全部时序记录累计的上/下行字节数（状态页展示用）。
func (s *TrafficService) Totals(ctx context.Context) (up, down int64, err error) {
	var row struct {
		Up   int64
		Down int64
	}
	err = s.db.WithContext(ctx).Model(&model.TrafficRecord{}).
		Select("COALESCE(SUM(up_bytes),0) AS up, COALESCE(SUM(down_bytes),0) AS down").
		Scan(&row).Error
	return row.Up, row.Down, err
}
