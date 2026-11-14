// Package model 定义 cx-box 的核心数据模型（单体单机）。
package model

import (
	"time"
)

// TrafficRecord 流量时序记录（单体单机，无 NodeID）。
// 使用组合主键：时间桶 + 客户端 ID + 入站 tag。
type TrafficRecord struct {
	Ts          time.Time `gorm:"type:datetime;not null;primaryKey" json:"ts"` // 时间桶
	ClientID    string    `gorm:"type:text;not null;primaryKey" json:"client_id"`
	InboundTag  string    `gorm:"type:varchar(64);not null;primaryKey" json:"inbound_tag"`
	UpBytes     int64     `gorm:"not null;default:0" json:"up_bytes"`
	DownBytes   int64     `gorm:"not null;default:0" json:"down_bytes"`
}

// TableName 返回表名。
func (TrafficRecord) TableName() string { return "traffic_records" }
