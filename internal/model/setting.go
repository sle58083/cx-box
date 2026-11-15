// Package model 定义 cx-box 的核心数据模型。
package model

import "time"

// Setting 面板全局设置（单行，对标 s-ui settings）。
type Setting struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	PanelPort   int       `gorm:"not null;default:2095" json:"panel_port"`
	PanelPath   string    `gorm:"not null;default:'/app/'" json:"panel_path"`
	SubPort     int       `gorm:"not null;default:2096" json:"sub_port"`
	SubPath     string    `gorm:"not null;default:'/sub/'" json:"sub_path"`
	WebBasePath string    `gorm:"not null;default:'/'" json:"web_base_path"`
	APISecret   string    `gorm:"type:varchar(64)" json:"-"` // sing-box api service 密钥（内部流量统计用，绝不下发）
	UpdatedAt   time.Time `json:"updated_at"`
}

// TableName 指定单例设置表名。
func (Setting) TableName() string { return "settings" }
