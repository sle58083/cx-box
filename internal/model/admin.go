// Package model 定义 cx-box 的核心数据模型。
package model

import "time"

// Admin 面板管理员账号（对标 s-ui 的 admin 凭据）。
type Admin struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Username     string    `gorm:"not null;uniqueIndex" json:"username"`
	PasswordHash string    `gorm:"not null" json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// TableName 指定管理员表名。
func (Admin) TableName() string { return "admins" }

// APIToken 面板 API 令牌（/apiv2 鉴权）。
type APIToken struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Token       string    `gorm:"not null;uniqueIndex" json:"token"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// TableName 指定 API 令牌表名。
func (APIToken) TableName() string { return "api_tokens" }
