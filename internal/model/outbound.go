// Package model 定义 cx-box 的核心数据模型（单体单机）。
package model

import (
	"encoding/json"
)

// Outbound 出站配置（中立模型）。
type Outbound struct {
	Base
	Name      string          `gorm:"type:varchar(64);not null;uniqueIndex" json:"name"` // 即 sing-box tag
	Type      string          `gorm:"type:varchar(32);not null" json:"type"`
	Settings  json.RawMessage `gorm:"type:text" json:"settings"`  // 出站参数，服务器密码等敏感值加密
	TLS       json.RawMessage `gorm:"type:text" json:"tls"`       // 出站 TLS/Reality，private_key 等私钥加密
	Transport json.RawMessage `gorm:"type:text" json:"transport"` // 出站传输层配置 ws/grpc/httpupgrade 等
	Status    string          `gorm:"type:varchar(16);not null;default:'enabled'" json:"status"`
}

// TableName 返回表名。
func (Outbound) TableName() string { return "outbounds" }
