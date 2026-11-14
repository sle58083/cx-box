// Package model 定义 cx-box 的核心数据模型（单体单机）。
package model

import (
	"encoding/json"
)

// Inbound 入站配置（中立模型），与 sing-box 原生 JSON Schema 解耦。
// 单体单机：无 GroupID/NodeID（对标 s-ui 的 inbound）。
type Inbound struct {
	Base
	Name          string          `gorm:"type:varchar(64);not null;uniqueIndex" json:"name"` // 即 sing-box tag
	Type          string          `gorm:"type:varchar(32);not null" json:"type"`
	Listen        string          `gorm:"type:varchar(64)" json:"listen"`
	Port          int             `gorm:"not null;default:0" json:"port"`
	Settings      json.RawMessage `gorm:"type:text" json:"settings"`      // 协议参数（clients/users 等）
	TLS           json.RawMessage `gorm:"type:text" json:"tls"`           // TLS/Reality 配置，private_key 等私钥加密
	CertID        *string         `gorm:"type:text;index" json:"cert_id"` // 绑定的证书（certificate.id），可空
	Transport     json.RawMessage `gorm:"type:text" json:"transport"`
	IsUserInbound bool            `gorm:"not null;default:false" json:"is_user_inbound"` // 是否客户端入口，生成时注入用户 UUID
	Status        string          `gorm:"type:varchar(16);not null;default:'enabled'" json:"status"`
}

// TableName 返回表名。
func (Inbound) TableName() string { return "inbounds" }
