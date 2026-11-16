// Package model 定义 cx-box 的核心数据模型（单体单机）。
package model

import (
	"encoding/json"
)

// RoutingRule 路由规则（中立模型）。
type RoutingRule struct {
	Base
	Name        string          `gorm:"type:varchar(64);not null" json:"name"`
	InboundTags json.RawMessage `gorm:"type:text" json:"inbound_tags"` // 入站 tag 数组
	OutboundTag string          `gorm:"type:varchar(64)" json:"outbound_tag"`
	RuleType    string          `gorm:"type:varchar(16)" json:"rule_type"` // geosite/geoip/domain/ip/protocol
	Value       string          `gorm:"type:text" json:"value"`
	Priority    int             `gorm:"not null;default:0" json:"priority"`
	Enabled     bool            `gorm:"not null;default:true" json:"enabled"`

	// 以下字段仅供内存合成规则使用（不落库）：IP 数限制的封锁规则需要
	// 同时按认证用户组与来源 IP 匹配，超出中立模型的单字段表达能力。
	AuthUsers    []string `gorm:"-" json:"-"`
	SourceIPCIDR string   `gorm:"-" json:"-"`
}

// TableName 返回表名。
func (RoutingRule) TableName() string { return "routing_rules" }
