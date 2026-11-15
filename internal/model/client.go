// Package model 定义 cx-box 的核心数据模型（单体单机）。
package model

import "encoding/json"

// Client 客户端（终端用户），对标 s-ui 的 client 概念。
type Client struct {
	Base
	Email         string  `gorm:"type:varchar(255);index" json:"email"` // 唯一标识（s-ui 用 email 区分客户端）
	UUID          string  `gorm:"type:text" json:"-"`                   // 🔐 vless/vmess 用户 UUID，加密存储
	Password      string  `gorm:"type:text" json:"-"`                   // 🔐 协议明文密码，加密存储
	Enable        bool    `gorm:"not null;default:true" json:"enable"`
	LimitIP       int     `gorm:"not null;default:0" json:"limit_ip"`         // 限制 IP 数（0=不限）
	TotalGB       int64   `gorm:"not null;default:0" json:"total_gb"`         // 流量上限（GB，0=无限）
	ExpiryTime    int64   `gorm:"not null;default:0" json:"expiry_time"`      // 到期时间戳（0=永不过期）
	UsedBytes     int64   `gorm:"not null;default:0" json:"used_bytes"`       // 已用流量
	SubID         string  `gorm:"type:varchar(64);uniqueIndex" json:"sub_id"` // 订阅 ID（用于订阅链接）
	Comment       string  `gorm:"type:varchar(255)" json:"comment"`
	InboundID     *string `gorm:"type:text;index" json:"inbound_id"`      // 绑定的入站（可空=全部用户入口入站）
	InboundIDs    string  `gorm:"type:text" json:"-"`                     // 多选入站 ID 列表（JSON []string）；非空时优先于 InboundID
	ResetStrategy string  `gorm:"type:varchar(32)" json:"reset_strategy"` // 流量重置策略（s-ui 兼容字段）
}

// SelectedInboundIDs 返回客户端选中的入站 ID 列表：多选（InboundIDs）优先，
// 其次旧的单选绑定（InboundID）；都为空返回 nil，表示适用全部用户入口入站。
// 订阅生成与内核用户注入共用这一份判定，保证两边看到的节点集合一致。
func (c *Client) SelectedInboundIDs() []string {
	if c.InboundIDs != "" {
		var ids []string
		if err := json.Unmarshal([]byte(c.InboundIDs), &ids); err == nil && len(ids) > 0 {
			return ids
		}
	}
	if c.InboundID != nil && *c.InboundID != "" {
		return []string{*c.InboundID}
	}
	return nil
}

// SetInboundIDs 写入多选入站列表（空列表表示清除多选）。
func (c *Client) SetInboundIDs(ids []string) {
	if len(ids) == 0 {
		c.InboundIDs = ""
		return
	}
	raw, err := json.Marshal(ids)
	if err != nil {
		return
	}
	c.InboundIDs = string(raw)
}

// TableName 返回表名。
func (Client) TableName() string { return "clients" }
