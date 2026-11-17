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
	// SubNodeHost 订阅节点地址覆盖：非空时订阅/导出链接里的节点服务器
	// 地址固定用它，不再跟随拉订阅请求的主机名（订阅走 Cloudflare
	// 中转、节点走直连域名时用）。空 = 跟随访问地址（默认行为）。
	SubNodeHost string `gorm:"type:varchar(255);not null;default:''" json:"sub_node_host"`
	// ACME 自动证书（Let's Encrypt + Cloudflare DNS 验证）配置。
	// 列名显式指定：GORM 对 ACMECFToken 这类连续大写字段名的默认
	// 蛇形转换与手写 map 更新的键容易不一致，钉死列名避免踩坑。
	ACMEEmail      string    `gorm:"column:acme_email;type:varchar(128);not null;default:''" json:"acme_email"`
	ACMECFToken    string    `gorm:"column:acme_cf_token;type:text" json:"-"`    // 🔐 Cloudflare API 令牌，绝不下发
	ACMEAccountKey string    `gorm:"column:acme_account_key;type:text" json:"-"` // 🔐 ACME 账户私钥 PEM，绝不下发
	UpdatedAt      time.Time `json:"updated_at"`
}

// TableName 指定单例设置表名。
func (Setting) TableName() string { return "settings" }
