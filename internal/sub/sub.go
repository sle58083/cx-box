// Package sub 生成客户端订阅内容（分享链接列表）。
//
// 单体面板的订阅来源是本机入站：把每个启用的用户入站转换成一个「出站视图」
// （在入站 Settings 里注入 server=<订阅访问主机>、server_port=<入站端口>），
// 再复用 renderer 的 SubscriptionURI 生成各协议分享链接 —— 协议编码规则仍由
// 渲染器唯一负责，本包只做视图转换与客户端状态校验。
package sub

import (
	"encoding/json"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/model"
	"github.com/sle58083/cx-box/internal/renderer"
	"github.com/sle58083/cx-box/internal/service"
)

// Generator 订阅生成器。
type Generator struct {
	db      *gorm.DB
	clients *service.ClientService
}

// New 构造订阅生成器。
func New(db *gorm.DB) *Generator {
	return &Generator{db: db, clients: service.NewClientService(db)}
}

// Links 返回某订阅 ID 对应客户端的分享链接列表。
// host 是订阅被访问时的主机名（不含端口），用作链接里的服务器地址。
// 客户端不存在返回 gorm.ErrRecordNotFound；被禁用/到期/超流量返回业务错误。
func (g *Generator) Links(subID, host string) ([]string, *model.Client, error) {
	client, err := g.clients.GetBySubID(subID)
	if err != nil {
		return nil, nil, err
	}
	if !client.Enable {
		return nil, client, fmt.Errorf("sub: 客户端已被禁用")
	}
	if client.ExpiryTime > 0 && client.ExpiryTime < time.Now().Unix() {
		return nil, client, fmt.Errorf("sub: 客户端已到期")
	}

	inbounds, err := g.targetInbounds(client)
	if err != nil {
		return nil, client, err
	}
	pw := client.Password
	user := renderer.ProxyUser{
		ID:       client.ID.String(),
		Name:     client.Email,
		UUID:     client.UUID,
		Password: pw,
	}
	var links []string
	for _, in := range inbounds {
		r, ok := renderer.Get(in.Type)
		if !ok {
			continue
		}
		ob, err := inboundAsOutbound(in, host)
		if err != nil {
			continue
		}
		uri, err := r.SubscriptionURI(ob, user)
		if err != nil {
			continue // 该协议无标准订阅格式或参数不全，跳过
		}
		links = append(links, uri)
	}
	return links, client, nil
}

// targetInbounds 决定客户端可用的入站：绑定了单个入站时只用它，
// 否则用全部启用的用户入口入站（is_user_inbound）。
func (g *Generator) targetInbounds(client *model.Client) ([]model.Inbound, error) {
	q := g.db.Where("status = ?", model.StatusEnabled)
	if client.InboundID != nil && *client.InboundID != "" {
		q = q.Where("id = ?", *client.InboundID)
	} else {
		q = q.Where("is_user_inbound = ?", true)
	}
	var inbounds []model.Inbound
	if err := q.Order("port ASC").Find(&inbounds).Error; err != nil {
		return nil, err
	}
	return inbounds, nil
}

// inboundAsOutbound 把入站转换为出站视图：复制 Settings 并注入 server/server_port。
func inboundAsOutbound(in model.Inbound, host string) (model.Outbound, error) {
	settings := map[string]any{}
	if len(in.Settings) > 0 {
		if err := json.Unmarshal(in.Settings, &settings); err != nil {
			return model.Outbound{}, fmt.Errorf("sub: 入站 %s 的 settings 不是合法 JSON: %w", in.Name, err)
		}
	}
	settings["server"] = host
	settings["server_port"] = in.Port
	raw, err := json.Marshal(settings)
	if err != nil {
		return model.Outbound{}, err
	}
	return model.Outbound{
		Name:      in.Name,
		Type:      in.Type,
		Settings:  raw,
		TLS:       in.TLS,
		Transport: in.Transport,
	}, nil
}
