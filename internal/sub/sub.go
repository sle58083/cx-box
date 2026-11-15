// Package sub 生成客户端订阅内容（分享链接列表）。
//
// 单体面板的订阅来源是本机入站：把每个启用的用户入站转换成一个「出站视图」
// （在入站 Settings 里注入 server=<订阅访问主机>、server_port=<入站端口>），
// 再复用 renderer 的 SubscriptionURI 生成各协议分享链接 —— 协议编码规则仍由
// 渲染器唯一负责，本包只做视图转换与客户端状态校验。
package sub

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
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
		// 绑定了证书但 TLS 没写 server_name 时，用证书的首个域名补 SNI，
		// 否则客户端连 IP 时证书校验/SNI 都对不上。
		if in.CertID != nil {
			if sni := g.certSNI(*in.CertID); sni != "" {
				ob.TLS = fillSNI(ob.TLS, sni)
			}
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
		TLS:       deriveRealityPublic(in.TLS),
		Transport: in.Transport,
	}, nil
}

// deriveRealityPublic 为订阅场景补全 Reality 公钥：入站 TLS 里只有 private_key，
// 客户端需要 public_key（pbk）。能从私钥推导时注入 reality.public_key，
// 并把 short_id 数组规范成首元素字符串（URI 参数形态）。解析失败原样返回。
func deriveRealityPublic(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var tls map[string]any
	if err := json.Unmarshal(raw, &tls); err != nil {
		return raw
	}
	reality, ok := tls["reality"].(map[string]any)
	if !ok {
		return raw
	}
	if ids, ok := reality["short_id"].([]any); ok && len(ids) > 0 {
		if s, ok := ids[0].(string); ok {
			reality["short_id"] = s
		}
	}
	if pk, _ := reality["public_key"].(string); pk != "" {
		return raw
	}
	privStr, _ := reality["private_key"].(string)
	if privStr == "" {
		return raw
	}
	privBytes, err := decodeB64(privStr)
	if err != nil {
		return raw
	}
	priv, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return raw
	}
	reality["public_key"] = base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
	out, err := json.Marshal(tls)
	if err != nil {
		return raw
	}
	return out
}

// decodeB64 兼容 sing-box 常见的 RawURLEncoding 与标准编码。
func decodeB64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("sub: base64 解码失败")
}

// certSNI 返回证书的首选 SNI 域名：Domains 里第一个 DNS 名（全是 IP 时取第一个 IP）。
func (g *Generator) certSNI(certID string) string {
	var cert model.Certificate
	if err := g.db.First(&cert, "id = ?", certID).Error; err != nil {
		return ""
	}
	var domains []string
	if err := json.Unmarshal([]byte(cert.Domains), &domains); err != nil || len(domains) == 0 {
		return ""
	}
	for _, d := range domains {
		if net.ParseIP(d) == nil {
			return d
		}
	}
	return domains[0]
}

// fillSNI 在 TLS 的 server_name 为空时填入 sni（已有值不覆盖）。解析失败原样返回。
func fillSNI(raw json.RawMessage, sni string) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var tls map[string]any
	if err := json.Unmarshal(raw, &tls); err != nil {
		return raw
	}
	if cur, _ := tls["server_name"].(string); cur != "" {
		return raw
	}
	tls["server_name"] = sni
	out, err := json.Marshal(tls)
	if err != nil {
		return raw
	}
	return out
}
