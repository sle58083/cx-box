// Package sub 生成客户端订阅内容（分享链接列表）。
//
// 单体面板的订阅来源是本机入站：把每个启用的用户入站转换成一个「出站视图」
// （在入站 Settings 里注入 server=<订阅访问主机>、server_port=<入站端口>），
// 再复用 renderer 的 SubscriptionURI 生成各协议分享链接 —— 协议编码规则仍由
// 渲染器唯一负责，本包只做视图转换与客户端状态校验。
package sub

import (
	"crypto/ecdh"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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
		} else if sni := g.autoCertSNI(); sni != "" {
			// 未绑证书的 TLS 入站由面板自动证书兜底，同样补上其域名作 SNI。
			ob.TLS = fillSNI(ob.TLS, sni)
		}
		// 生效证书为自签时客户端无法通过 CA 校验，链接必须带跳过校验标记，
		// 否则 trojan / hysteria2 / tuic / anytls 等 TLS 节点在客户端全部连不上
		//（实测 x509: certificate signed by unknown authority）。
		if g.selfSignedCert(in) {
			ob.TLS = fillInsecure(ob.TLS)
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
	if ids := client.SelectedInboundIDs(); len(ids) > 0 {
		q = q.Where("id IN ?", ids)
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
		// settings 存的是 JSON 字面量 null 时 map 会被置 nil，
		// 下面注入 server/server_port 就会 panic（真机踩中）。
		if settings == nil {
			settings = map[string]any{}
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
	return firstDomain(cert.Domains)
}

// autoCertSNI 返回面板自动证书的首选 SNI 域名（自动证书尚不存在时返回空）。
func (g *Generator) autoCertSNI() string {
	var cert model.Certificate
	if err := g.db.First(&cert, "name = ?", service.AutoCertName).Error; err != nil {
		return ""
	}
	return firstDomain(cert.Domains)
}

// firstDomain 从证书 Domains（JSON []string）里取首选域名：第一个 DNS 名优先。
func firstDomain(domainsJSON string) string {
	var domains []string
	if err := json.Unmarshal([]byte(domainsJSON), &domains); err != nil || len(domains) == 0 {
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
// selfSignedCert 判断入站最终生效的证书是否为自签证书：
//   - 绑了面板证书：面板自签（Type=self_signed）或导入 PEM 本身自签 → true；
//   - 未绑证书：TLS 里自备 certificate_path 的无法判定，按非自签处理；
//     其余情况应用时由面板自动证书（自签）兜底 → true。
//
// TLS 未启用或启用了 Reality 时与证书无关，返回 false。
func (g *Generator) selfSignedCert(in model.Inbound) bool {
	var tls map[string]any
	if len(in.TLS) > 0 {
		if err := json.Unmarshal(in.TLS, &tls); err != nil {
			return false
		}
	}
	if en, _ := tls["enabled"].(bool); !en {
		return false
	}
	if rm, ok := tls["reality"].(map[string]any); ok {
		if en, _ := rm["enabled"].(bool); en {
			return false
		}
	}
	if in.CertID != nil && *in.CertID != "" {
		var cert model.Certificate
		if err := g.db.First(&cert, "id = ?", *in.CertID).Error; err != nil {
			return false
		}
		if cert.Type == "self_signed" {
			return true
		}
		return pemSelfSigned(cert.CertPEM)
	}
	if _, ok := tls["certificate_path"]; ok {
		return false
	}
	return true
}

// pemSelfSigned 解析 PEM 叶子证书并判定是否自签：颁发者与主体相同，
// 且签名能用证书自身公钥验过。不用 CheckSignatureFrom——它要求父证书带
// CA 约束，普通自签服务器证书（IsCA=false）会被误判为非自签。
func pemSelfSigned(certPEM string) bool {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return false
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	if string(leaf.RawIssuer) != string(leaf.RawSubject) {
		return false
	}
	return leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil
}

// fillInsecure 在订阅出站视图的 TLS 里置 insecure=true，
// 各协议 SubscriptionURI 据此在链接里输出跳过证书校验的参数。
func fillInsecure(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var tls map[string]any
	if err := json.Unmarshal(raw, &tls); err != nil {
		return raw
	}
	if v, _ := tls["insecure"].(bool); v {
		return raw
	}
	tls["insecure"] = true
	out, err := json.Marshal(tls)
	if err != nil {
		return raw
	}
	return out
}

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
