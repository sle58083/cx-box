// Package renderer 是「中立配置模型 → sing-box 原生 JSON」的协议渲染器插件包。
//
// 一个协议 = 一个 ProtocolRenderer 实现（渲染 + 校验 + 订阅 URI + 元数据），
// 通过 init() + registry 自注册；Generator 只做 renderer.Get(type) 查表分发，
// 绝不硬编码协议名（docs/protocol-matrix-renderer.md）。
package renderer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/sle58083/cx-box/internal/model"
)

// ErrUnsupported 表示该协议不支持当前操作（如无标准订阅格式、方向不支持）。
var ErrUnsupported = errors.New("renderer: operation not supported for this protocol")

// ProxyUser 是渲染时注入的代理用户视图（敏感值已由 configsvc 解密）。
// 渲染器负责「编码规则」（如 anytls 要 base64），但不得负责「解密」。
type ProxyUser struct {
	ID       string
	Name     string
	UUID     string // vless/vmess/tuic 用，已解密
	Password string // 协议密码明文（已解密；anytls 渲染器会再 base64）
	// InboundIDs 是该客户端选中的入站 ID 列表（空 = 适用全部用户入口入站）；
	// 生成器据此把用户只注入被选中的入站，订阅视图不使用该字段。
	InboundIDs []string
	// OutboundID 是该客户端指定的出口（空 = 跟随全局默认；"direct" = 直连；
	// 否则为出站 ID）。生成器据此合成按 user 匹配的路由规则。
	OutboundID string
	// OutboundIDs 是该客户端选中的出口列表（多选优先于 OutboundID 的
	// 统一视图）：空 = 跟随全局默认；每项为 "direct" 或出站 ID；
	// 多于一项时生成器合成 urltest 测速组并把规则指向它。
	OutboundIDs []string
}

// RenderContext 提供渲染期间共享数据与已解密的敏感值。
type RenderContext struct {
	Ctx   context.Context
	Users []ProxyUser
}

// ProtocolRenderer 协议渲染器接口：一个协议 = 一个实现。
type ProtocolRenderer interface {
	// Protocol 返回协议标识，必须与 inbound_config.type / outbound_config.type 一致。
	Protocol() string

	// RenderInbound 渲染 sing-box inbounds[] 的一个元素。
	// users 仅在 cfg.IsUserInbound 为真时非空。
	RenderInbound(ctx *RenderContext, cfg model.Inbound, users []ProxyUser) (map[string]any, error)

	// RenderOutbound 渲染 sing-box outbounds[] 的一个元素。
	RenderOutbound(ctx *RenderContext, cfg model.Outbound) (map[string]any, error)

	// ValidateInbound / ValidateOutbound：保存前业务校验（含协议×TLS 组合约束，唯一权威）。
	ValidateInbound(cfg model.Inbound) error
	ValidateOutbound(cfg model.Outbound) error

	// SubscriptionURI 生成订阅 URI；协议无标准订阅格式时返回 ErrUnsupported。
	SubscriptionURI(cfg model.Outbound, user ProxyUser) (string, error)

	// Meta 返回前端动态表单所需的协议元数据（方向、字段 schema、允许的 TLS 组合）。
	Meta() ProtocolMeta
}

// Direction 协议支持方向。
type Direction string

const (
	DirectionInbound  Direction = "inbound"
	DirectionOutbound Direction = "outbound"
)

// TLSMode 协议允许的 TLS 组合。
type TLSMode string

const (
	TLSModeNone    TLSMode = "none"
	TLSModePlain   TLSMode = "plain"
	TLSModeReality TLSMode = "reality"
	TLSModeECH     TLSMode = "ech"
)

// ProtocolMeta 协议元数据，前端据此渲染动态表单与约束。
// 该结构经 GET /api/v1/protocols 直接序列化下发，故字段带 json tag。
type ProtocolMeta struct {
	Protocol    string        `json:"protocol"`
	Directions  []Direction   `json:"directions"`
	Inbound     []FieldSchema `json:"inbound"`
	Outbound    []FieldSchema `json:"outbound"`
	TLSAllowed  []TLSMode     `json:"tls_allowed"`
	TLSRequired bool          `json:"tls_required"`
	MultiUser   bool          `json:"multi_user"`
}

// FieldSchema 是前端动态表单的字段描述（JSON-schema 风格最小子集）。
type FieldSchema struct {
	Key      string          `json:"key"`
	Label    string          `json:"label"`
	Type     string          `json:"type"` // text/number/bool/select/array/duration
	Required bool            `json:"required"`
	Encrypt  bool            `json:"encrypt"`        // 是否 🔐 加密落库（如 anytls password）
	Help     string          `json:"help,omitempty"` // 帮助提示（如 2022-blake3 需 base64 密钥）
	Options  []FieldOption   `json:"options,omitempty"`
	Default  json.RawMessage `json:"default,omitempty"`
}

// FieldOption 是 select 字段的可选项。
type FieldOption struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// defaultJSON 将任意值序列化为 json.RawMessage，用于 FieldSchema.Default。
// 序列化失败时返回 nil（前端视为无默认值）。
func defaultJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}

// hasDirection 判断协议是否支持指定方向。
func hasDirection(meta ProtocolMeta, d Direction) bool {
	for _, v := range meta.Directions {
		if v == d {
			return true
		}
	}
	return false
}

// ---- 派生用户（一个客户端的多个出口在订阅里可选）----
//
// 客户端选了多个出口时，除了基础用户（跟随其出口选择/测速组），还为每个
// 出口派生一个独立用户：入站同时接受基础与派生凭据，路由按派生用户名把
// 流量送到对应出口；订阅为每个出口生成一条独立链接（节点名带出口名），
// 用户在客户端里点哪个节点就走哪个出口。派生凭据由客户端凭据 + 出口 ID
// 确定性推导，configsvc 与 sub 两侧同源同值，无需落库。

// DerivedSep 是派生用户名中客户端 ID 与出口 ID 的分隔符。
const DerivedSep = "#"

// DerivedUserName 生成派生用户在入站 users 中的名字（auth_user 匹配键）。
func DerivedUserName(clientID, outboundID string) string {
	return clientID + DerivedSep + outboundID
}

// BaseClientID 从用户名反解基础客户端 ID：派生名返回分隔符前段，
// 基础用户名（本身即客户端 ID）原样返回。流量归因用。
func BaseClientID(userName string) string {
	if i := strings.Index(userName, DerivedSep); i >= 0 {
		return userName[:i]
	}
	return userName
}

// DerivedUUID 由客户端 UUID 与出口 ID 确定性推导派生用户的 UUID。
func DerivedUUID(clientUUID, outboundID string) string {
	sum := sha256.Sum256([]byte(clientUUID + "|" + outboundID))
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// DerivedPassword 由客户端密码与出口 ID 确定性推导派生用户的密码。
func DerivedPassword(clientPassword, outboundID string) string {
	sum := sha256.Sum256([]byte(clientPassword + "|" + outboundID))
	return hex.EncodeToString(sum[:])[:32]
}
