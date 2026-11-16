package configsvc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sle58083/cx-box/internal/model"
	"github.com/sle58083/cx-box/internal/renderer"
)

// ssInboundHasPassword 判断 ss 入站是否在 settings 里设了静态密码。
func ssInboundHasPassword(cfg model.Inbound) bool {
	if len(cfg.Settings) == 0 {
		return false
	}
	var s struct {
		P string `json:"password"`
	}
	if err := json.Unmarshal(cfg.Settings, &s); err != nil {
		return false
	}
	return s.P != ""
}

// ErrUnknownProtocol 表示未注册的协议类型。
var ErrUnknownProtocol = errors.New("configsvc: unknown protocol")

// DefaultAPIPort 是 sing-box api service 的本地监听端口（仅回环，
// 供 cx-box 采集 per-user 流量；见 internal/traffic）。
const DefaultAPIPort = 19090

// APIAddress 返回 api service 的监听地址（采集器与生成器共用同一约定）。
func APIAddress() string { return fmt.Sprintf("127.0.0.1:%d", DefaultAPIPort) }

// NodeConfigContext 是 Generator 的输入（单节点聚合后的配置上下文）。
type NodeConfigContext struct {
	Global     GlobalSettings
	Inbounds   []model.Inbound
	Outbounds  []model.Outbound
	Rules      []model.RoutingRule
	ProxyUsers []renderer.ProxyUser // 该分组 active 用户（UUID 已解密）
	APISecret  string               // 非空时注入 sing-box api service（流量统计）
}

// Generator 是中立模型 → sing-box JSON 的纯函数生成器。
// 只做「查表分发 + 全局结构拼装」，不感知协议字段。
type Generator struct{}

// NewGenerator 构造 Generator。
func NewGenerator() *Generator { return &Generator{} }

// Generate 输入 NodeConfigContext，输出 sing-box 原生 JSON（map 形式）。
func (g *Generator) Generate(ctx *NodeConfigContext) (map[string]any, error) {
	global := ctx.Global
	if global.LogLevel == "" {
		global = DefaultGlobalSettings()
	}

	// 启停过滤（§5.2）：status=disabled 不写入 inbounds[]/outbounds[]。
	// aggregate 已过滤一次，此处再防御一次，保证 Generator 纯函数自洽。
	enabledInbounds := filterInbounds(ctx.Inbounds)
	enabledOutbounds := filterOutbounds(ctx.Outbounds)

	// 1. 渲染 inbounds（查表分发）。
	inbounds := make([]map[string]any, 0, len(enabledInbounds))
	for _, cfg := range enabledInbounds {
		r, ok := renderer.Get(cfg.Type)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnknownProtocol, cfg.Type)
		}
		var users []renderer.ProxyUser
		if cfg.IsUserInbound {
			users = usersForInbound(ctx.ProxyUsers, cfg.ID.String())
		}
		// shadowsocks 用户入口在「无客户端且未设静态密码」时没有任何凭据，
		// sing-box 会以 missing password 拒绝整份配置（连累其他入站一起
		// 起不来，实测其余协议空 users 均可启动）。这种入站此时无人可连，
		// 跳过生成；建好客户端后下一次（自动）应用会自动带上它。
		if cfg.Type == "shadowsocks" && cfg.IsUserInbound && len(users) == 0 && !ssInboundHasPassword(cfg) {
			continue
		}
		el, err := r.RenderInbound(&renderer.RenderContext{Ctx: context.Background(), Users: users}, cfg, users)
		if err != nil {
			return nil, fmt.Errorf("render inbound %q: %w", cfg.Name, err)
		}
		inbounds = append(inbounds, el)
	}

	// 2. 渲染 outbounds（查表分发）。
	outbounds := make([]map[string]any, 0, len(enabledOutbounds))
	for _, cfg := range enabledOutbounds {
		r, ok := renderer.Get(cfg.Type)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnknownProtocol, cfg.Type)
		}
		el, err := r.RenderOutbound(&renderer.RenderContext{Ctx: context.Background()}, cfg)
		if err != nil {
			return nil, fmt.Errorf("render outbound %q: %w", cfg.Name, err)
		}
		outbounds = append(outbounds, el)
	}

	// 兜底直连：保证 tag=direct 的出站存在——route.final 的兜底值与
	// 「客户端指定直连出口」的路由规则都会引用它，缺失会让 sing-box 以
	// "default outbound not found: direct" 拒绝整份配置。已有同名 tag 时不重复加。
	hasDirect := false
	for _, el := range outbounds {
		if el[kTag] == "direct" {
			hasDirect = true
			break
		}
	}
	if !hasDirect {
		outbounds = append(outbounds, map[string]any{kType: "direct", kTag: "direct"})
	}

	// 3. tag 全局唯一断言（§9.8，跨 inbound/outbound 全量）。
	if err := assertUniqueTags(inbounds, outbounds); err != nil {
		return nil, err
	}

	// 4. 全局结构拼装。
	// 注意：不生成 experimental.v2ray_api —— 官方 sing-box 构建不带
	// with_v2ray_api，带上这一节会让 `sing-box check` 直接失败、内核永远
	// 起不来（P4 实测踩到）。流量统计改走 sing-box 1.14 官方 api service
	// （services[].type=api，连接事件带 user 字段，可精确归因到客户端）。
	doc := map[string]any{
		kInbounds:  inbounds,
		kOutbounds: outbounds,
	}
	if ctx.APISecret != "" {
		doc["services"] = []map[string]any{{
			"type":        "api",
			"tag":         "api",
			"listen":      "127.0.0.1",
			"listen_port": DefaultAPIPort,
			"secret":      ctx.APISecret,
		}}
	}
	global.RouteFinal = resolveRouteFinal(outbounds)
	// 客户端级出口：为指定了出口的客户端合成按 user 匹配的路由规则，
	// 放在通用路由规则之前（优先命中），未指定的走 route.final 全局默认。
	rules := clientOutboundRules(ctx.ProxyUsers, enabledOutbounds)
	rules = append(rules, ctx.Rules...)
	applyGlobalTemplate(doc, global, rules)
	return doc, nil
}

// clientOutboundRules 把客户端的出口选择翻译成路由规则：sing-box 按
// 连接的认证 user（即入站 users[].name = 客户端 ID）匹配。OutboundID 为
// 空的不生成规则（走全局默认）；"direct" 直连；其余按出站 ID 解析成
// tag（出站名称）。出站已被删除/禁用时跳过该规则，客户端回落全局默认，
// 不让一个失效引用拖垮整份配置。
func clientOutboundRules(users []renderer.ProxyUser, outbounds []model.Outbound) []model.RoutingRule {
	tagByID := make(map[string]string, len(outbounds))
	for _, o := range outbounds {
		tagByID[o.ID.String()] = o.Name
	}
	var rules []model.RoutingRule
	for _, u := range users {
		if u.OutboundID == "" {
			continue
		}
		tag := u.OutboundID
		if tag != "direct" {
			t, ok := tagByID[tag]
			if !ok {
				continue
			}
			tag = t
		}
		rules = append(rules, model.RoutingRule{
			RuleType:    "user",
			Value:       u.Name,
			OutboundTag: tag,
			Enabled:     true,
		})
	}
	return rules
}

// usersForInbound 过滤出可注入某个入站的客户端：未做入站选择的（InboundIDs
// 为空）适用全部用户入口入站；做了多选/单选的只注入被选中的入站，与订阅侧
// targetInbounds 的判定保持一致（同一份 SelectedInboundIDs 语义）。
func usersForInbound(users []renderer.ProxyUser, inboundID string) []renderer.ProxyUser {
	out := make([]renderer.ProxyUser, 0, len(users))
	for _, u := range users {
		if len(u.InboundIDs) == 0 {
			out = append(out, u)
			continue
		}
		for _, id := range u.InboundIDs {
			if id == inboundID {
				out = append(out, u)
				break
			}
		}
	}
	return out
}

// assertUniqueTags 断言 inbounds[] 与 outbounds[] 的 tag 全局唯一。
func assertUniqueTags(inbounds, outbounds []map[string]any) error {
	seen := map[string]string{}
	for _, el := range inbounds {
		tag, _ := el[kTag].(string)
		if tag == "" {
			return errors.New("configsvc: inbound tag 不能为空")
		}
		if prev, dup := seen[tag]; dup {
			return fmt.Errorf("configsvc: tag %q 重复（inbound 与 %s）", tag, prev)
		}
		seen[tag] = "inbound"
	}
	for _, el := range outbounds {
		tag, _ := el[kTag].(string)
		if tag == "" {
			return errors.New("configsvc: outbound tag 不能为空")
		}
		if prev, dup := seen[tag]; dup {
			return fmt.Errorf("configsvc: tag %q 重复（outbound 与 %s）", tag, prev)
		}
		seen[tag] = "outbound"
	}
	return nil
}

// resolveRouteFinal 推导 route.final：优先 selector，其次第一个出站，兜底 direct。
func resolveRouteFinal(outbounds []map[string]any) string {
	fallback := "direct"
	for _, el := range outbounds {
		tag, _ := el[kTag].(string)
		if tag != "" && fallback == "direct" {
			fallback = tag
		}
		typ, _ := el["type"].(string)
		if typ == "selector" {
			return tag
		}
	}
	return fallback
}

// filterInbounds 过滤 status=disabled。
func filterInbounds(in []model.Inbound) []model.Inbound {
	out := make([]model.Inbound, 0, len(in))
	for _, c := range in {
		if c.Status != model.StatusDisabled {
			out = append(out, c)
		}
	}
	return out
}

// filterOutbounds 过滤 status=disabled。
func filterOutbounds(in []model.Outbound) []model.Outbound {
	out := make([]model.Outbound, 0, len(in))
	for _, c := range in {
		if c.Status != model.StatusDisabled {
			out = append(out, c)
		}
	}
	return out
}
