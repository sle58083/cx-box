package configsvc

import (
	"context"
	"errors"
	"fmt"

	"github.com/sle58083/cx-box/internal/model"
	"github.com/sle58083/cx-box/internal/renderer"
)

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
			users = ctx.ProxyUsers
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

	// 兜底直连：无任何出站时注入默认 direct，避免 route.final="direct" 引用不存在的
	// tag 导致 sing-box 启动失败（"default outbound not found: direct"）。
	if len(outbounds) == 0 {
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
	applyGlobalTemplate(doc, global, ctx.Rules)
	return doc, nil
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
