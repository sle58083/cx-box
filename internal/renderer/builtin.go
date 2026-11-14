package renderer

import (
	"fmt"

	"github.com/sle58083/cx-box/internal/model"
)

// 以下四个 renderer 处理出站内置类型：direct / block / selector / urltest。
// 它们只支持出站方向，入站方向与订阅 URI 返回 ErrUnsupported。

// DirectRenderer 渲染 direct 出站。
type DirectRenderer struct{}

func (r *DirectRenderer) Protocol() string { return "direct" }

func (r *DirectRenderer) RenderInbound(_ *RenderContext, _ model.Inbound, _ []ProxyUser) (map[string]any, error) {
	return nil, ErrUnsupported
}

func (r *DirectRenderer) RenderOutbound(_ *RenderContext, cfg model.Outbound) (map[string]any, error) {
	out := map[string]any{}
	renderOutboundCommon(out, cfg)
	return out, nil
}

func (r *DirectRenderer) ValidateInbound(model.Inbound) error { return ErrUnsupported }
func (r *DirectRenderer) ValidateOutbound(model.Outbound) error {
	return nil
}
func (r *DirectRenderer) SubscriptionURI(model.Outbound, ProxyUser) (string, error) {
	return "", ErrUnsupported
}
func (r *DirectRenderer) Meta() ProtocolMeta {
	return ProtocolMeta{Protocol: "direct", Directions: []Direction{DirectionOutbound}}
}

// BlockRenderer 渲染 block 出站。
type BlockRenderer struct{}

func (r *BlockRenderer) Protocol() string { return "block" }

func (r *BlockRenderer) RenderInbound(_ *RenderContext, _ model.Inbound, _ []ProxyUser) (map[string]any, error) {
	return nil, ErrUnsupported
}

func (r *BlockRenderer) RenderOutbound(_ *RenderContext, cfg model.Outbound) (map[string]any, error) {
	out := map[string]any{}
	renderOutboundCommon(out, cfg)
	return out, nil
}

func (r *BlockRenderer) ValidateInbound(model.Inbound) error { return ErrUnsupported }
func (r *BlockRenderer) ValidateOutbound(model.Outbound) error {
	return nil
}
func (r *BlockRenderer) SubscriptionURI(model.Outbound, ProxyUser) (string, error) {
	return "", ErrUnsupported
}
func (r *BlockRenderer) Meta() ProtocolMeta {
	return ProtocolMeta{Protocol: "block", Directions: []Direction{DirectionOutbound}}
}

// SelectorRenderer 渲染 selector 出站。
type SelectorRenderer struct{}

func (r *SelectorRenderer) Protocol() string { return "selector" }

func (r *SelectorRenderer) RenderInbound(_ *RenderContext, _ model.Inbound, _ []ProxyUser) (map[string]any, error) {
	return nil, ErrUnsupported
}

func (r *SelectorRenderer) RenderOutbound(_ *RenderContext, cfg model.Outbound) (map[string]any, error) {
	out := map[string]any{}
	renderOutboundCommon(out, cfg)

	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return nil, err
	}
	if ob, ok := settings["outbounds"]; ok {
		out["outbounds"] = ob
	}
	if def := str(settings, "default"); def != "" {
		out["default"] = def
	}
	return out, nil
}

func (r *SelectorRenderer) ValidateInbound(model.Inbound) error { return ErrUnsupported }

func (r *SelectorRenderer) ValidateOutbound(cfg model.Outbound) error {
	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return err
	}
	if _, ok := settings["outbounds"]; !ok {
		return fmt.Errorf("selector outbound: settings.outbounds 必填")
	}
	return nil
}
func (r *SelectorRenderer) SubscriptionURI(model.Outbound, ProxyUser) (string, error) {
	return "", ErrUnsupported
}
func (r *SelectorRenderer) Meta() ProtocolMeta {
	return ProtocolMeta{
		Protocol:   "selector",
		Directions: []Direction{DirectionOutbound},
		Outbound: []FieldSchema{
			{Key: "outbounds", Label: "出站列表", Type: "array", Required: true},
			{Key: "default", Label: "默认出站", Type: "text", Required: false},
		},
	}
}

// URLTestRenderer 渲染 urltest 出站。
type URLTestRenderer struct{}

func (r *URLTestRenderer) Protocol() string { return "urltest" }

func (r *URLTestRenderer) RenderInbound(_ *RenderContext, _ model.Inbound, _ []ProxyUser) (map[string]any, error) {
	return nil, ErrUnsupported
}

func (r *URLTestRenderer) RenderOutbound(_ *RenderContext, cfg model.Outbound) (map[string]any, error) {
	out := map[string]any{}
	renderOutboundCommon(out, cfg)

	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return nil, err
	}
	if ob, ok := settings["outbounds"]; ok {
		out["outbounds"] = ob
	}
	out["url"] = str(settings, "url")
	if interval := str(settings, "interval"); interval != "" {
		out["interval"] = interval
	}
	if tolerance := settings["tolerance"]; tolerance != nil {
		out["tolerance"] = tolerance
	}
	return out, nil
}

func (r *URLTestRenderer) ValidateInbound(model.Inbound) error { return ErrUnsupported }

func (r *URLTestRenderer) ValidateOutbound(cfg model.Outbound) error {
	settings, err := parseMap(cfg.Settings)
	if err != nil {
		return err
	}
	if _, ok := settings["outbounds"]; !ok {
		return fmt.Errorf("urltest outbound: settings.outbounds 必填")
	}
	if str(settings, "url") == "" {
		return fmt.Errorf("urltest outbound: settings.url 必填")
	}
	return nil
}
func (r *URLTestRenderer) SubscriptionURI(model.Outbound, ProxyUser) (string, error) {
	return "", ErrUnsupported
}
func (r *URLTestRenderer) Meta() ProtocolMeta {
	return ProtocolMeta{
		Protocol:   "urltest",
		Directions: []Direction{DirectionOutbound},
		Outbound: []FieldSchema{
			{Key: "outbounds", Label: "出站列表", Type: "array", Required: true},
			{Key: "url", Label: "探测 URL", Type: "text", Required: true},
			{Key: "interval", Label: "探测间隔", Type: "duration", Required: false},
		},
	}
}

func init() {
	Register(&DirectRenderer{})
	Register(&BlockRenderer{})
	Register(&SelectorRenderer{})
	Register(&URLTestRenderer{})
}
