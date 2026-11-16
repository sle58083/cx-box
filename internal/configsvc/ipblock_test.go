package configsvc

import (
	"testing"

	"github.com/sle58083/cx-box/internal/model"
	"github.com/sle58083/cx-box/internal/renderer"
)

// TestGenerateIPBlockRules 覆盖 IP 数限制的配置生成：封锁集合生成
// 「auth_user（基础+派生）+ source_ip_cidr -> block」规则且排在出口
// 规则之前；block 出站被兜底生成；无对应活跃用户的封锁不生成规则。
func TestGenerateIPBlockRules(t *testing.T) {
	cid := model.NewID().String()
	users := []renderer.ProxyUser{
		{ID: cid, Name: cid},
		{ID: cid, Name: renderer.DerivedUserName(cid, "ob-1")},
		{ID: model.NewID().String(), Name: "other"},
	}
	ctx := &NodeConfigContext{
		Global:     DefaultGlobalSettings(),
		ProxyUsers: users,
		IPBlocks: map[string][]string{
			cid:          {"2.2.2.2", "2001:db8::5"},
			"ghost-user": {"9.9.9.9"},
		},
	}
	doc, err := NewGenerator().Generate(ctx)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	route, _ := doc["route"].(map[string]any)
	rules, _ := route["rules"].([]map[string]any)
	if len(rules) != 2 {
		t.Fatalf("rules = %v, want 2 block rules", rules)
	}
	r0 := rules[0]
	if r0["outbound"] != "block" {
		t.Fatalf("rule0 outbound = %v", r0["outbound"])
	}
	au, _ := r0["auth_user"].([]string)
	if len(au) != 2 {
		t.Fatalf("rule0 auth_user = %v, want base+derived", au)
	}
	cidrs, _ := r0["source_ip_cidr"].([]string)
	if len(cidrs) != 1 || (cidrs[0] != "2.2.2.2/32" && cidrs[0] != "2001:db8::5/128") {
		t.Fatalf("rule0 source_ip_cidr = %v", cidrs)
	}
	// block 出站兜底存在。
	foundBlock := false
	for _, o := range doc["outbounds"].([]map[string]any) {
		if o["tag"] == "block" && o["type"] == "block" {
			foundBlock = true
		}
	}
	if !foundBlock {
		t.Fatal("block outbound missing")
	}
}

// TestResolveRouteFinal 钉住 route.final 的推导：selector 优先、其次第一个
// 非 direct 出站、兜底 direct；block 永远不能当默认出口（[direct, block]
// 顺序下旧实现会选 block，等于全网断流）。
func TestResolveRouteFinal(t *testing.T) {
	ob := func(tag, typ string) map[string]any { return map[string]any{kTag: tag, kType: typ} }
	cases := []struct {
		name string
		in   []map[string]any
		want string
	}{
		{"空", nil, "direct"},
		{"仅 direct", []map[string]any{ob("direct", "direct")}, "direct"},
		{"direct 后跟 block", []map[string]any{ob("direct", "direct"), ob("block", "block")}, "direct"},
		{"落地在前", []map[string]any{ob("landing", "socks"), ob("direct", "direct")}, "landing"},
		{"direct 在前落地在后", []map[string]any{ob("direct", "direct"), ob("landing", "socks")}, "landing"},
		{"selector 优先", []map[string]any{ob("landing", "socks"), ob("sel", "selector"), ob("direct", "direct")}, "sel"},
		{"组出站可选", []map[string]any{ob("direct", "direct"), ob("cx-grp-x", "urltest"), ob("block", "block")}, "cx-grp-x"},
	}
	for _, c := range cases {
		if got := resolveRouteFinal(c.in); got != c.want {
			t.Errorf("%s: resolveRouteFinal = %q, want %q", c.name, got, c.want)
		}
	}
}
