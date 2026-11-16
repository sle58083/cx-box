package configsvc

import (
	"encoding/json"
	"testing"

	"github.com/sle58083/cx-box/internal/model"
	"github.com/sle58083/cx-box/internal/renderer"
)

// TestGenerateClientOutboundRules 覆盖客户端级出口：指定出站的客户端生成
// 按 user 匹配的路由规则；指定直连时规则指向 direct 且 direct 出站被
// 保证存在；出站不存在时跳过规则回落默认；未指定出口不生成规则。
func TestGenerateClientOutboundRules(t *testing.T) {
	ob := model.Outbound{
		Base:     model.Base{ID: model.NewID()},
		Type:     "shadowsocks",
		Name:     "landing-1",
		Settings: json.RawMessage(`{"server":"127.0.0.1","server_port":11081,"method":"aes-128-gcm","password":"pw"}`),
		Status:   model.StatusEnabled,
	}
	mkCtx := func(users []renderer.ProxyUser) *NodeConfigContext {
		return &NodeConfigContext{
			Global:     DefaultGlobalSettings(),
			Outbounds:  []model.Outbound{ob},
			ProxyUsers: users,
		}
	}
	gen := func(users []renderer.ProxyUser) map[string]any {
		doc, err := NewGenerator().Generate(mkCtx(users))
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		return doc
	}
	rulesOf := func(doc map[string]any) []map[string]any {
		route, _ := doc["route"].(map[string]any)
		rules, _ := route["rules"].([]map[string]any)
		return rules
	}
	findRule := func(rules []map[string]any, user string) map[string]any {
		for _, r := range rules {
			us, _ := r["auth_user"].([]string)
			if len(us) == 1 && us[0] == user {
				return r
			}
		}
		return nil
	}

	// 指定出站 → user 规则指向该出站 tag。
	doc := gen([]renderer.ProxyUser{{ID: "c1", Name: "c1", OutboundID: ob.ID.String()}})
	r := findRule(rulesOf(doc), "c1")
	if r == nil || r["outbound"] != "landing-1" {
		t.Fatalf("指定出站应生成 user→landing-1 规则, got %v", rulesOf(doc))
	}

	// 指定直连 → 规则指向 direct，且 outbounds 里保证有 direct。
	doc = gen([]renderer.ProxyUser{{ID: "c2", Name: "c2", OutboundID: "direct"}})
	r = findRule(rulesOf(doc), "c2")
	if r == nil || r["outbound"] != "direct" {
		t.Fatalf("指定直连应生成 user→direct 规则, got %v", rulesOf(doc))
	}
	obs, _ := doc["outbounds"].([]map[string]any)
	hasDirect := false
	for _, o := range obs {
		if o["tag"] == "direct" {
			hasDirect = true
		}
	}
	if !hasDirect {
		t.Fatalf("指定直连时 outbounds 应包含 direct, got %v", obs)
	}

	// 出站 ID 不存在 → 跳过规则（回落全局默认），不报错。
	doc = gen([]renderer.ProxyUser{{ID: "c3", Name: "c3", OutboundID: model.NewID().String()}})
	if r := findRule(rulesOf(doc), "c3"); r != nil {
		t.Fatalf("出站不存在时不应生成规则, got %v", r)
	}

	// 未指定出口 → 无规则。
	doc = gen([]renderer.ProxyUser{{ID: "c4", Name: "c4"}})
	if r := findRule(rulesOf(doc), "c4"); r != nil {
		t.Fatalf("未指定出口不应生成规则, got %v", r)
	}

	// 多选出口 → 合成 urltest 测速组，规则指向组，组员含所选出站与 direct。
	doc = gen([]renderer.ProxyUser{{ID: "c5", Name: "c5",
		OutboundIDs: []string{ob.ID.String(), "direct"}}})
	rr := findRule(rulesOf(doc), "c5")
	if rr == nil || rr["outbound"] != "cx-grp-c5" {
		t.Fatalf("多选应生成指向测速组的规则, got %v", rr)
	}
	obs, _ = doc["outbounds"].([]map[string]any)
	var grp map[string]any
	for _, o := range obs {
		if o["tag"] == "cx-grp-c5" {
			grp = o
		}
	}
	if grp == nil || grp["type"] != "urltest" {
		t.Fatalf("应合成 urltest 测速组, got %v", grp)
	}
	members, _ := grp["outbounds"].([]any)
	if len(members) != 2 || members[0] != "landing-1" || members[1] != "direct" {
		t.Fatalf("测速组成员应为 [landing-1 direct], got %v", members)
	}

	// 多选里混了不存在的出站 → 只保留有效的；剩一个时直达不建组。
	doc = gen([]renderer.ProxyUser{{ID: "c6", Name: "c6",
		OutboundIDs: []string{model.NewID().String(), ob.ID.String()}}})
	rr = findRule(rulesOf(doc), "c6")
	if rr == nil || rr["outbound"] != "landing-1" {
		t.Fatalf("多选过滤后剩一个应直达该出站, got %v", rr)
	}
}
