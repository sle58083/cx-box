package renderer

import (
	"encoding/json"
	"testing"
)

// TestRenderTLSStripsCertPathsUnderReality 是证书注入的渲染层兜底：
// TLS JSON 里同时有 Reality 与证书路径时，渲染结果必须剥离证书路径，
// 否则 sing-box 校验 FATAL、整份配置无法启动。
func TestRenderTLSStripsCertPathsUnderReality(t *testing.T) {
	raw := json.RawMessage(`{"enabled":true,"certificate_path":"/x.crt","key_path":"/x.key","reality":{"enabled":true,"private_key":"k"}}`)
	out, err := renderTLS(raw)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("renderTLS = %T", out)
	}
	if _, ok := m["certificate_path"]; ok {
		t.Fatal("Reality 下 certificate_path 未剥离")
	}
	if _, ok := m["key_path"]; ok {
		t.Fatal("Reality 下 key_path 未剥离")
	}
	// 普通 TLS 不动证书路径。
	raw2 := json.RawMessage(`{"enabled":true,"certificate_path":"/x.crt","key_path":"/x.key"}`)
	out2, err := renderTLS(raw2)
	if err != nil {
		t.Fatal(err)
	}
	m2 := out2.(map[string]any)
	if m2["certificate_path"] != "/x.crt" {
		t.Fatal("普通 TLS 的 certificate_path 被误剥离")
	}
}

// TestDerivedCredentials 覆盖派生凭据的确定性与反解。
func TestDerivedCredentials(t *testing.T) {
	u1 := DerivedUUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "ob-1")
	u2 := DerivedUUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "ob-1")
	u3 := DerivedUUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "ob-2")
	if u1 != u2 {
		t.Fatal("DerivedUUID 应确定性一致")
	}
	if u1 == u3 {
		t.Fatal("不同出口应推导出不同 UUID")
	}
	if len(u1) != 36 || u1[14] != '4' {
		t.Fatalf("DerivedUUID 格式异常: %s", u1)
	}
	p1 := DerivedPassword("pw", "ob-1")
	if p1 != DerivedPassword("pw", "ob-1") || p1 == DerivedPassword("pw", "ob-2") {
		t.Fatal("DerivedPassword 确定性/区分度异常")
	}
	name := DerivedUserName("client-1", "ob-1")
	if BaseClientID(name) != "client-1" {
		t.Fatalf("BaseClientID 反解失败: %s", name)
	}
	if BaseClientID("client-1") != "client-1" {
		t.Fatal("BaseClientID 对基础用户名应原样返回")
	}
}
