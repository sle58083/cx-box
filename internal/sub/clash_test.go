package sub

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type clashYAML struct {
	Proxies []map[string]any `yaml:"proxies"`
	Groups  []struct {
		Name    string   `yaml:"name"`
		Type    string   `yaml:"type"`
		Proxies []string `yaml:"proxies"`
	} `yaml:"proxy-groups"`
	Rules []string `yaml:"rules"`
}

func TestClashForClient(t *testing.T) {
	gen, c := seed(t)
	body, client, err := gen.Clash(c.SubID, "example.com")
	if err != nil {
		t.Fatalf("clash: %v", err)
	}
	if client.Email != "user@example.com" {
		t.Fatalf("client = %+v", client)
	}
	var doc clashYAML
	if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatalf("clash output is not valid YAML: %v\n%s", err, body)
	}
	if len(doc.Proxies) != 1 {
		t.Fatalf("proxies = %v, want exactly the vless user inbound", doc.Proxies)
	}
	p := doc.Proxies[0]
	if p["name"] != "vless-main" || p["type"] != "vless" || p["server"] != "example.com" {
		t.Fatalf("proxy wrong: %v", p)
	}
	if p["uuid"] != c.UUID {
		t.Fatalf("proxy uuid = %v, want client uuid %v", p["uuid"], c.UUID)
	}
	if len(doc.Groups) != 2 || doc.Groups[0].Type != "url-test" || doc.Groups[1].Type != "select" {
		t.Fatalf("groups wrong: %+v", doc.Groups)
	}
	if len(doc.Rules) != 1 || !strings.HasPrefix(doc.Rules[0], "MATCH,") {
		t.Fatalf("rules wrong: %v", doc.Rules)
	}
	// 通用格式不受影响：同一客户端的链接列表仍是原来的 vless 链接。
	links, _, err := gen.Links(c.SubID, "example.com")
	if err != nil || len(links) != 1 || !strings.HasPrefix(links[0], "vless://") {
		t.Fatalf("links changed unexpectedly: %v, %v", links, err)
	}
}

func TestClashUnknownClient(t *testing.T) {
	gen, _ := seed(t)
	if _, _, err := gen.Clash("not-exist", "example.com"); err == nil {
		t.Fatal("unknown sub id should fail")
	}
}
