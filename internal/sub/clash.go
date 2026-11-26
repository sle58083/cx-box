package sub

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/sle58083/cx-box/internal/model"
	"github.com/sle58083/cx-box/internal/renderer"
)

// Clash 系订阅（Mihomo / Clash Verge / Stash 等）组装：节点清单与分享链接
// 共用 collect 的结果，逐条经渲染器映射成 proxies 条目，再套上最小可用的
// 规则模板（自动选择 url-test 组 + 节点选择 select 组 + MATCH 直达规则组），
// 用户导入即可用，不需要再套 subconverter 之类的第三方转换（订阅凭据
// 不出本机，也不受源地址是内网 IP 的限制）。

// Clash 分组名（订阅内固定，用户可在客户端里自行改名）。
const (
	clashGroupAuto   = "自动选择"
	clashGroupSelect = "节点选择"
)

// clashGroup 是 proxy-groups 的一条（字段顺序即 YAML 输出顺序）。
type clashGroup struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	Proxies  []string `yaml:"proxies"`
	URL      string   `yaml:"url,omitempty"`
	Interval int      `yaml:"interval,omitempty"`
}

// clashDoc 是一份完整可导入的 Mihomo 配置订阅。
type clashDoc struct {
	MixedPort   int              `yaml:"mixed-port"`
	AllowLan    bool             `yaml:"allow-lan"`
	Mode        string           `yaml:"mode"`
	LogLevel    string           `yaml:"log-level"`
	Proxies     []map[string]any `yaml:"proxies"`
	ProxyGroups []clashGroup     `yaml:"proxy-groups"`
	Rules       []string         `yaml:"rules"`
}

// Clash 返回某订阅 ID 的 Clash 格式订阅（YAML 文本）。
// 客户端校验与节点来源与 Links 完全一致（同一个 collect）。
func (g *Generator) Clash(subID, host string) (string, *model.Client, error) {
	entries, client, err := g.collect(subID, host)
	if err != nil {
		return "", client, err
	}
	proxies := make([]map[string]any, 0, len(entries))
	names := make([]string, 0, len(entries))
	seen := map[string]int{}
	for _, e := range entries {
		p, err := renderer.ClashProxyFor(e.ob, e.user)
		if err != nil {
			continue // 该协议无 Clash 映射（如网关类协议本就无订阅），跳过
		}
		// Mihomo 要求 proxies 内 name 唯一：同名节点（同名入站等）加序号后缀。
		name, _ := p["name"].(string)
		if name == "" {
			name = e.ob.Name
		}
		seen[name]++
		if n := seen[name]; n > 1 {
			name = fmt.Sprintf("%s (%d)", name, n)
			p["name"] = name
		}
		proxies = append(proxies, p)
		names = append(names, name)
	}

	selectMembers := make([]string, 0, len(names)+2)
	if len(names) > 0 {
		selectMembers = append(selectMembers, clashGroupAuto)
	}
	selectMembers = append(selectMembers, names...)
	selectMembers = append(selectMembers, "DIRECT")

	doc := clashDoc{
		MixedPort: 7890,
		AllowLan:  false,
		Mode:      "rule",
		LogLevel:  "info",
		Proxies:   proxies,
		ProxyGroups: []clashGroup{
			{
				Name:     clashGroupAuto,
				Type:     "url-test",
				Proxies:  names,
				URL:      "http://www.gstatic.com/generate_204",
				Interval: 300,
			},
			{
				Name:    clashGroupSelect,
				Type:    "select",
				Proxies: selectMembers,
			},
		},
		Rules: []string{"MATCH," + clashGroupSelect},
	}
	if len(names) == 0 {
		// 没有可用节点时不生成空的自动选择组，避免客户端导入直接报错。
		doc.ProxyGroups = doc.ProxyGroups[1:]
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		return "", client, fmt.Errorf("sub: clash 订阅组装失败: %w", err)
	}
	return string(out), client, nil
}
