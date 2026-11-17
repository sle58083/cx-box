package sub

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/model"
	"github.com/sle58083/cx-box/internal/service"
)

// TestSanitizeNodeHost 节点地址清洗：去协议头/路径/端口，只留裸主机名。
func TestSanitizeNodeHost(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"  ", ""},
		{"mofadingyue.ccwu.cc", "mofadingyue.ccwu.cc"},
		{"https://mofadingyue.ccwu.cc", "mofadingyue.ccwu.cc"},
		{"http://mofadingyue.ccwu.cc:2096/sub/abc", "mofadingyue.ccwu.cc"},
		{"mofadingyue.ccwu.cc:2096", "mofadingyue.ccwu.cc"},
		{"mofadingyue.ccwu.cc/", "mofadingyue.ccwu.cc"},
		{" 1.2.3.4 ", "1.2.3.4"},
		{"1.2.3.4:443", "1.2.3.4"},
	}
	for _, c := range cases {
		if got := SanitizeNodeHost(c.in); got != c.want {
			t.Errorf("SanitizeNodeHost(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestLinksNodeHostOverride 设置了订阅节点地址时，链接里的服务器地址
// 固定用它，不跟随请求主机名；未设置时跟随请求主机名（原行为）。
func TestLinksNodeHostOverride(t *testing.T) {
	g, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := g.AutoMigrate(&model.Inbound{}, &model.Client{}, &model.Certificate{}, &model.Setting{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	inSvc := service.NewInboundService(g)
	in := &model.Inbound{Name: "ss-a", Type: "shadowsocks", Port: 8388,
		IsUserInbound: true, Settings: json.RawMessage(`{"method":"aes-128-gcm"}`)}
	if err := inSvc.Create(in); err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	clSvc := service.NewClientService(g)
	cl := &model.Client{Email: "u1", Enable: true}
	if err := clSvc.Create(cl); err != nil {
		t.Fatalf("create client: %v", err)
	}
	gen := New(g)

	links, _, err := gen.Links(cl.SubID, "req.example.org")
	if err != nil {
		t.Fatalf("links: %v", err)
	}
	if len(links) != 1 || !strings.Contains(links[0], "@req.example.org:8388") {
		t.Fatalf("无覆盖时应跟随请求主机名, got %v", links)
	}

	if err := g.Create(&model.Setting{PanelPort: 2095, PanelPath: "/app/",
		SubPort: 2096, SubPath: "/sub/", SubNodeHost: "https://node.example.com:2096/"}).Error; err != nil {
		t.Fatalf("create setting: %v", err)
	}
	links, _, err = gen.Links(cl.SubID, "req.example.org")
	if err != nil {
		t.Fatalf("links with override: %v", err)
	}
	if len(links) != 1 || !strings.Contains(links[0], "@node.example.com:8388") {
		t.Fatalf("有覆盖时链接应使用固定节点地址（且清洗掉协议头/端口）, got %v", links)
	}
}
