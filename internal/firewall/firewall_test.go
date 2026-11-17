package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/model"
)

type fakeRunner struct{ cmds [][]string }

func (f *fakeRunner) Run(name string, args ...string) (string, error) {
	f.cmds = append(f.cmds, append([]string{name}, args...))
	// 模拟真实 iptables：-C 检查不存在规则时返回错误。
	for _, a := range args {
		if a == "-C" {
			return "", os.ErrNotExist
		}
	}
	return "", nil
}

func (f *fakeRunner) joined() string {
	var lines []string
	for _, c := range f.cmds {
		lines = append(lines, strings.Join(c, " "))
	}
	return strings.Join(lines, "\n")
}

func (f *fakeRunner) indexOf(prefix string) int {
	for i, c := range f.cmds {
		if strings.HasPrefix(strings.Join(c, " "), prefix) {
			return i
		}
	}
	return -1
}

func lookFrom(present map[string]bool) func(string) (string, error) {
	return func(name string) (string, error) {
		if present[name] {
			return "/usr/sbin/" + name, nil
		}
		return "", os.ErrNotExist
	}
}

func fwDB(t *testing.T) *gorm.DB {
	t.Helper()
	g, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if sqlDB, err := g.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	if err := g.AutoMigrate(&model.Setting{}, &model.Inbound{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := g.Create(&model.Setting{PanelPort: 2095, PanelPath: "/app/", SubPort: 2096, SubPath: "/sub/"}).Error; err != nil {
		t.Fatalf("seed setting: %v", err)
	}
	for _, in := range []model.Inbound{
		{Name: "ss", Type: "shadowsocks", Port: 8388, Status: model.StatusEnabled},
		{Name: "hy2", Type: "hysteria2", Port: 36712, Status: model.StatusEnabled},
		{Name: "off", Type: "vless", Port: 9999, Status: "disabled"},
	} {
		in := in
		in.ID = model.NewID()
		if err := g.Create(&in).Error; err != nil {
			t.Fatalf("seed inbound: %v", err)
		}
	}
	return g
}

func newTestManager(t *testing.T, present map[string]bool) (*Manager, *fakeRunner) {
	t.Helper()
	fr := &fakeRunner{}
	m := NewManager(t.TempDir())
	m.Runner = fr
	m.lookPath = lookFrom(present)
	// 测试环境写一份带自定义 SSH 端口的 sshd_config。
	cfg := filepath.Join(t.TempDir(), "sshd_config")
	if err := os.WriteFile(cfg, []byte("Port 2222\nPermitRootLogin yes\n"), 0o644); err != nil {
		t.Fatalf("write sshd_config: %v", err)
	}
	m.sshdConfigPath = cfg
	return m, fr
}

// TestDetect 后端检测优先级 ufw > firewalld > iptables。
func TestDetect(t *testing.T) {
	m, _ := newTestManager(t, map[string]bool{"ufw": true, "firewall-cmd": true, "iptables": true})
	if got := m.Detect(); got != "ufw" {
		t.Fatalf("detect = %q, want ufw", got)
	}
	m, _ = newTestManager(t, map[string]bool{"firewall-cmd": true, "iptables": true})
	if got := m.Detect(); got != "firewalld" {
		t.Fatalf("detect = %q, want firewalld", got)
	}
	m, _ = newTestManager(t, map[string]bool{"iptables": true})
	if got := m.Detect(); got != "iptables" {
		t.Fatalf("detect = %q, want iptables", got)
	}
	m, _ = newTestManager(t, map[string]bool{})
	if got := m.Detect(); got != "" {
		t.Fatalf("detect = %q, want empty", got)
	}
}

// TestDesiredPorts 端口集合：面板/订阅/SSH（含自定义端口）+ 启用入站
// 的 TCP/UDP；禁用入站不放行。
func TestDesiredPorts(t *testing.T) {
	m, _ := newTestManager(t, map[string]bool{"ufw": true})
	ports, err := m.DesiredPorts(fwDB(t))
	if err != nil {
		t.Fatalf("desired: %v", err)
	}
	set := map[string]bool{}
	for _, p := range ports {
		set[p.String()] = true
	}
	for _, want := range []string{"2095/tcp", "2096/tcp", "22/tcp", "2222/tcp",
		"8388/tcp", "8388/udp", "36712/tcp", "36712/udp"} {
		if !set[want] {
			t.Fatalf("应放行 %s, 实际集合 %v", want, ports)
		}
	}
	if set["9999/tcp"] || set["9999/udp"] {
		t.Fatalf("禁用入站的端口不应放行: %v", ports)
	}
}

// TestEnableUFW 开启顺序：先放行全部端口，最后才 enable（防自锁）。
func TestEnableUFW(t *testing.T) {
	m, fr := newTestManager(t, map[string]bool{"ufw": true})
	st, err := m.Enable(fwDB(t))
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !st.Enabled || st.Backend != "ufw" || len(st.Ports) == 0 {
		t.Fatalf("state 不对: %+v", st)
	}
	allowIdx := fr.indexOf("ufw allow 36712/udp")
	enableIdx := fr.indexOf("ufw --force enable")
	if allowIdx < 0 || enableIdx < 0 || allowIdx > enableIdx {
		t.Fatalf("必须先放行端口再启用 ufw:\n%s", fr.joined())
	}
	loaded, err := m.LoadState()
	if err != nil || !loaded.Enabled {
		t.Fatalf("状态未落盘: %v %+v", err, loaded)
	}
}

// TestSyncDiff 同步只增删变化的端口（新建入站放行、删入站收回）。
func TestSyncDiff(t *testing.T) {
	m, fr := newTestManager(t, map[string]bool{"ufw": true})
	g := fwDB(t)
	if _, err := m.Enable(g); err != nil {
		t.Fatalf("enable: %v", err)
	}
	fr.cmds = nil
	// 新增一个启用入站 + 删掉 ss 入站。
	extra := model.Inbound{Name: "vmess", Type: "vmess", Port: 8443, Status: model.StatusEnabled}
	extra.ID = model.NewID()
	if err := g.Create(&extra).Error; err != nil {
		t.Fatalf("create inbound: %v", err)
	}
	if err := g.Model(&model.Inbound{}).Where("port = ?", 8388).Update("status", "disabled").Error; err != nil {
		t.Fatalf("disable inbound: %v", err)
	}
	if err := m.Sync(g); err != nil {
		t.Fatalf("sync: %v", err)
	}
	j := fr.joined()
	if !strings.Contains(j, "ufw allow 8443/tcp") || !strings.Contains(j, "ufw allow 8443/udp") {
		t.Fatalf("新入站端口应被放行:\n%s", j)
	}
	if !strings.Contains(j, "ufw delete allow 8388/tcp") {
		t.Fatalf("下线入站端口应被收回:\n%s", j)
	}
	if strings.Contains(j, "ufw allow 2095/tcp") {
		t.Fatalf("未变化的端口不应重复操作:\n%s", j)
	}
	// 再次同步应无任何命令（已收敛）。
	fr.cmds = nil
	if err := m.Sync(g); err != nil {
		t.Fatalf("sync2: %v", err)
	}
	if len(fr.cmds) != 0 {
		t.Fatalf("收敛后同步应是空操作, 实际:\n%s", fr.joined())
	}
}

// TestDisable 删除全部自管规则并停用后端、清状态文件。
func TestDisable(t *testing.T) {
	m, fr := newTestManager(t, map[string]bool{"ufw": true})
	if _, err := m.Enable(fwDB(t)); err != nil {
		t.Fatalf("enable: %v", err)
	}
	fr.cmds = nil
	if err := m.Disable(); err != nil {
		t.Fatalf("disable: %v", err)
	}
	j := fr.joined()
	if !strings.Contains(j, "ufw delete allow 2095/tcp") || !strings.Contains(j, "ufw --force disable") {
		t.Fatalf("关闭应删规则并停用 ufw:\n%s", j)
	}
	if _, err := os.Stat(m.statePath()); !os.IsNotExist(err) {
		t.Fatalf("状态文件应被删除")
	}
}

// TestEnableNoBackend 无任何后端时明确报错，不假装成功。
func TestEnableNoBackend(t *testing.T) {
	m, _ := newTestManager(t, map[string]bool{})
	if _, err := m.Enable(fwDB(t)); err == nil || !strings.Contains(err.Error(), "未检测到") {
		t.Fatalf("应报未检测到后端, got %v", err)
	}
}

// TestEnableIPTables iptables 后端：自建链、挂 INPUT、端口规则齐、DROP 兜底。
func TestEnableIPTables(t *testing.T) {
	m, fr := newTestManager(t, map[string]bool{"iptables": true})
	if _, err := m.Enable(fwDB(t)); err != nil {
		t.Fatalf("enable: %v", err)
	}
	j := fr.joined()
	for _, want := range []string{
		"iptables -N CX-BOX",
		"iptables -I INPUT 1 -j CX-BOX",
		"iptables -A CX-BOX -p udp --dport 36712 -j ACCEPT",
		"iptables -A CX-BOX -p tcp --dport 2095 -j ACCEPT",
		"iptables -A CX-BOX -j DROP",
	} {
		if !strings.Contains(j, want) {
			t.Fatalf("缺命令 %q:\n%s", want, j)
		}
	}
	if strings.LastIndex(j, "iptables -A CX-BOX -j DROP") < strings.LastIndex(j, "--dport 36712") {
		t.Fatalf("DROP 必须是链的最后一条:\n%s", j)
	}
}
