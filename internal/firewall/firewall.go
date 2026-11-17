// Package firewall 实现一键开启/关闭系统防火墙，并保证 cx-box 需要的
// 端口（面板、订阅、SSH、全部启用入站）始终放行。
//
// 适配三种后端，按优先级检测：ufw（Debian/Ubuntu 系）、firewalld
// （RHEL/CentOS 系）、iptables（兜底，自建 CX-BOX 链）。cx-box 只增删
// 自己管理的端口规则，状态落在 <安装目录>/etc/firewall.json；面板每次
// 应用配置后调用 Sync，新建入站的端口会被自动放行、删除的自动收回，
// 防火墙不会导致协议连不通。
package firewall

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/model"
)

// PortRule 一条放行规则（端口+协议）。
type PortRule struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"` // tcp | udp
}

func (r PortRule) String() string { return fmt.Sprintf("%d/%s", r.Port, r.Proto) }

// State cx-box 的防火墙托管状态。
type State struct {
	Enabled bool       `json:"enabled"`
	Backend string     `json:"backend"` // ufw | firewalld | iptables
	Ports   []PortRule `json:"ports"`   // 当前由 cx-box 放行的端口集合
}

// Runner 执行外部命令（测试可注入假实现）。
type Runner interface {
	Run(name string, args ...string) (string, error)
}

type execRunner struct{}

func (execRunner) Run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}

// Manager 防火墙管理器。
type Manager struct {
	AppDir string // cx-box 安装目录（状态文件在 AppDir/etc/firewall.json）
	Runner Runner // nil 用真实命令执行

	lookPath       func(string) (string, error) // nil 用 exec.LookPath
	sshdConfigPath string                       // 空用 /etc/ssh/sshd_config
}

// NewManager 构造管理器。
func NewManager(appDir string) *Manager { return &Manager{AppDir: appDir} }

func (m *Manager) runner() Runner {
	if m.Runner != nil {
		return m.Runner
	}
	return execRunner{}
}

func (m *Manager) look(name string) bool {
	lp := m.lookPath
	if lp == nil {
		lp = exec.LookPath
	}
	_, err := lp(name)
	return err == nil
}

// Detect 检测可用的防火墙后端；都没有返回空串。
func (m *Manager) Detect() string {
	switch {
	case m.look("ufw"):
		return "ufw"
	case m.look("firewall-cmd"):
		return "firewalld"
	case m.look("iptables"):
		return "iptables"
	default:
		return ""
	}
}

func (m *Manager) statePath() string { return filepath.Join(m.AppDir, "etc", "firewall.json") }

// LoadState 读取托管状态；文件不存在视为空状态（未开启）。
func (m *Manager) LoadState() (*State, error) {
	data, err := os.ReadFile(m.statePath())
	if err != nil {
		if os.IsNotExist(err) {
			return &State{}, nil
		}
		return nil, err
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("firewall: 状态文件损坏: %w", err)
	}
	return &st, nil
}

func (m *Manager) saveState(st *State) error {
	if err := os.MkdirAll(filepath.Dir(m.statePath()), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.statePath(), data, 0o644)
}

// sshPorts 返回要放行的 SSH 端口：22 恒放行，外加 sshd_config 里
// 显式配置的 Port（改过 SSH 端口的机器不能被自己的防火墙锁在门外）。
func (m *Manager) sshPorts() []int {
	ports := []int{22}
	path := m.sshdConfigPath
	if path == "" {
		path = "/etc/ssh/sshd_config"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ports
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 2 && strings.EqualFold(fields[0], "Port") {
			if p, err := strconv.Atoi(fields[1]); err == nil && p > 0 && p <= 65535 && p != 22 {
				ports = append(ports, p)
			}
		}
	}
	return ports
}

// DesiredPorts 计算当前应放行的完整端口集合：面板/订阅/SSH（TCP）+
// 每个启用入站的端口（TCP 与 UDP 都放行，hysteria2/tuic 走 UDP，
// 其余走 TCP，多放 UDP 无副作用，规则简单且不会漏）。
func (m *Manager) DesiredPorts(db *gorm.DB) ([]PortRule, error) {
	set := map[PortRule]bool{}
	add := func(port int, protos ...string) {
		if port <= 0 || port > 65535 {
			return
		}
		for _, pr := range protos {
			set[PortRule{Port: port, Proto: pr}] = true
		}
	}
	var st model.Setting
	if err := db.First(&st).Error; err == nil {
		add(st.PanelPort, "tcp")
		add(st.SubPort, "tcp")
	}
	for _, p := range m.sshPorts() {
		add(p, "tcp")
	}
	var inbounds []model.Inbound
	if err := db.Where("status = ?", model.StatusEnabled).Find(&inbounds).Error; err != nil {
		return nil, fmt.Errorf("firewall: 读取入站失败: %w", err)
	}
	for _, in := range inbounds {
		add(in.Port, "tcp", "udp")
	}
	out := make([]PortRule, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Proto < out[j].Proto
	})
	return out, nil
}

// Enable 一键开启：先放行全部必需端口，再激活防火墙，最后落状态。
// 顺序至关重要：先加规则再开默认拒绝，避免把自己锁在外面。
func (m *Manager) Enable(db *gorm.DB) (*State, error) {
	backend := m.Detect()
	if backend == "" {
		return nil, fmt.Errorf("未检测到可用的防火墙：ufw、firewalld、iptables 均不存在，请先安装 ufw 或 firewalld")
	}
	ports, err := m.DesiredPorts(db)
	if err != nil {
		return nil, err
	}
	if backend == "firewalld" {
		// firewall-cmd 的永久规则需要守护进程在跑。
		if _, err := m.runner().Run("systemctl", "enable", "--now", "firewalld"); err != nil {
			return nil, fmt.Errorf("启动 firewalld 失败: %w", err)
		}
	}
	if backend == "iptables" {
		if err := m.iptablesRebuild(ports); err != nil {
			return nil, err
		}
	} else {
		for _, p := range ports {
			if err := m.addRule(backend, p); err != nil {
				return nil, fmt.Errorf("放行端口 %s 失败: %w", p, err)
			}
		}
	}
	switch backend {
	case "ufw":
		if out, err := m.runner().Run("ufw", "--force", "enable"); err != nil {
			return nil, fmt.Errorf("启用 ufw 失败: %w（%s）", err, strings.TrimSpace(out))
		}
	case "firewalld":
		if _, err := m.runner().Run("firewall-cmd", "--reload"); err != nil {
			return nil, fmt.Errorf("firewalld 重载失败: %w", err)
		}
	case "iptables":
		m.iptablesPersist()
	}
	st := &State{Enabled: true, Backend: backend, Ports: ports}
	if err := m.saveState(st); err != nil {
		return nil, err
	}
	return st, nil
}

// Disable 一键关闭：删除 cx-box 放行的全部端口并停用防火墙后端。
func (m *Manager) Disable() error {
	st, err := m.LoadState()
	if err != nil {
		return err
	}
	backend := st.Backend
	if backend == "" {
		backend = m.Detect()
	}
	if backend == "" {
		_ = os.Remove(m.statePath())
		return nil
	}
	if backend == "iptables" {
		m.iptablesTeardown()
	} else {
		for _, p := range st.Ports {
			_ = m.removeRule(backend, p) // 逐条尽力删除，失败不阻断关闭
		}
	}
	switch backend {
	case "ufw":
		_, _ = m.runner().Run("ufw", "--force", "disable")
	case "firewalld":
		_, _ = m.runner().Run("firewall-cmd", "--reload")
		_, _ = m.runner().Run("systemctl", "stop", "firewalld")
	}
	return os.Remove(m.statePath())
}

// Sync 把放行集合同步到 DesiredPorts（新增放行、 stale 收回）。
// 未开启托管时是空操作；面板每次应用配置后调用。
func (m *Manager) Sync(db *gorm.DB) error {
	st, err := m.LoadState()
	if err != nil || !st.Enabled {
		return err
	}
	desired, err := m.DesiredPorts(db)
	if err != nil {
		return err
	}
	want := map[PortRule]bool{}
	for _, p := range desired {
		want[p] = true
	}
	have := map[PortRule]bool{}
	for _, p := range st.Ports {
		have[p] = true
	}
	if st.Backend == "iptables" {
		changed := len(want) != len(have)
		if !changed {
			for p := range want {
				if !have[p] {
					changed = true
					break
				}
			}
		}
		if changed {
			if err := m.iptablesRebuild(desired); err != nil {
				return err
			}
			m.iptablesPersist()
		}
	} else {
		changed := false
		for _, p := range desired {
			if !have[p] {
				if err := m.addRule(st.Backend, p); err != nil {
					return fmt.Errorf("放行端口 %s 失败: %w", p, err)
				}
				changed = true
			}
		}
		for _, p := range st.Ports {
			if !want[p] {
				_ = m.removeRule(st.Backend, p)
				changed = true
			}
		}
		if changed && st.Backend == "firewalld" {
			_, _ = m.runner().Run("firewall-cmd", "--reload")
		}
	}
	st.Ports = desired
	return m.saveState(st)
}

// Status 返回给 CLI 展示的人类可读状态。
func (m *Manager) Status(db *gorm.DB) string {
	st, err := m.LoadState()
	if err != nil {
		return fmt.Sprintf("防火墙状态读取失败: %v", err)
	}
	detected := m.Detect()
	if detected == "" {
		detected = "无（ufw/firewalld/iptables 均未安装）"
	}
	if !st.Enabled {
		return fmt.Sprintf("防火墙: 未开启（cx-box 未托管）\n检测到的后端: %s", detected)
	}
	parts := make([]string, 0, len(st.Ports))
	for _, p := range st.Ports {
		parts = append(parts, p.String())
	}
	return fmt.Sprintf("防火墙: 已开启（后端 %s）\ncx-box 放行端口: %s",
		st.Backend, strings.Join(parts, ", "))
}

func (m *Manager) addRule(backend string, p PortRule) error {
	var err error
	switch backend {
	case "ufw":
		_, err = m.runner().Run("ufw", "allow", p.String())
	case "firewalld":
		_, err = m.runner().Run("firewall-cmd", "--permanent", "--add-port="+p.String())
	default:
		return fmt.Errorf("未知防火墙后端 %s", backend)
	}
	return err
}

func (m *Manager) removeRule(backend string, p PortRule) error {
	var err error
	switch backend {
	case "ufw":
		_, err = m.runner().Run("ufw", "delete", "allow", p.String())
	case "firewalld":
		_, err = m.runner().Run("firewall-cmd", "--permanent", "--remove-port="+p.String())
	default:
		return fmt.Errorf("未知防火墙后端 %s", backend)
	}
	return err
}

// iptablesBins 返回要操作的 iptables 二进制（v4 必有，v6 有则一并）。
func (m *Manager) iptablesBins() []string {
	bins := []string{"iptables"}
	if m.look("ip6tables") {
		bins = append(bins, "ip6tables")
	}
	return bins
}

// iptablesRebuild 重建 CX-BOX 链：回环与已建立连接放行 → 各端口放行
// → 其余 DROP；链挂在 INPUT 最前面。整链重建保证规则顺序与集合一致。
func (m *Manager) iptablesRebuild(ports []PortRule) error {
	for _, bin := range m.iptablesBins() {
		run := func(args ...string) {
			_, _ = m.runner().Run(bin, args...)
		}
		run("-N", "CX-BOX")
		run("-F", "CX-BOX")
		if _, err := m.runner().Run(bin, "-C", "INPUT", "-j", "CX-BOX"); err != nil {
			if _, err := m.runner().Run(bin, "-I", "INPUT", "1", "-j", "CX-BOX"); err != nil {
				return fmt.Errorf("%s 挂载 CX-BOX 链失败: %w", bin, err)
			}
		}
		run("-A", "CX-BOX", "-i", "lo", "-j", "ACCEPT")
		run("-A", "CX-BOX", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
		for _, p := range ports {
			run("-A", "CX-BOX", "-p", p.Proto, "--dport", strconv.Itoa(p.Port), "-j", "ACCEPT")
		}
		run("-A", "CX-BOX", "-j", "DROP")
	}
	return nil
}

// iptablesTeardown 摘除 CX-BOX 链（先摘跳转再清空删除）。
func (m *Manager) iptablesTeardown() {
	for _, bin := range m.iptablesBins() {
		_, _ = m.runner().Run(bin, "-D", "INPUT", "-j", "CX-BOX")
		_, _ = m.runner().Run(bin, "-F", "CX-BOX")
		_, _ = m.runner().Run(bin, "-X", "CX-BOX")
	}
}

// iptablesPersist 尽力持久化 iptables 规则（失败不报错，运行时规则已生效）。
func (m *Manager) iptablesPersist() {
	if m.look("netfilter-persistent") {
		_, _ = m.runner().Run("netfilter-persistent", "save")
		return
	}
	if st, err := os.Stat("/etc/iptables"); err == nil && st.IsDir() {
		_, _ = m.runner().Run("sh", "-c", "iptables-save > /etc/iptables/rules.v4")
		if m.look("ip6tables") {
			_, _ = m.runner().Run("sh", "-c", "ip6tables-save > /etc/iptables/rules.v6")
		}
	}
}
