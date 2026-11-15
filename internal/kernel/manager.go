// Package kernel 负责 sing-box 二进制的下载与进程托管（单体单机精简版）。
//
// 与 yc-box 的 edge-agent kernel 不同：cx-box 是单机，内核直接托管在本进程，
// 无需版本池/原子切换/回滚等复杂逻辑，只需「下载 + 启停」。
package kernel

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// DefaultVersion 是默认使用的 sing-box 版本。
const DefaultVersion = "1.14.4"

// Manager 管理 sing-box 二进制与进程。
type Manager struct {
	mu         sync.Mutex
	dataDir    string
	version    string
	cmd        *exec.Cmd
	configPath string
}

// New 构造内核管理器。
// dataDir 是数据目录（bin/ 下放二进制，etc/ 下放 config.json）。
func New(dataDir, version string) *Manager {
	if version == "" {
		version = DefaultVersion
	}
	return &Manager{
		dataDir: dataDir,
		version: version,
	}
}

// BinaryPath 返回 sing-box 二进制路径。
func (m *Manager) BinaryPath() string {
	name := "sing-box"
	if runtime.GOOS == "windows" {
		name = "sing-box.exe"
	}
	return filepath.Join(m.dataDir, "bin", name)
}

// ConfigPath 返回配置路径。
func (m *Manager) ConfigPath() string {
	if m.configPath != "" {
		return m.configPath
	}
	return filepath.Join(m.dataDir, "etc", "config.json")
}

// SetConfigPath 覆盖配置路径。
func (m *Manager) SetConfigPath(p string) { m.configPath = p }

// DefaultDownloadURL 返回当前平台 sing-box 官方 Release 包地址。
// 官方资产形如 sing-box-<ver>-linux-amd64.tar.gz（包内文件夹含 sing-box 二进制）。
func (m *Manager) DefaultDownloadURL() string {
	arch := runtime.GOARCH
	if arch == "arm" {
		arch = "armv7" // 官方资产按 armv6/armv7 区分，运行时取不到 GOARM，默认 armv7
	}
	return fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/v%s/sing-box-%s-%s-%s.tar.gz",
		m.version, m.version, runtime.GOOS, arch)
}

// Running 返回 sing-box 进程是否在运行。
func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cmd != nil && m.cmd.Process != nil
}

// EnsureBinary 确保二进制存在；缺失时从 URL 下载。
// URL 以 .tar.gz 结尾时按官方 Release 包处理：下载后解出包内的 sing-box 二进制。
func (m *Manager) EnsureBinary(downloadURL string) error {
	p := m.BinaryPath()
	if _, err := os.Stat(p); err == nil {
		return nil // 已存在
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return fmt.Errorf("kernel: 创建 bin 目录失败: %w", err)
	}
	if downloadURL == "" {
		return fmt.Errorf("kernel: sing-box 二进制缺失且未提供下载地址: %s", p)
	}
	if strings.HasSuffix(downloadURL, ".tar.gz") {
		tmp := p + ".tar.gz"
		if err := downloadFile(downloadURL, tmp); err != nil {
			return fmt.Errorf("kernel: 下载 sing-box 失败: %w", err)
		}
		defer os.Remove(tmp)
		if err := extractSingBox(tmp, p); err != nil {
			return fmt.Errorf("kernel: 解包 sing-box 失败: %w", err)
		}
	} else if err := downloadFile(downloadURL, p); err != nil {
		return fmt.Errorf("kernel: 下载 sing-box 失败: %w", err)
	}
	if err := os.Chmod(p, 0o755); err != nil {
		return fmt.Errorf("kernel: 设置可执行权限失败: %w", err)
	}
	return nil
}

// Start 启动 sing-box 进程。
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil && m.cmd.Process != nil {
		return fmt.Errorf("kernel: sing-box 已在运行 (pid %d)", m.cmd.Process.Pid)
	}
	// 内核是守护进程，生命周期由 Stop 管理，不能绑定调用方 ctx：
	// 否则经 HTTP apply 触发的重启会在请求结束（ctx 取消）时被连带杀掉。
	cmd := exec.CommandContext(context.Background(), m.BinaryPath(), "run", "-c", m.ConfigPath())
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("kernel: 启动 sing-box 失败: %w", err)
	}
	m.cmd = cmd
	// 进程退出后清掉句柄，Running() 才不会误报。
	go func() {
		_ = cmd.Wait()
		m.mu.Lock()
		if m.cmd == cmd {
			m.cmd = nil
		}
		m.mu.Unlock()
	}()
	return nil
}

// Stop 停止 sing-box 进程。
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd == nil || m.cmd.Process == nil {
		return nil
	}
	if err := m.cmd.Process.Kill(); err != nil {
		return fmt.Errorf("kernel: 停止 sing-box 失败: %w", err)
	}
	m.cmd = nil
	return nil
}

// Restart 重启 sing-box（Stop → Start）。
func (m *Manager) Restart(ctx context.Context) error {
	if err := m.Stop(); err != nil {
		return err
	}
	return m.Start(ctx)
}

// Check 校验配置（sing-box check -c）。
func (m *Manager) Check() error {
	cmd := exec.Command(m.BinaryPath(), "check", "-c", m.ConfigPath())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("kernel: 配置校验失败: %v\n%s", err, string(out))
	}
	return nil
}

// downloadFile 下载文件到目标路径（带重试）。
func downloadFile(url, dest string) error {
	return downloadFileWithRetry(url, dest, 3)
}
