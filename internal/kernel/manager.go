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
	"sync"
)

// DefaultVersion 是默认使用的 sing-box 版本。
const DefaultVersion = "1.14.4"

// Manager 管理 sing-box 二进制与进程。
type Manager struct {
	mu       sync.Mutex
	dataDir  string
	version  string
	cmd      *exec.Cmd
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

// EnsureBinary 确保二进制存在；缺失时从 URL 下载。
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
	if err := downloadFile(downloadURL, p); err != nil {
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
	m.cmd = exec.CommandContext(ctx, m.BinaryPath(), "run", "-c", m.ConfigPath())
	m.cmd.Stdout = os.Stdout
	m.cmd.Stderr = os.Stderr
	if err := m.cmd.Start(); err != nil {
		return fmt.Errorf("kernel: 启动 sing-box 失败: %w", err)
	}
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
