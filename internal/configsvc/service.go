// Package configsvc 负责「中立模型 → sing-box 原生 JSON」的生成与应用（单体版）。
package configsvc

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/kernel"
	"github.com/sle58083/cx-box/internal/model"
	"github.com/sle58083/cx-box/internal/renderer"
)

// Service 是配置生成与应用的服务（单体版）。
type Service struct {
	db        *gorm.DB
	generator *Generator
	kernel    *kernel.Manager
}

// NewService 构造配置服务。
func NewService(db *gorm.DB, km *kernel.Manager) *Service {
	return &Service{
		db:        db,
		generator: NewGenerator(),
		kernel:    km,
	}
}

// Generate 从数据库读取所有配置，生成 sing-box 原生 JSON（map）。
func (s *Service) Generate(ctx context.Context) (map[string]any, error) {
	var inbounds []model.Inbound
	if err := s.db.WithContext(ctx).Where("status = ?", model.StatusEnabled).Find(&inbounds).Error; err != nil {
		return nil, fmt.Errorf("configsvc: 读取入站失败: %w", err)
	}
	var outbounds []model.Outbound
	if err := s.db.WithContext(ctx).Where("status = ?", model.StatusEnabled).Find(&outbounds).Error; err != nil {
		return nil, fmt.Errorf("configsvc: 读取出站失败: %w", err)
	}
	var rules []model.RoutingRule
	if err := s.db.WithContext(ctx).Where("enabled = ?", true).Order("priority ASC").Find(&rules).Error; err != nil {
		return nil, fmt.Errorf("configsvc: 读取路由规则失败: %w", err)
	}

	// 读取客户端（is_user_inbound 入站需要注入用户）
	users, err := s.activeUsers(ctx)
	if err != nil {
		return nil, err
	}

	return s.generator.Generate(&NodeConfigContext{
		Global:     DefaultGlobalSettings(),
		Inbounds:   inbounds,
		Outbounds:  outbounds,
		Rules:      rules,
		ProxyUsers: users,
	})
}

// Apply 生成配置 → 写盘 → 校验 → 重启 sing-box。
func (s *Service) Apply(ctx context.Context) error {
	doc, err := s.Generate(ctx)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("configsvc: marshal 失败: %w", err)
	}

	configPath := s.kernel.ConfigPath()
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(configPath, raw, 0o644); err != nil {
		return fmt.Errorf("configsvc: 写盘失败: %w", err)
	}

	// 校验 + 重启
	if err := s.kernel.Check(); err != nil {
		return err
	}
	return s.kernel.Restart(ctx)
}

// activeUsers 返回启用状态的客户端（转为 renderer.ProxyUser）。
func (s *Service) activeUsers(ctx context.Context) ([]renderer.ProxyUser, error) {
	var clients []model.Client
	if err := s.db.WithContext(ctx).Where("enable = ?", true).Find(&clients).Error; err != nil {
		return nil, fmt.Errorf("configsvc: 读取客户端失败: %w", err)
	}
	users := make([]renderer.ProxyUser, 0, len(clients))
	for _, c := range clients {
		users = append(users, renderer.ProxyUser{
			ID:       c.ID.String(),
			Name:     c.ID.String(),
			UUID:     c.UUID,
			Password: c.Password,
		})
	}
	return users, nil
}
