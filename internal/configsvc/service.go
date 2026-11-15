// Package configsvc 负责「中立模型 → sing-box 原生 JSON」的生成与应用（单体版）。
package configsvc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

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

	// 证书绑定解析：入站绑了 cert_id 时把证书落盘，并把路径注入其 TLS
	// （TLS 里已显式写了 certificate_path/key_path 的不覆盖）。
	if err := s.resolveCertBindings(ctx, inbounds); err != nil {
		return nil, err
	}

	secret, err := s.EnsureAPISecret(ctx)
	if err != nil {
		return nil, err
	}

	return s.generator.Generate(&NodeConfigContext{
		Global:     DefaultGlobalSettings(),
		Inbounds:   inbounds,
		Outbounds:  outbounds,
		Rules:      rules,
		ProxyUsers: users,
		APISecret:  secret,
	})
}

// EnsureAPISecret 返回 sing-box api service 的密钥；设置行里没有时生成并落库。
// 采集器（internal/traffic）与生成器共用这一份，保证配置与采集端一致。
func (s *Service) EnsureAPISecret(ctx context.Context) (string, error) {
	var st model.Setting
	if err := s.db.WithContext(ctx).First(&st).Error; err != nil {
		if err != gorm.ErrRecordNotFound {
			return "", fmt.Errorf("configsvc: 读取设置失败: %w", err)
		}
		st = model.Setting{PanelPort: 2095, PanelPath: "/app/", SubPort: 2096, SubPath: "/sub/"}
		if err := s.db.WithContext(ctx).Create(&st).Error; err != nil {
			return "", fmt.Errorf("configsvc: 创建默认设置失败: %w", err)
		}
	}
	if st.APISecret != "" {
		return st.APISecret, nil
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("configsvc: 生成 api 密钥失败: %w", err)
	}
	secret := hex.EncodeToString(buf)
	if err := s.db.WithContext(ctx).Model(&model.Setting{}).Where("id = ?", st.ID).
		Update("api_secret", secret).Error; err != nil {
		return "", fmt.Errorf("configsvc: 保存 api 密钥失败: %w", err)
	}
	return secret, nil
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

// resolveCertBindings 把入站的证书绑定落盘并注入 TLS 证书路径（就地修改 inbounds）。
func (s *Service) resolveCertBindings(ctx context.Context, inbounds []model.Inbound) error {
	for i := range inbounds {
		certID := inbounds[i].CertID
		if certID == nil || *certID == "" || s.kernel == nil {
			continue
		}
		var cert model.Certificate
		if err := s.db.WithContext(ctx).First(&cert, "id = ?", *certID).Error; err != nil {
			return fmt.Errorf("configsvc: 入站 %q 绑定的证书不存在: %s", inbounds[i].Name, *certID)
		}
		if err := s.kernel.WriteCert(cert.ID.String(), cert.CertPEM, cert.KeyPEM); err != nil {
			return err
		}
		certFile, keyFile := s.kernel.CertPaths(cert.ID.String())
		tls := map[string]any{}
		if len(inbounds[i].TLS) > 0 {
			if err := json.Unmarshal(inbounds[i].TLS, &tls); err != nil {
				return fmt.Errorf("configsvc: 入站 %q 的 TLS 不是合法 JSON: %w", inbounds[i].Name, err)
			}
		}
		if _, ok := tls["certificate_path"]; !ok {
			tls["certificate_path"] = certFile
		}
		if _, ok := tls["key_path"]; !ok {
			tls["key_path"] = keyFile
		}
		raw, err := json.Marshal(tls)
		if err != nil {
			return err
		}
		inbounds[i].TLS = raw
	}
	return nil
}

// activeUsers 返回可下发到 sing-box 的客户端（转为 renderer.ProxyUser）。
// 过滤：未启用、已到期、已用完流量配额的客户端不注入内核配置——到期/超额
// 即断网，订阅侧也会拒绝（见 internal/sub）。采集器落库后若发现超额会触发
// 重新 Apply，让剔除及时生效。
func (s *Service) activeUsers(ctx context.Context) ([]renderer.ProxyUser, error) {
	var clients []model.Client
	if err := s.db.WithContext(ctx).Where("enable = ?", true).Find(&clients).Error; err != nil {
		return nil, fmt.Errorf("configsvc: 读取客户端失败: %w", err)
	}
	now := time.Now().Unix()
	users := make([]renderer.ProxyUser, 0, len(clients))
	for _, c := range clients {
		if c.ExpiryTime > 0 && c.ExpiryTime <= now {
			continue
		}
		if c.TotalGB > 0 && c.UsedBytes >= c.TotalGB*1024*1024*1024 {
			continue
		}
		users = append(users, renderer.ProxyUser{
			ID:       c.ID.String(),
			Name:     c.ID.String(),
			UUID:     c.UUID,
			Password: c.Password,
		})
	}
	return users, nil
}
