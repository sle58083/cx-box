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
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/kernel"
	"github.com/sle58083/cx-box/internal/model"
	"github.com/sle58083/cx-box/internal/renderer"
	"github.com/sle58083/cx-box/internal/service"
)

// Service 是配置生成与应用的服务（单体版）。
type Service struct {
	db        *gorm.DB
	generator *Generator
	kernel    *kernel.Manager

	// ipBlocks 是 IP 数限制的当前封锁集合（客户端 ID → 被拒来源 IP），
	// 由流量采集器检测超限后经 SetIPBlocks 注入，随每次 Generate 生效。
	ipMu     sync.Mutex
	ipBlocks map[string][]string
}

// SetIPBlocks 更新 IP 数限制的封锁集合（采集器在集合变化时调用，
// 随后触发 Apply 让新配置生效）。
func (s *Service) SetIPBlocks(blocks map[string][]string) {
	s.ipMu.Lock()
	defer s.ipMu.Unlock()
	cp := make(map[string][]string, len(blocks))
	for k, v := range blocks {
		cp[k] = append([]string(nil), v...)
	}
	s.ipBlocks = cp
}

// ipBlocksSnapshot 返回封锁集合的副本（Generate 用）。
func (s *Service) ipBlocksSnapshot() map[string][]string {
	s.ipMu.Lock()
	defer s.ipMu.Unlock()
	if len(s.ipBlocks) == 0 {
		return nil
	}
	cp := make(map[string][]string, len(s.ipBlocks))
	for k, v := range s.ipBlocks {
		cp[k] = append([]string(nil), v...)
	}
	return cp
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

	// 自动证书兜底：需要 TLS 证书但既没绑定证书、也没写证书路径的入站，
	// 注入面板自动生成的共享自签证书，保证免绑证书一键应用。
	if err := s.ensureAutoCerts(ctx, inbounds); err != nil {
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
		IPBlocks:   s.ipBlocksSnapshot(),
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
	// 先写临时文件校验，通过后才原子替换正式文件：校验失败时磁盘上
	// 保留上一份好配置，服务重启不会因坏文件起不来内核（旧实现先覆盖
	// 再校验，坏文件会留盘）。
	tmpPath := configPath + ".tmp"
	defer os.Remove(tmpPath)
	if err := os.WriteFile(tmpPath, raw, 0o644); err != nil {
		return fmt.Errorf("configsvc: 写盘失败: %w", err)
	}
	if err := s.kernel.CheckFile(tmpPath); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, configPath); err != nil {
		return fmt.Errorf("configsvc: 写盘失败: %w", err)
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
			// TLS 存的是 JSON 字面量 null 时 Unmarshal 会把 map 置 nil，
			// 下面写 certificate_path 就会 panic（assignment to entry in
			// nil map，真机踩中：证书绑定的 vmess 入站 TLS 为 null）。
			if tls == nil {
				tls = map[string]any{}
			}
		}
		// Reality 不使用证书文件：绑了证书的 Reality 入站若注入证书路径，
		// sing-box 校验直接 FATAL（certificate is unavailable in reality），
		// 整份配置无法应用（真机踩中：内核一直跑旧配置、新客户端全部
		// unknown UUID）。Reality 入站跳过证书路径注入。
		if _, hasReality := tls["reality"]; hasReality {
			continue
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

// ensureAutoCerts 为「启用了普通 TLS、没有 Reality、未绑定证书且未写证书
// 路径」的入站注入自动证书路径（就地修改 inbounds）。覆盖 trojan /
// hysteria2 / tuic / anytls 以及 plain-TLS 的 vless 等一切需要证书的入站。
func (s *Service) ensureAutoCerts(ctx context.Context, inbounds []model.Inbound) error {
	if s.kernel == nil {
		return nil
	}
	for i := range inbounds {
		in := &inbounds[i]
		if in.CertID != nil && *in.CertID != "" {
			continue
		}
		if len(in.TLS) == 0 {
			continue
		}
		tls := map[string]any{}
		if err := json.Unmarshal(in.TLS, &tls); err != nil {
			continue // TLS 本身不合法时留给 renderer 报错，不在这里掩盖
		}
		if tls == nil {
			continue // TLS 为 JSON null，等同未配置
		}
		if enabled, _ := tls["enabled"].(bool); !enabled {
			continue
		}
		if _, hasReality := tls["reality"]; hasReality {
			continue
		}
		cp, _ := tls["certificate_path"].(string)
		kp, _ := tls["key_path"].(string)
		if cp != "" && kp != "" {
			continue
		}
		cert, err := s.autoCert(ctx)
		if err != nil {
			return err
		}
		if err := s.kernel.WriteCert(cert.ID.String(), cert.CertPEM, cert.KeyPEM); err != nil {
			return err
		}
		certFile, keyFile := s.kernel.CertPaths(cert.ID.String())
		if cp == "" {
			tls["certificate_path"] = certFile
		}
		if kp == "" {
			tls["key_path"] = keyFile
		}
		raw, err := json.Marshal(tls)
		if err != nil {
			return err
		}
		in.TLS = raw
	}
	return nil
}

// autoCert 返回面板自动证书（按名称查已有，没有就生成一张自签并落库）。
func (s *Service) autoCert(ctx context.Context) (*model.Certificate, error) {
	var cert model.Certificate
	err := s.db.WithContext(ctx).Where("name = ?", service.AutoCertName).First(&cert).Error
	if err == nil {
		return &cert, nil
	}
	if err != gorm.ErrRecordNotFound {
		return nil, fmt.Errorf("configsvc: 读取自动证书失败: %w", err)
	}
	created, err := service.NewCertificateService(s.db).SelfSigned(ctx, service.AutoCertName, []string{"www.bing.com"}, 3650)
	if err != nil {
		return nil, fmt.Errorf("configsvc: 生成自动证书失败: %w", err)
	}
	return created, nil
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
			ID:          c.ID.String(),
			Name:        c.ID.String(),
			UUID:        c.UUID,
			InboundIDs:  c.SelectedInboundIDs(),
			OutboundID:  c.OutboundID,
			OutboundIDs: c.SelectedOutboundIDs(),
			Password:    c.Password,
		})
		// 派生用户：为每个已选出口生成一个独立用户（凭据由客户端凭据
		// 确定性推导），订阅里每个出口一条独立链接，用户在客户端点哪个
		// 节点就走哪个出口；路由按派生用户名直达对应出口。
		seenOb := map[string]bool{}
		for _, obID := range c.SelectedOutboundIDs() {
			if seenOb[obID] {
				continue // 出口列表去重，避免同名派生用户重复注入
			}
			seenOb[obID] = true
			du := renderer.ProxyUser{
				ID:          c.ID.String(),
				Name:        renderer.DerivedUserName(c.ID.String(), obID),
				UUID:        renderer.DerivedUUID(c.UUID, obID),
				InboundIDs:  c.SelectedInboundIDs(),
				OutboundID:  obID,
				OutboundIDs: []string{obID},
			}
			du.Password = renderer.DerivedPassword(c.Password, obID)
			users = append(users, du)
		}
	}
	return users, nil
}
