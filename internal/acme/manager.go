package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/model"
)

// Manager 管理 ACME 自动证书：配置（邮箱/令牌）保存、异步签发、到期续签。
// 令牌与账户私钥只存 settings 表中 json:"-" 的字段，永不经 API 返回。
type Manager struct {
	db *gorm.DB

	// DirURL / CFBaseURL 可覆盖（测试用）；为空用正式环境。
	DirURL    string
	CFBaseURL string
	// OnIssued 签发/续签成功后的回调（通常是重新应用内核配置）。
	OnIssued func(ctx context.Context)

	// issueFn 是签发实现，测试可注入假实现。
	issueFn func(ctx context.Context, domains []string, email, token string, accountKey *ecdsa.PrivateKey) (string, string, error)

	mu      sync.Mutex
	issuing map[string]bool
}

// NewManager 构造管理器。
func NewManager(db *gorm.DB) *Manager {
	return &Manager{db: db, issuing: map[string]bool{}}
}

// Config 返回当前 ACME 配置状态（令牌只报是否已配置，永不回明文）。
func (m *Manager) Config() (email string, tokenConfigured bool, err error) {
	st, err := m.setting()
	if err != nil {
		return "", false, err
	}
	return st.ACMEEmail, strings.TrimSpace(st.ACMECFToken) != "", nil
}

// SaveConfig 保存邮箱与令牌。令牌为空表示保留原值（前端不回显明文，
// 用户不重填就沿用已保存的）。
func (m *Manager) SaveConfig(email, token string) error {
	st, err := m.setting()
	if err != nil {
		return err
	}
	updates := map[string]any{"acme_email": strings.TrimSpace(email)}
	if strings.TrimSpace(token) != "" {
		updates["acme_cf_token"] = strings.TrimSpace(token)
	}
	return m.db.Model(&model.Setting{}).Where("id = ?", st.ID).Updates(updates).Error
}

func (m *Manager) setting() (*model.Setting, error) {
	var st model.Setting
	if err := m.db.First(&st).Error; err != nil {
		return nil, fmt.Errorf("acme: 读取设置失败: %w", err)
	}
	return &st, nil
}

// NormalizeDomains 清洗域名列表：去空白、转小写、去重、保序。
func NormalizeDomains(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range in {
		d = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(d, ".")))
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// ValidateDomains 校验域名列表（允许 *.example.com 泛域名）。
func ValidateDomains(domains []string) error {
	if len(domains) == 0 {
		return fmt.Errorf("至少填写一个域名")
	}
	for _, d := range domains {
		base := strings.TrimPrefix(d, "*.")
		if !strings.Contains(base, ".") || strings.ContainsAny(base, " \t/\\:*") {
			return fmt.Errorf("域名格式不对: %s", d)
		}
	}
	return nil
}

// CreateAndIssue 建一条 acme 证书记录（状态 issuing）并异步开始签发。
func (m *Manager) CreateAndIssue(name string, domains []string, email, token string) (*model.Certificate, error) {
	domains = NormalizeDomains(domains)
	if err := ValidateDomains(domains); err != nil {
		return nil, err
	}
	if strings.TrimSpace(email) == "" || !strings.Contains(email, "@") {
		return nil, fmt.Errorf("请填写有效的邮箱（Let's Encrypt 账户邮箱，到期/异常通知会发到这里）")
	}
	if err := m.SaveConfig(email, token); err != nil {
		return nil, err
	}
	st, err := m.setting()
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(st.ACMECFToken) == "" {
		return nil, fmt.Errorf("请填写 Cloudflare API 令牌")
	}
	domainsJSON, _ := json.Marshal(domains)
	cert := &model.Certificate{
		Name:    name,
		Type:    "acme",
		Domains: string(domainsJSON),
		Status:  "issuing",
	}
	cert.ID = model.NewID()
	if err := m.db.Create(cert).Error; err != nil {
		return nil, fmt.Errorf("acme: 创建证书记录失败: %w", err)
	}
	go m.issue(cert.ID.String())
	return cert, nil
}

// RenewDue 检查所有 acme 证书：已过期/30 天内到期/上次失败的重新签发。
// 由 run.go 的每日任务调用。
func (m *Manager) RenewDue(ctx context.Context) {
	var certs []model.Certificate
	if err := m.db.WithContext(ctx).Where("type = ?", "acme").Find(&certs).Error; err != nil {
		return
	}
	now := time.Now()
	for _, cert := range certs {
		due := false
		switch {
		case cert.Status == "failed":
			due = true
		case cert.NotAfter != nil && cert.NotAfter.Before(now.Add(30*24*time.Hour)):
			due = true
		case cert.Status == "valid" && cert.NotAfter == nil:
			due = true
		}
		if due {
			m.issue(cert.ID.String())
		}
	}
}

// issue 执行一次签发（同步），全程更新证书记录状态。
func (m *Manager) issue(certID string) {
	m.mu.Lock()
	if m.issuing[certID] {
		m.mu.Unlock()
		return
	}
	m.issuing[certID] = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.issuing, certID)
		m.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	fail := func(err error) {
		_ = m.db.Model(&model.Certificate{}).Where("id = ?", certID).
			Updates(map[string]any{"status": "failed", "last_error": err.Error()}).Error
	}

	var cert model.Certificate
	if err := m.db.WithContext(ctx).First(&cert, "id = ?", certID).Error; err != nil {
		return // 记录已被删除，无声结束
	}
	_ = m.db.Model(&model.Certificate{}).Where("id = ?", certID).
		Updates(map[string]any{"status": "issuing", "last_error": ""}).Error

	st, err := m.setting()
	if err != nil {
		fail(err)
		return
	}
	if strings.TrimSpace(st.ACMECFToken) == "" || strings.TrimSpace(st.ACMEEmail) == "" {
		fail(fmt.Errorf("ACME 配置不完整：请先在证书页填写邮箱与 Cloudflare 令牌"))
		return
	}
	accountKey, err := m.accountKey(st)
	if err != nil {
		fail(err)
		return
	}
	domains := NormalizeDomains(mustJSONStrings(cert.Domains))
	if err := ValidateDomains(domains); err != nil {
		fail(err)
		return
	}

	issueFn := m.issueFn
	if issueFn == nil {
		dir := m.DirURL
		if dir == "" {
			dir = DefaultDirectory
		}
		iss := &issuer{dirURL: dir, email: st.ACMEEmail, accountKey: accountKey,
			cf: newCFClient(st.ACMECFToken, m.CFBaseURL)}
		issueFn = func(ctx context.Context, domains []string, _, _ string, _ *ecdsa.PrivateKey) (string, string, error) {
			return iss.issue(ctx, domains)
		}
	}
	certPEM, keyPEM, err := issueFn(ctx, domains, st.ACMEEmail, st.ACMECFToken, accountKey)
	if err != nil {
		fail(err)
		return
	}
	leaf, err := parseLeaf(certPEM)
	if err != nil {
		fail(fmt.Errorf("签发结果解析失败: %w", err))
		return
	}
	err = m.db.Model(&model.Certificate{}).Where("id = ?", certID).Updates(map[string]any{
		"cert_pem":   certPEM,
		"key_pem":    keyPEM,
		"issuer":     leaf.Issuer.String(),
		"not_before": leaf.NotBefore,
		"not_after":  leaf.NotAfter,
		"status":     "valid",
		"last_error": "",
	}).Error
	if err != nil {
		fail(fmt.Errorf("保存签发结果失败: %w", err))
		return
	}
	if m.OnIssued != nil {
		m.OnIssued(ctx)
	}
}

// accountKey 读取已保存的 ACME 账户私钥；没有则生成并落库。
func (m *Manager) accountKey(st *model.Setting) (*ecdsa.PrivateKey, error) {
	if strings.TrimSpace(st.ACMEAccountKey) != "" {
		block, _ := pem.Decode([]byte(st.ACMEAccountKey))
		if block != nil {
			if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
				return key, nil
			}
			if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				if ek, ok := k.(*ecdsa.PrivateKey); ok {
					return ek, nil
				}
			}
		}
		return nil, fmt.Errorf("已保存的 ACME 账户私钥无法解析")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成 ACME 账户私钥失败: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	if err := m.db.Model(&model.Setting{}).Where("id = ?", st.ID).
		Update("acme_account_key", pemStr).Error; err != nil {
		return nil, fmt.Errorf("保存 ACME 账户私钥失败: %w", err)
	}
	return key, nil
}

func mustJSONStrings(s string) []string {
	var out []string
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

// parseLeaf 解析 PEM 证书链的第一张（叶子）证书。
func parseLeaf(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("PEM 中没有证书块")
	}
	return x509.ParseCertificate(block.Bytes)
}
