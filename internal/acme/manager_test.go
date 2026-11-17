package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/model"
)

func testDB(t *testing.T) *gorm.DB {
	t.Helper()
	g, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	// :memory: 每个连接是独立的库；签发在 goroutine 里跑，必须钉死单
	// 连接，否则并发下连接池开新连接会读到空库（全量跑偶发失败的根因）。
	if sqlDB, err := g.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	if err := g.AutoMigrate(&model.Setting{}, &model.Certificate{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := g.Create(&model.Setting{PanelPort: 2095, PanelPath: "/app/", SubPort: 2096, SubPath: "/sub/"}).Error; err != nil {
		t.Fatalf("seed setting: %v", err)
	}
	return g
}

// fakeCertPEM 生成一张指定到期时间的自签证书 PEM（假签发结果）。
func fakeCertPEM(t *testing.T, notAfter time.Time) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

func waitStatus(t *testing.T, g *gorm.DB, id, want string) model.Certificate {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		var cert model.Certificate
		if err := g.First(&cert, "id = ?", id).Error; err == nil && cert.Status == want {
			return cert
		}
		time.Sleep(50 * time.Millisecond)
	}
	var cert model.Certificate
	_ = g.First(&cert, "id = ?", id).Error
	t.Fatalf("证书状态未变为 %s（当前 %s, err=%s）", want, cert.Status, cert.LastError)
	return cert
}

// TestSaveConfigSecrecy 令牌保存后只报「已配置」；Setting 的 JSON
// 序列化里绝不能出现令牌/账户私钥明文。
func TestSaveConfigSecrecy(t *testing.T) {
	g := testDB(t)
	m := NewManager(g)
	if err := m.SaveConfig("me@example.com", "cf-token-SECRET123"); err != nil {
		t.Fatalf("save: %v", err)
	}
	email, configured, err := m.Config()
	if err != nil || email != "me@example.com" || !configured {
		t.Fatalf("config = %q, %v, %v", email, configured, err)
	}
	// 空令牌保存 = 保留原值。
	if err := m.SaveConfig("me@example.com", ""); err != nil {
		t.Fatalf("save2: %v", err)
	}
	var st model.Setting
	if err := g.First(&st).Error; err != nil {
		t.Fatalf("load setting: %v", err)
	}
	if st.ACMECFToken != "cf-token-SECRET123" {
		t.Fatalf("空令牌保存应保留原令牌, got %q", st.ACMECFToken)
	}
	raw, _ := json.Marshal(st)
	if strings.Contains(string(raw), "cf-token-SECRET123") {
		t.Fatalf("Setting JSON 泄漏了令牌: %s", raw)
	}
}

// TestCreateAndIssueFlow 假签发成功：记录被填满、状态 valid、回调触发。
func TestCreateAndIssueFlow(t *testing.T) {
	g := testDB(t)
	m := NewManager(g)
	certPEM, keyPEM := fakeCertPEM(t, time.Now().Add(90*24*time.Hour))
	m.issueFn = func(ctx context.Context, domains []string, email, token string, key *ecdsa.PrivateKey) (string, string, error) {
		if token != "tok-abc" {
			t.Errorf("issueFn 收到的令牌不对: %q", token)
		}
		return certPEM, keyPEM, nil
	}
	var applied atomic.Int32
	m.OnIssued = func(ctx context.Context) { applied.Add(1) }

	cert, err := m.CreateAndIssue("我的证书", []string{"Example.COM", "*.example.com"}, "me@example.com", "tok-abc")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got := waitStatus(t, g, cert.ID.String(), "valid")
	if got.CertPEM != certPEM || got.KeyPEM != keyPEM {
		t.Fatalf("PEM 未正确落库")
	}
	if got.NotAfter == nil || got.Issuer == "" {
		t.Fatalf("证书元信息未填充: %+v", got)
	}
	if applied.Load() != 1 {
		t.Fatalf("OnIssued 应被调用一次, got %d", applied.Load())
	}
	// 账户私钥已生成并落库（后续签发复用同一账户）。
	var st model.Setting
	if err := g.First(&st).Error; err != nil {
		t.Fatalf("load setting: %v", err)
	}
	if st.ACMEAccountKey == "" {
		t.Fatalf("账户私钥未落库")
	}
	raw, _ := json.Marshal(st)
	if strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatalf("Setting JSON 泄漏了账户私钥")
	}
}

// TestIssueFailure 签发失败时状态落 failed 并记录原因，不 panic。
func TestIssueFailure(t *testing.T) {
	g := testDB(t)
	m := NewManager(g)
	m.issueFn = func(ctx context.Context, domains []string, email, token string, key *ecdsa.PrivateKey) (string, string, error) {
		return "", "", errors.New("模拟签发失败")
	}
	cert, err := m.CreateAndIssue("坏证书", []string{"example.com"}, "me@example.com", "tok")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got := waitStatus(t, g, cert.ID.String(), "failed")
	if !strings.Contains(got.LastError, "模拟签发失败") {
		t.Fatalf("last_error 应记录失败原因, got %q", got.LastError)
	}
}

// TestRenewDue 临期与失败的证书会被重签，健康证书不动。
func TestRenewDue(t *testing.T) {
	g := testDB(t)
	m := NewManager(g)
	var calls atomic.Int32
	certPEM, keyPEM := fakeCertPEM(t, time.Now().Add(90*24*time.Hour))
	m.issueFn = func(ctx context.Context, domains []string, email, token string, key *ecdsa.PrivateKey) (string, string, error) {
		calls.Add(1)
		return certPEM, keyPEM, nil
	}
	if err := m.SaveConfig("me@example.com", "tok"); err != nil {
		t.Fatalf("save config: %v", err)
	}
	mk := func(name, status string, notAfter *time.Time) {
		domains, _ := json.Marshal([]string{"example.com"})
		c := &model.Certificate{Name: name, Type: "acme", Domains: string(domains),
			Status: status, NotAfter: notAfter}
		c.ID = model.NewID()
		if err := g.Create(c).Error; err != nil {
			t.Fatalf("create cert %s: %v", name, err)
		}
	}
	soon := time.Now().Add(10 * 24 * time.Hour)
	far := time.Now().Add(80 * 24 * time.Hour)
	mk("临期", "valid", &soon)
	mk("健康", "valid", &far)
	mk("失败", "failed", nil)
	m.RenewDue(context.Background())
	if calls.Load() != 2 {
		t.Fatalf("应重签 2 张（临期+失败）, 实际 %d", calls.Load())
	}
}

// TestValidateDomains 域名清洗与校验。
func TestValidateDomains(t *testing.T) {
	got := NormalizeDomains([]string{" EXAMPLE.com ", "example.com", "*.Example.com", ""})
	if len(got) != 2 || got[0] != "example.com" || got[1] != "*.example.com" {
		t.Fatalf("normalize = %v", got)
	}
	if err := ValidateDomains([]string{"example.com", "*.example.com"}); err != nil {
		t.Fatalf("合法域名被拒: %v", err)
	}
	for _, bad := range [][]string{{}, {"nodot"}, {"exa mple.com"}, {"http://example.com"}, {"*.*.example.com"}} {
		if err := ValidateDomains(NormalizeDomains(bad)); err == nil {
			t.Fatalf("非法域名 %v 应被拒绝", bad)
		}
	}
}
