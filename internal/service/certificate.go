package service

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/sle58083/cx-box/internal/model"
	"gorm.io/gorm"
)

// AutoCertName 是面板自动证书的名称：TLS 入站未绑定证书时，configsvc 用这张
// 共享自签证书兜底注入，保证「不绑证书也能一键应用」。它会出现在证书列表里，
// 用户随时可以改为绑定自己的证书。
const AutoCertName = "自动证书（系统生成）"

// CertificateService 管理证书：手动导入 PEM、一键自签、删除引用保护。
// 证书内容只存 DB（model.Certificate 的 PEM 字段不对 API 输出），
// 生成 sing-box 配置时由 configsvc 落盘到 etc/certs/ 并注入 TLS 路径。
type CertificateService struct{ db *gorm.DB }

func NewCertificateService(db *gorm.DB) *CertificateService { return &CertificateService{db: db} }

func (s *CertificateService) List(ctx context.Context) ([]model.Certificate, error) {
	var out []model.Certificate
	err := s.db.WithContext(ctx).Order("created_at ASC").Find(&out).Error
	return out, err
}

func (s *CertificateService) Get(ctx context.Context, id string) (*model.Certificate, error) {
	var c model.Certificate
	if err := s.db.WithContext(ctx).First(&c, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &c, nil
}

// Create 导入手动证书（PEM 对，校验解析与配对后落库）。
func (s *CertificateService) Create(ctx context.Context, name, certPEM, keyPEM string) (*model.Certificate, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("证书名称不能为空")
	}
	c := &model.Certificate{Name: name, Type: "manual", CertPEM: certPEM, KeyPEM: keyPEM}
	c.ID = model.NewID()
	if err := fillCertMeta(c); err != nil {
		return nil, err
	}
	if err := s.db.WithContext(ctx).Create(c).Error; err != nil {
		return nil, err
	}
	return c, nil
}

// SelfSigned 生成一张自签证书（ECDSA P-256）并落库。
// domains 里能解析为 IP 的进 IP SAN，其余进 DNS SAN；为空时默认 www.bing.com。
func (s *CertificateService) SelfSigned(ctx context.Context, name string, domains []string, days int) (*model.Certificate, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("证书名称不能为空")
	}
	if days <= 0 {
		days = 3650
	}
	if len(domains) == 0 {
		domains = []string{"www.bing.com"}
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成私钥失败: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domains[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, d := range domains {
		if ip := net.ParseIP(d); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, d)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("签发自签证书失败: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	domainsJSON, _ := json.Marshal(domains)
	c := &model.Certificate{
		Name: name, Type: "self_signed", Domains: string(domainsJSON),
		CertPEM: certPEM, KeyPEM: keyPEM,
	}
	c.ID = model.NewID()
	if err := fillCertMeta(c); err != nil {
		return nil, err
	}
	if err := s.db.WithContext(ctx).Create(c).Error; err != nil {
		return nil, err
	}
	return c, nil
}

// Delete 删除证书；被入站引用时拒绝，避免生成配置时悬空绑定。
func (s *CertificateService) Delete(ctx context.Context, id string) error {
	var refs int64
	if err := s.db.WithContext(ctx).Model(&model.Inbound{}).Where("cert_id = ?", id).Count(&refs).Error; err != nil {
		return err
	}
	if refs > 0 {
		return fmt.Errorf("证书正被 %d 个入站引用，请先解绑", refs)
	}
	return s.db.WithContext(ctx).Delete(&model.Certificate{}, "id = ?", id).Error
}

// fillCertMeta 解析 PEM 对、校验配对并回填元数据（域名/签发者/有效期/状态）。
func fillCertMeta(c *model.Certificate) error {
	certBlock, _ := pem.Decode([]byte(c.CertPEM))
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return errors.New("证书 PEM 无法解析")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("证书解析失败: %w", err)
	}
	pub, err := parsePrivateKeyPublic(c.KeyPEM)
	if err != nil {
		return err
	}
	certPubDER, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	keyPubDER, _ := x509.MarshalPKIXPublicKey(pub)
	if string(certPubDER) != string(keyPubDER) {
		return errors.New("证书与私钥不匹配")
	}
	sans := append([]string{}, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	domainsJSON, _ := json.Marshal(sans)
	c.Domains = string(domainsJSON)
	c.Issuer = cert.Issuer.CommonName
	nb, na := cert.NotBefore, cert.NotAfter
	c.NotBefore, c.NotAfter = &nb, &na
	if time.Now().After(na) {
		c.Status = "expired"
	} else {
		c.Status = "valid"
	}
	return nil
}

// parsePrivateKeyPublic 解析 PEM 私钥（PKCS8 / PKCS1 / EC）并返回其公钥。
func parsePrivateKeyPublic(keyPEM string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, errors.New("私钥 PEM 无法解析")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := k.(crypto.Signer); ok {
			return signer.Public(), nil
		}
		return nil, errors.New("私钥类型不支持")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k.Public(), nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k.Public(), nil
	}
	return nil, errors.New("私钥解析失败（需 PKCS8 / PKCS1 / EC 格式）")
}
