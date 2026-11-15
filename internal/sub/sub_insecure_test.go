package sub

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/model"
	"github.com/sle58083/cx-box/internal/service"
)

func makeCertPEM(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, isCA bool) (string, *x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		DNSNames:     []string{"test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	parent, parentKey := tpl, key
	if ca != nil {
		parent, parentKey = ca, caKey
	}
	if isCA {
		tpl.IsCA = true
		tpl.KeyUsage |= x509.KeyUsageCertSign
		tpl.BasicConstraintsValid = true
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), cert, key
}

func TestPEMSelfSigned(t *testing.T) {
	selfPEM, _, _ := makeCertPEM(t, nil, nil, false)
	if !pemSelfSigned(selfPEM) {
		t.Fatal("self-signed PEM should be detected")
	}
	_, caCert, caKey := makeCertPEM(t, nil, nil, true)
	leafPEM, _, _ := makeCertPEM(t, caCert, caKey, false)
	if pemSelfSigned(leafPEM) {
		t.Fatal("CA-signed PEM should not be detected as self-signed")
	}
	if pemSelfSigned("not a pem") {
		t.Fatal("garbage should not be self-signed")
	}
}

// TestLinksInsecureForSelfSignedCerts 端到端（生成器层）：
//   - trojan 入站未绑证书（自动证书兜底）→ 链接带 insecure=1；
//   - trojan 入站绑 CA 签发的正式证书 → 链接不带 insecure；
//   - vless Reality 入站 → 与证书无关，链接不带 insecure。
func TestLinksInsecureForSelfSignedCerts(t *testing.T) {
	g, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := g.AutoMigrate(&model.Inbound{}, &model.Client{}, &model.Certificate{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	_, caCert, caKey := makeCertPEM(t, nil, nil, true)
	leafPEM, _, _ := makeCertPEM(t, caCert, caKey, false)
	caCertModel := &model.Certificate{Name: "real", Type: "manual", CertPEM: leafPEM, KeyPEM: "x",
		Domains: `["test.example.com"]`}
	if err := g.Create(caCertModel).Error; err != nil {
		t.Fatalf("create cert: %v", err)
	}
	caID := caCertModel.ID.String()

	inSvc := service.NewInboundService(g)
	tlsOn := json.RawMessage(`{"enabled":true,"server_name":"test.example.com"}`)
	for _, in := range []*model.Inbound{
		{Name: "trojan-auto", Type: "trojan", Port: 4443, IsUserInbound: true, TLS: tlsOn},
		{Name: "trojan-ca", Type: "trojan", Port: 4444, IsUserInbound: true, TLS: tlsOn, CertID: &caID},
		{Name: "vless-reality", Type: "vless", Port: 443, IsUserInbound: true,
			TLS: json.RawMessage(`{"enabled":true,"server_name":"www.microsoft.com","reality":{"enabled":true,"private_key":"` +
				strings.Repeat("A", 43) + `","short_id":[""]}}`)},
	} {
		if err := inSvc.Create(in); err != nil {
			t.Fatalf("create inbound %s: %v", in.Name, err)
		}
	}
	clSvc := service.NewClientService(g)
	c := &model.Client{Email: "u@example.com", Enable: true}
	if err := clSvc.Create(c); err != nil {
		t.Fatalf("create client: %v", err)
	}
	links, _, err := New(g).Links(c.SubID, "example.com")
	if err != nil {
		t.Fatalf("links: %v", err)
	}
	byName := map[string]string{}
	for _, ln := range links {
		if i := strings.LastIndex(ln, "#"); i >= 0 {
			byName[ln[i+1:]] = ln
		}
	}
	if ln := byName["trojan-auto"]; !strings.Contains(ln, "insecure=1") {
		t.Fatalf("trojan-auto link should carry insecure=1: %s", ln)
	}
	if ln := byName["trojan-ca"]; ln == "" || strings.Contains(ln, "insecure") {
		t.Fatalf("trojan-ca link should not carry insecure: %s", ln)
	}
	if ln := byName["vless-reality"]; ln == "" || strings.Contains(ln, "insecure") {
		t.Fatalf("vless reality link should not carry insecure: %s", ln)
	}
}
