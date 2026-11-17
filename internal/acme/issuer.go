package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
)

// DefaultDirectory Let's Encrypt 正式环境。
const DefaultDirectory = "https://acme-v02.api.letsencrypt.org/directory"

// lookupTXT 可在测试中替换。
var lookupTXT = net.LookupTXT

type issuer struct {
	dirURL     string
	email      string
	accountKey crypto.Signer
	cf         *cfClient
}

// txtPending 是一条已创建、待校验的 DNS-01 TXT 记录。
type txtPending struct {
	chal  *acme.Challenge
	name  string
	value string
}

// issue 走完整的 ACME DNS-01 流程签发证书，返回证书链 PEM 与私钥 PEM。
func (is *issuer) issue(ctx context.Context, domains []string) (string, string, error) {
	client := &acme.Client{Key: is.accountKey, DirectoryURL: is.dirURL}
	if _, err := client.GetReg(ctx, ""); err != nil {
		acct := &acme.Account{Contact: []string{"mailto:" + is.email}}
		if _, err := client.Register(ctx, acct, acme.AcceptTOS); err != nil {
			return "", "", fmt.Errorf("注册 ACME 账户失败: %w", err)
		}
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(domains...))
	if err != nil {
		return "", "", fmt.Errorf("创建证书订单失败: %w", err)
	}

	// 先把所有 dns-01 的 TXT 记录都建好（同名多值是泛域名+主域名同签
	// 的常态），传播确认后再统一 Accept，避免逐个等待串行叠加。
	var pend []txtPending
	var cleanups []func()
	defer func() {
		for _, cl := range cleanups {
			cl()
		}
	}()
	for _, azURL := range order.AuthzURLs {
		az, err := client.GetAuthorization(ctx, azURL)
		if err != nil {
			return "", "", fmt.Errorf("获取域名验证信息失败: %w", err)
		}
		if az.Status == acme.StatusValid {
			continue // 账户此前已验证过该域名（有效期内的授权可复用）
		}
		var chal *acme.Challenge
		for _, ch := range az.Challenges {
			if ch.Type == "dns-01" {
				chal = ch
				break
			}
		}
		if chal == nil {
			return "", "", fmt.Errorf("域名 %s 没有可用的 dns-01 验证方式", az.Identifier.Value)
		}
		value, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return "", "", fmt.Errorf("计算验证记录失败: %w", err)
		}
		name := "_acme-challenge." + az.Identifier.Value
		cleanup, err := is.cf.present(ctx, name, value)
		if err != nil {
			return "", "", err
		}
		cleanups = append(cleanups, cleanup)
		pend = append(pend, txtPending{chal: chal, name: name, value: value})
	}

	if len(pend) > 0 {
		waitTXTPropagation(ctx, pend)
		for _, p := range pend {
			if _, err := client.Accept(ctx, p.chal); err != nil {
				return "", "", fmt.Errorf("提交域名验证失败: %w", err)
			}
		}
	}
	// WaitOrder 在订单 Ready（全部授权通过、待提交 CSR）或 Valid 时
	// 返回；提交 CSR 完成 finalize、再等到 Valid 并下载证书，都由
	// CreateOrderCert 内部完成。此处不能要求状态必须是 Valid——
	// Ready 才是 finalize 前的正常状态（v0.5.15 实测踩中：订单明明
	// 一切正常却报「证书订单状态异常: ready」）。
	finalOrder, err := client.WaitOrder(ctx, order.URI)
	if err != nil {
		return "", "", fmt.Errorf("等待域名验证完成失败: %w", err)
	}
	if finalOrder.Status != acme.StatusReady && finalOrder.Status != acme.StatusValid {
		return "", "", fmt.Errorf("证书订单状态异常: %s", finalOrder.Status)
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("生成证书私钥失败: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domains[0]},
		DNSNames: domains,
	}, certKey)
	if err != nil {
		return "", "", fmt.Errorf("生成 CSR 失败: %w", err)
	}
	derChain, _, err := client.CreateOrderCert(ctx, finalOrder.FinalizeURL, csrDER, true)
	if err != nil {
		return "", "", fmt.Errorf("下载证书失败: %w", err)
	}
	var certPEM strings.Builder
	for _, der := range derChain {
		_ = pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	keyDER, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return "", "", fmt.Errorf("编码证书私钥失败: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM.String(), string(keyPEM), nil
}

// waitTXTPropagation 轮询公共 DNS，直到每个验证记录名下期望的 TXT 值
// 都能查到，或超时（约 2 分钟）。超时不直接失败：Let's Encrypt 的
// 校验结果才是最终裁决，这里只是尽量避免抢跑。
func waitTXTPropagation(ctx context.Context, pend []txtPending) {
	want := map[string]map[string]bool{}
	for _, p := range pend {
		if want[p.name] == nil {
			want[p.name] = map[string]bool{}
		}
		want[p.name][p.value] = true
	}
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		all := true
		for name, values := range want {
			txts, err := lookupTXT(name)
			if err != nil {
				all = false
				break
			}
			seen := map[string]bool{}
			for _, t := range txts {
				seen[t] = true
			}
			for v := range values {
				if !seen[v] {
					all = false
					break
				}
			}
			if !all {
				break
			}
		}
		if all {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(8 * time.Second):
		}
	}
}
