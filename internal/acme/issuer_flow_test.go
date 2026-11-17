package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeACME 是一个最小可用的假 ACME 服务器（RFC 8555 形状），把签发
// 全流程在本地跑通：注册 → 下单 → dns-01 → Accept → 订单 Ready →
// finalize → Valid → 下载证书。它钉住的是订单状态机语义——WaitOrder
// 在 Ready 时就会返回，finalize 由 CreateOrderCert 完成；v0.5.15 曾
// 错误地要求 WaitOrder 后状态必须是 Valid，导致真实签发在最后一步
// 报「证书订单状态异常: ready」。
type fakeACME struct {
	srv       *httptest.Server
	registered bool
	finalized  bool
	certPEM    string
	mu         sync.Mutex
}

func (f *fakeACME) url(path string) string { return f.srv.URL + path }

func (f *fakeACME) handler() http.Handler {
	mux := http.NewServeMux()
	jsonw := func(w http.ResponseWriter, code int, body string) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Replay-Nonce", "nonce-abc")
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}
	mux.HandleFunc("/directory", func(w http.ResponseWriter, r *http.Request) {
		jsonw(w, 200, `{"newNonce":"`+f.url("/nonce")+`","newAccount":"`+f.url("/new-account")+`","newOrder":"`+f.url("/new-order")+`"}`)
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", "nonce-abc")
		w.WriteHeader(200)
	})
	mux.HandleFunc("/new-account", func(w http.ResponseWriter, r *http.Request) {
		// JWS payload 里带 onlyReturnExisting 的是 GetReg 探测。
		var jws struct {
			Payload string `json:"payload"`
		}
		_ = json.NewDecoder(r.Body).Decode(&jws)
		raw, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
		f.mu.Lock()
		defer f.mu.Unlock()
		if strings.Contains(string(raw), "onlyReturnExisting") && !f.registered {
			jsonw(w, 400, `{"type":"urn:ietf:params:acme:error:accountDoesNotExist","detail":"no such account"}`)
			return
		}
		f.registered = true
		w.Header().Set("Location", f.url("/acct/1"))
		jsonw(w, 201, `{"status":"valid","contact":["mailto:me@example.com"]}`)
	})
	mux.HandleFunc("/new-order", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", f.url("/order/1"))
		jsonw(w, 201, `{"status":"pending","authorizations":["`+f.url("/authz/1")+`"],"finalize":"`+f.url("/finalize/1")+`"}`)
	})
	mux.HandleFunc("/authz/1", func(w http.ResponseWriter, r *http.Request) {
		jsonw(w, 200, `{"status":"pending","identifier":{"type":"dns","value":"example.com"},`+
			`"challenges":[{"type":"dns-01","url":"`+f.url("/chal/1")+`","token":"tok-123","status":"pending"}]}`)
	})
	mux.HandleFunc("/chal/1", func(w http.ResponseWriter, r *http.Request) {
		jsonw(w, 200, `{"type":"dns-01","url":"`+f.url("/chal/1")+`","token":"tok-123","status":"valid"}`)
	})
	mux.HandleFunc("/order/1", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		fin := f.finalized
		f.mu.Unlock()
		if fin {
			jsonw(w, 200, `{"status":"valid","authorizations":["`+f.url("/authz/1")+`"],"finalize":"`+f.url("/finalize/1")+`","certificate":"`+f.url("/cert/1")+`"}`)
			return
		}
		jsonw(w, 200, `{"status":"ready","authorizations":["`+f.url("/authz/1")+`"],"finalize":"`+f.url("/finalize/1")+`"}`)
	})
	mux.HandleFunc("/finalize/1", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.finalized = true
		f.mu.Unlock()
		jsonw(w, 200, `{"status":"valid","authorizations":["`+f.url("/authz/1")+`"],"finalize":"`+f.url("/finalize/1")+`","certificate":"`+f.url("/cert/1")+`"}`)
	})
	mux.HandleFunc("/cert/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.Header().Set("Replay-Nonce", "nonce-abc")
		_, _ = w.Write([]byte(f.certPEM))
	})
	return mux
}

// TestIssueFullFlowAgainstFakeACME 用假 ACME + 假 Cloudflare 跑完整
// 签发流程，断言拿到证书 PEM 与可解析的私钥 PEM。
func TestIssueFullFlowAgainstFakeACME(t *testing.T) {
	leafPEM, _ := fakeCertPEM(t, time.Now().Add(90*24*time.Hour))
	fa := &fakeACME{certPEM: leafPEM}
	fa.srv = httptest.NewServer(fa.handler())
	defer fa.srv.Close()

	// 假 Cloudflare：zone 只有 example.com；把建好的 TXT 值按名存下，
	// 供 lookupTXT 桩「查到」——模拟 DNS 传播完成。
	txtByName := map[string][]string{}
	var mu sync.Mutex
	cfMux := http.NewServeMux()
	cfMux.HandleFunc("/zones", func(w http.ResponseWriter, r *http.Request) {
		result := "[]"
		if r.URL.Query().Get("name") == "example.com" {
			result = `[{"id":"zone-1","name":"example.com"}]`
		}
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":` + result + `}`))
	})
	cfMux.HandleFunc("/zones/zone-1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		name, _ := body["name"].(string)
		content, _ := body["content"].(string)
		txtByName[name] = append(txtByName[name], content)
		mu.Unlock()
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"rec-1"}}`))
	})
	cfMux.HandleFunc("/zones/zone-1/dns_records/rec-1", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"rec-1"}}`))
	})
	cfSrv := httptest.NewServer(cfMux)
	defer cfSrv.Close()

	oldLookup := lookupTXT
	lookupTXT = func(name string) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		if vals, ok := txtByName[name]; ok {
			return vals, nil
		}
		return nil, &netDNSError{}
	}
	defer func() { lookupTXT = oldLookup }()

	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen account key: %v", err)
	}
	iss := &issuer{
		dirURL:     fa.url("/directory"),
		email:      "me@example.com",
		accountKey: accountKey,
		cf:         newCFClient("tok-test", cfSrv.URL),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	certPEM, keyPEM, err := iss.issue(ctx, []string{"example.com"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if certPEM != leafPEM {
		t.Fatalf("证书 PEM 与 CA 下发的不一致")
	}
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		t.Fatalf("私钥 PEM 无法解析")
	}
	if _, err := x509.ParseECPrivateKey(block.Bytes); err != nil {
		t.Fatalf("私钥不是合法 EC 私钥: %v", err)
	}
	// CSR 的 SAN 应含申请的域名：这里只验签发确实走到了 finalize。
	if !fa.finalized {
		t.Fatalf("订单应已被 finalize")
	}
}

type netDNSError struct{}

func (*netDNSError) Error() string   { return "no such host" }
func (*netDNSError) Timeout() bool   { return false }
func (*netDNSError) Temporary() bool { return false }
