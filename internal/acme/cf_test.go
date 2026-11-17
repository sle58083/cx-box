package acme

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeCF 起一个假的 Cloudflare API：只有 example.com 一个 zone。
func fakeCF(t *testing.T, created *map[string]any, deleted *string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/zones", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok-test" {
			t.Errorf("Authorization 头不对: %q", got)
		}
		name := r.URL.Query().Get("name")
		result := "[]"
		if name == "example.com" {
			result = `[{"id":"zone-1","name":"example.com"}]`
		}
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":` + result + `}`))
	})
	mux.HandleFunc("/zones/zone-1/dns_records", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		*created = body
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"rec-1"}}`))
	})
	mux.HandleFunc("/zones/zone-1/dns_records/rec-1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("期望 DELETE, got %s", r.Method)
		}
		*deleted = "rec-1"
		_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"rec-1"}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestCFPresentCleanup present 应逐级找到 zone、建 TXT 记录，
// cleanup 删除的正是新建的那条。
func TestCFPresentCleanup(t *testing.T) {
	created := map[string]any{}
	deleted := ""
	srv := fakeCF(t, &created, &deleted)
	c := newCFClient("tok-test", srv.URL)
	cleanup, err := c.present(context.Background(), "_acme-challenge.sub.example.com", "txt-value-1")
	if err != nil {
		t.Fatalf("present: %v", err)
	}
	if created["type"] != "TXT" || created["name"] != "_acme-challenge.sub.example.com" ||
		created["content"] != "txt-value-1" {
		t.Fatalf("创建的记录不对: %v", created)
	}
	cleanup()
	if deleted != "rec-1" {
		t.Fatalf("cleanup 应删除 rec-1, got %q", deleted)
	}
}

// TestCFZoneNotFound 账号下没有对应 zone 时给出可读错误。
func TestCFZoneNotFound(t *testing.T) {
	created := map[string]any{}
	deleted := ""
	srv := fakeCF(t, &created, &deleted)
	c := newCFClient("tok-test", srv.URL)
	_, err := c.present(context.Background(), "_acme-challenge.other.org", "v")
	if err == nil || !strings.Contains(err.Error(), "找不到") {
		t.Fatalf("应报找不到 zone, got %v", err)
	}
}

// TestCFAPIError Cloudflare 返回 success=false 时错误信息要透出来。
func TestCFAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"message":"Invalid access token"}],"result":null}`))
	}))
	defer srv.Close()
	c := newCFClient("bad-token", srv.URL)
	_, err := c.present(context.Background(), "_acme-challenge.example.com", "v")
	if err == nil || !strings.Contains(err.Error(), "Invalid access token") {
		t.Fatalf("应透出 CF 错误, got %v", err)
	}
}
