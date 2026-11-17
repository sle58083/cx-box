// Package acme 实现自动证书：Let's Encrypt + Cloudflare DNS-01 验证。
//
// 只做 DNS 验证（NAT/内网机器也能签，含泛域名）；Cloudflare 令牌由
// 调用方从设置中取出传入，本包不落库、不打日志明文。
package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// cfClient 是 Cloudflare API v4 的最小客户端，只用 DNS 记录相关接口。
type cfClient struct {
	token string
	base  string // 默认 https://api.cloudflare.com/client/v4，测试可覆盖
	http  *http.Client
}

func newCFClient(token, base string) *cfClient {
	if base == "" {
		base = "https://api.cloudflare.com/client/v4"
	}
	return &cfClient{token: token, base: strings.TrimRight(base, "/"),
		http: &http.Client{Timeout: 30 * time.Second}}
}

type cfResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (c *cfClient) do(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare 请求失败: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var cr cfResponse
	if err := json.Unmarshal(data, &cr); err != nil {
		return nil, fmt.Errorf("cloudflare 响应无法解析（HTTP %d）", resp.StatusCode)
	}
	if !cr.Success {
		msgs := make([]string, 0, len(cr.Errors))
		for _, e := range cr.Errors {
			msgs = append(msgs, e.Message)
		}
		return nil, fmt.Errorf("cloudflare API 错误: %s", strings.Join(msgs, "; "))
	}
	return cr.Result, nil
}

// zoneIDFor 按从长到短逐级缩短后缀，找到 fqdn 所属的 zone。
// _acme-challenge.sub.example.com → 先查 sub.example.com 再查 example.com。
func (c *cfClient) zoneIDFor(ctx context.Context, fqdn string) (zoneID, zoneName string, err error) {
	labels := strings.Split(strings.TrimSuffix(fqdn, "."), ".")
	for i := 0; i+1 < len(labels); i++ {
		name := strings.Join(labels[i:], ".")
		raw, err := c.do(ctx, http.MethodGet, "/zones?name="+name, nil)
		if err != nil {
			return "", "", err
		}
		var zones []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(raw, &zones); err != nil {
			return "", "", fmt.Errorf("cloudflare zones 响应无法解析: %w", err)
		}
		if len(zones) > 0 {
			return zones[0].ID, zones[0].Name, nil
		}
	}
	return "", "", fmt.Errorf("cloudflare 账号下找不到 %s 所属的域名 zone（令牌需有该 zone 的 DNS 编辑权限）", fqdn)
}

// present 创建一条 TXT 记录，返回删除它的清理函数。
func (c *cfClient) present(ctx context.Context, fqdn, value string) (func(), error) {
	zoneID, _, err := c.zoneIDFor(ctx, fqdn)
	if err != nil {
		return nil, err
	}
	raw, err := c.do(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", map[string]any{
		"type": "TXT", "name": fqdn, "content": value, "ttl": 60,
	})
	if err != nil {
		return nil, fmt.Errorf("创建验证 TXT 记录失败: %w", err)
	}
	var rec struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil || rec.ID == "" {
		return nil, fmt.Errorf("cloudflare 未返回新记录 ID")
	}
	cleanup := func() {
		dctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, _ = c.do(dctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+rec.ID, nil)
	}
	return cleanup, nil
}
