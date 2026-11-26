package server

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/model"
	"github.com/sle58083/cx-box/internal/sub"
)

// registerSubRoutes 在订阅路径下注册订阅下发路由（subId 即凭据，无需登录）。
func (s *Server) registerSubRoutes(r *gin.Engine, subPath string) {
	base := normalizePath(subPath)
	r.GET(base+"/:subId", s.handleSubscription)
}

// isClashUA 判断请求是否来自 Clash 系客户端（Mihomo / Clash Verge /
// Stash / FlClash 等）：这些客户端只认 YAML 配置，拉到 base64 链接列表
// 会直接导入失败，故未显式指定 format 时按 UA 自动返回 Clash 格式。
func isClashUA(ua string) bool {
	ua = strings.ToLower(ua)
	for _, kw := range []string{"clash", "mihomo", "stash"} {
		if strings.Contains(ua, kw) {
			return true
		}
	}
	return false
}

// handleSubscription 下发订阅：默认返回 base64 编码的链接列表（主流客户端通用），
// ?format=raw 返回明文逐行链接，?format=clash 返回 Clash 系 YAML 配置；
// 未指定 format 且 UA 是 Clash 系客户端时自动返回 Clash 格式。
// 附带 Subscription-Userinfo 流量/到期信息头。
func (s *Server) handleSubscription(c *gin.Context) {
	gen := sub.New(s.db)
	format := c.Query("format")
	if format == "" && isClashUA(c.GetHeader("User-Agent")) {
		format = "clash"
	}

	var client *model.Client
	var body string
	var err error
	if format == "clash" || format == "mihomo" {
		body, client, err = gen.Clash(c.Param("subId"), requestHost(c))
	} else {
		var links []string
		links, client, err = gen.Links(c.Param("subId"), requestHost(c))
		if err == nil {
			body = strings.Join(links, "\n")
			if format != "raw" {
				body = base64.StdEncoding.EncodeToString([]byte(body))
			}
		}
	}
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			failMsg(c, http.StatusNotFound, "订阅不存在")
			return
		}
		failMsg(c, http.StatusForbidden, err.Error())
		return
	}

	total := client.TotalGB * 1024 * 1024 * 1024
	c.Header("Subscription-Userinfo",
		fmt.Sprintf("upload=0; download=%d; total=%d; expire=%d", client.UsedBytes, total, client.ExpiryTime))
	// 订阅名称：客户端导入时用作订阅标题（profile-title 约定），未设置时用邮箱。
	subName := client.SubName
	if subName == "" {
		subName = client.Email
	}
	c.Header("profile-title", subName)
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", client.Email))

	if format == "clash" || format == "mihomo" {
		c.Data(http.StatusOK, "text/yaml; charset=utf-8", []byte(body))
		return
	}
	c.String(http.StatusOK, body)
}

// requestHost 取请求主机名（不含端口）：优先 X-Forwarded-Host，其次 Host。
func requestHost(c *gin.Context) string {
	h := c.GetHeader("X-Forwarded-Host")
	if h == "" {
		h = c.Request.Host
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}
