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

	"github.com/sle58083/cx-box/internal/sub"
)

// registerSubRoutes 在订阅路径下注册订阅下发路由（subId 即凭据，无需登录）。
func (s *Server) registerSubRoutes(r *gin.Engine, subPath string) {
	base := normalizePath(subPath)
	r.GET(base+"/:subId", s.handleSubscription)
}

// handleSubscription 下发订阅：默认返回 base64 编码的链接列表（主流客户端通用），
// ?format=raw 返回明文逐行链接。附带 Subscription-Userinfo 流量/到期信息头。
func (s *Server) handleSubscription(c *gin.Context) {
	gen := sub.New(s.db)
	links, client, err := gen.Links(c.Param("subId"), requestHost(c))
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

	body := strings.Join(links, "\n")
	if c.Query("format") == "raw" {
		c.String(http.StatusOK, body)
		return
	}
	c.String(http.StatusOK, base64.StdEncoding.EncodeToString([]byte(body)))
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
