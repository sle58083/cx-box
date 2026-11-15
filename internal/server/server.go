// Package server 提供 cx-box 的 HTTP 服务器（面板 + 订阅 + API）。
//
// 监听两个端口（对标 s-ui）：
//   - 面板端口（默认 2095）：PanelPath 下是管理 API（登录会话 / API token 鉴权）；
//   - 订阅端口（默认 2096）：SubPath 下按订阅 ID 下发分享链接，无需鉴权（ID 即凭据）。
package server

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/configsvc"
	"github.com/sle58083/cx-box/internal/kernel"
	"github.com/sle58083/cx-box/internal/service"
)

// Version 是面板版本号（随发布递增）。
const Version = "0.4.0"

// Server 是 cx-box 的 HTTP 服务器。
type Server struct {
	db       *gorm.DB
	setting  *service.SettingService
	admin    *service.AdminService
	token    *service.TokenService
	inbound  *service.InboundService
	outbound *service.OutboundService
	client   *service.ClientService
	cert     *service.CertificateService
	km       *kernel.Manager    // 可为 nil（内核未就绪时面板仍可用）
	cfg      *configsvc.Service // 可为 nil（同上）
	sessions *sessionStore
}

// New 构造服务器。km/cfg 可为 nil，表示 sing-box 内核未就绪（状态接口会如实报告）。
func New(g *gorm.DB, km *kernel.Manager, cfg *configsvc.Service) *Server {
	return &Server{
		db:       g,
		setting:  service.NewSettingService(g),
		admin:    service.NewAdminService(g),
		token:    service.NewTokenService(g),
		inbound:  service.NewInboundService(g),
		outbound: service.NewOutboundService(g),
		client:   service.NewClientService(g),
		cert:     service.NewCertificateService(g),
		km:       km,
		cfg:      cfg,
		sessions: newSessionStore(),
	}
}

// Run 启动面板与订阅两个监听（订阅与面板同端口时合并到一个引擎）。
func (s *Server) Run() error {
	st, err := s.setting.Get()
	if err != nil {
		return err
	}
	gin.SetMode(gin.ReleaseMode)

	panel := gin.New()
	panel.Use(gin.Logger(), gin.Recovery())
	s.registerPanelRoutes(panel, st.PanelPath)
	panel.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	if st.SubPort == st.PanelPort {
		s.registerSubRoutes(panel, st.SubPath)
		return panel.Run(fmt.Sprintf(":%d", st.PanelPort))
	}

	sub := gin.New()
	sub.Use(gin.Logger(), gin.Recovery())
	s.registerSubRoutes(sub, st.SubPath)
	sub.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	go func() {
		if err := sub.Run(fmt.Sprintf(":%d", st.SubPort)); err != nil {
			log.Printf("订阅服务器退出: %v", err)
		}
	}()

	return panel.Run(fmt.Sprintf(":%d", st.PanelPort))
}

// normalizePath 保证路径以 / 开头、结尾无 /（根路径除外），用于路由分组。
func normalizePath(p string) string {
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimSuffix(p, "/")
}
