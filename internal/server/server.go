// Package server 提供 cx-box 的 HTTP 服务器（面板 + 订阅 + API）。
package server

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/service"
)

// Server 是 cx-box 的 HTTP 服务器。
type Server struct {
	db      *gorm.DB
	setting *service.SettingService
	admin   *service.AdminService
	token   *service.TokenService
}

// New 构造服务器。
func New(g *gorm.DB) *Server {
	return &Server{
		db:      g,
		setting: service.NewSettingService(g),
		admin:   service.NewAdminService(g),
		token:   service.NewTokenService(g),
	}
}

// Run 启动服务器。
func (s *Server) Run() error {
	st, err := s.setting.Get()
	if err != nil {
		return err
	}

	r := gin.Default()
	s.registerRoutes(r)

	addr := fmt.Sprintf(":%d", st.PanelPort)
	return r.Run(addr)
}

// registerRoutes 注册路由。
func (s *Server) registerRoutes(r *gin.Engine) {
	// 健康检查
	r.GET("/healthz", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
}
