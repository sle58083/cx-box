package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/sle58083/cx-box/internal/configsvc"
	"github.com/sle58083/cx-box/internal/kernel"
	"github.com/sle58083/cx-box/internal/server"
)

// runServer 启动 cx-box：托管 sing-box 内核 + 面板/订阅 HTTP 服务。
//
// 内核就绪流程（对标 s-ui「面板即节点」）：确保 sing-box 二进制存在（缺失则从
// 官方 Release 下载）→ 按数据库生成配置 → 校验 → 启动 sing-box。
// 内核任何一步失败只打日志、不拖垮面板：面板照常启动，状态接口会报告内核未就绪，
// 配置修好后可在面板里手动「应用配置」。
func runServer() {
	g := openDB()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	exe, err := os.Executable()
	if err != nil {
		log.Fatalf("无法定位可执行文件路径: %v", err)
	}
	km := kernel.New(filepath.Dir(exe), "")

	var cfg *configsvc.Service
	if err := km.EnsureBinary(km.DefaultDownloadURL()); err != nil {
		log.Printf("警告: sing-box 内核未就绪: %v（面板照常启动）", err)
	} else {
		cfg = configsvc.NewService(g, km)
		if err := cfg.Apply(ctx); err != nil {
			log.Printf("警告: 应用 sing-box 配置失败: %v（面板照常启动）", err)
		} else {
			log.Printf("sing-box %s 已启动", kernel.DefaultVersion)
		}
	}

	srv := server.New(g, km, cfg)
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run() }()

	select {
	case err := <-errCh:
		if err != nil {
			log.Fatalf("服务器退出: %v", err)
		}
	case <-ctx.Done():
		log.Println("收到退出信号，正在关闭…")
		_ = km.Stop()
	}
}
