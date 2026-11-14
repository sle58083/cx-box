package main

import (
	"log"

	"github.com/sle58083/cx-box/internal/server"
)

// runServer 启动 HTTP 服务器（面板 + 订阅 + API）。
func runServer() {
	g := openDB()

	srv := server.New(g)
	if err := srv.Run(); err != nil {
		log.Fatalf("服务器退出: %v", err)
	}
}
