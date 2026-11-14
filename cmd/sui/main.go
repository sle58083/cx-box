// Package main 是 cx-box 的主程序入口，提供 CLI 子命令与 HTTP 服务器。
//
// 子命令（对标 s-ui 的 sui 二进制）：
//   - 无参数 / run   启动 HTTP 服务器
//   - uri            输出面板访问地址
//   - setting        查看/修改面板设置
//   - admin          查看/修改管理员账号
//   - token          生成 API 令牌
//   - migrate        执行数据库迁移
package main

import (
	"fmt"
	"os"

	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/db"
)

func main() {
	if len(os.Args) < 2 {
		runServer()
		return
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "run":
		runServer()
	case "uri":
		cmdURI()
	case "setting":
		cmdSetting(args)
	case "admin":
		cmdAdmin(args)
	case "token":
		cmdToken(args)
	case "migrate":
		cmdMigrate()
	case "help", "-h", "--help":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n\n", cmd)
		printHelp()
		os.Exit(1)
	}
}

// openDB 打开数据库并迁移。
func openDB() *gorm.DB {
	g, err := db.Open("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
	if err := db.Migrate(g); err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
	return g
}

func printHelp() {
	fmt.Println(`cx-box - sing-box 单体单机 Web 面板

用法:
  sui               启动服务器
  sui run           启动服务器
  sui uri           输出面板访问地址
  sui setting       查看/修改面板设置
  sui admin         查看/修改管理员账号
  sui token         生成 API 令牌
  sui migrate       执行数据库迁移
  sui help          显示帮助`)
}
