package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/sle58083/cx-box/internal/service"
)

// cmdSetting 查看/修改面板设置。
// 用法：
//   sui setting -show
//   sui setting -port 2095 -path /app/ -subPort 2096 -subPath /sub/
func cmdSetting(args []string) {
	fs := flag.NewFlagSet("setting", flag.ExitOnError)
	show := fs.Bool("show", false, "查看当前设置")
	port := fs.Int("port", 0, "面板端口")
	path := fs.String("path", "", "面板路径")
	subPort := fs.Int("subPort", 0, "订阅端口")
	subPath := fs.String("subPath", "", "订阅路径")
	_ = fs.Parse(args)

	g := openDB()
	settingSvc := service.NewSettingService(g)
	st, err := settingSvc.Get()
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}

	if *show || (*port == 0 && *path == "" && *subPort == 0 && *subPath == "") {
		fmt.Printf("panel port : %d\n", st.PanelPort)
		fmt.Printf("panel path : %s\n", st.PanelPath)
		fmt.Printf("sub port   : %d\n", st.SubPort)
		fmt.Printf("sub path   : %s\n", st.SubPath)
		return
	}

	if *port > 0 {
		st.PanelPort = *port
	}
	if *path != "" {
		st.PanelPath = *path
	}
	if *subPort > 0 {
		st.SubPort = *subPort
	}
	if *subPath != "" {
		st.SubPath = *subPath
	}
	if err := settingSvc.Update(st); err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("设置已更新")
}

// cmdAdmin 查看/修改管理员账号。
func cmdAdmin(args []string) {
	fs := flag.NewFlagSet("admin", flag.ExitOnError)
	show := fs.Bool("show", false, "查看当前管理员")
	username := fs.String("username", "", "管理员用户名")
	password := fs.String("password", "", "管理员密码")
	_ = fs.Parse(args)

	g := openDB()
	adminSvc := service.NewAdminService(g)

	if *show || (*username == "" && *password == "") {
		a, err := adminSvc.Get()
		if err != nil {
			fmt.Println("尚未创建管理员（首次运行会自动创建默认 admin）")
			return
		}
		fmt.Printf("username: %s\n", a.Username)
		return
	}

	if *username == "" {
		a, err := adminSvc.Get()
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: %v\n", err)
			os.Exit(1)
		}
		*username = a.Username
	}
	if err := adminSvc.SetPassword(*username, *password); err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("管理员已更新")
}

// cmdToken 生成 API 令牌。
func cmdToken(args []string) {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	desc := fs.String("desc", "", "令牌描述")
	_ = fs.Parse(args)

	g := openDB()
	tokenSvc := service.NewTokenService(g)
	token, err := tokenSvc.Create(*desc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(token)
}

// cmdMigrate 执行数据库迁移。
func cmdMigrate() {
	openDB()
	fmt.Println("数据库迁移完成")
}
