package main

import (
	"fmt"
	"net"
	"os"

	"github.com/sle58083/cx-box/internal/service"
)

// cmdURI 输出面板访问地址。
// 除 localhost 外，还枚举本机非回环 IPv4 地址逐行输出 —— 安装脚本在 VPS 上
// 直接调用 `cx-box uri` 打印访问地址，只有 localhost 对用户没有意义（对标 s-ui uri）。
func cmdURI() {
	g := openDB()
	settingSvc := service.NewSettingService(g)
	st, err := settingSvc.Get()
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("http://localhost:%d%s\n", st.PanelPort, st.PanelPath)
	for _, ip := range externalIPv4s() {
		fmt.Printf("http://%s:%d%s\n", ip, st.PanelPort, st.PanelPath)
	}
}

// externalIPv4s 返回本机所有非回环、已启用的 IPv4 地址（去重、保持枚举顺序）。
func externalIPv4s() []string {
	var out []string
	seen := map[string]bool{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ip4 := ip.To4()
			if ip4 == nil || ip4.IsLoopback() {
				continue
			}
			s := ip4.String()
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}
