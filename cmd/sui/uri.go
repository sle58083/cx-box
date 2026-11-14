package main

import (
	"fmt"
	"os"

	"github.com/sle58083/cx-box/internal/service"
)

// cmdURI 输出面板访问地址。
func cmdURI() {
	g := openDB()
	settingSvc := service.NewSettingService(g)
	st, err := settingSvc.Get()
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("http://localhost:%d%s\n", st.PanelPort, st.PanelPath)
}
