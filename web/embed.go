// Package web 内嵌面板前端。前端是单个 index.html（原生 JS，无构建步骤），
// 与「单二进制、零编译部署」的定位一致：改前端只改这个 HTML 文件即可。
package web

import _ "embed"

// IndexHTML 是面板单页应用的完整 HTML。
//
//go:embed index.html
var IndexHTML []byte
