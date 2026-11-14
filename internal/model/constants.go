// Package model 定义 cx-box 的核心数据模型。
package model

// 状态常量（对标 s-ui 的状态枚举）。
const (
	StatusEnabled  = "enabled"
	StatusDisabled = "disabled"
)

// 证书类型。
const (
	CertTypeSelfSigned = "self_signed"
	CertTypeManual     = "manual"
)

// 证书状态。
const (
	CertStatusValid    = "valid"
	CertStatusInvalid  = "invalid"
	CertStatusExpired  = "expired"
)
