// Package service 提供设置与账号的业务逻辑。
package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/model"
)

// AdminService 管理面板管理员账号。
type AdminService struct {
	db *gorm.DB
}

// NewAdminService 构造管理员服务。
func NewAdminService(db *gorm.DB) *AdminService { return &AdminService{db: db} }

// Get 返回首个管理员。
func (s *AdminService) Get() (*model.Admin, error) {
	var a model.Admin
	if err := s.db.First(&a).Error; err != nil {
		return nil, err
	}
	return &a, nil
}

// SetPassword 设置管理员密码（SHA-256 哈希存储）。
func (s *AdminService) SetPassword(username, plainPassword string) error {
	if plainPassword == "" {
		return fmt.Errorf("admin: 密码不能为空")
	}
	hash := hashPassword(plainPassword)
	var a model.Admin
	if err := s.db.Where("username = ?", username).First(&a).Error; err == nil {
		// 已存在，更新密码
		a.PasswordHash = hash
		return s.db.Save(&a).Error
	} else if err == gorm.ErrRecordNotFound {
		// 不存在，创建
		a = model.Admin{Username: username, PasswordHash: hash}
		return s.db.Create(&a).Error
	} else {
		return err
	}
}

// Verify 校验用户名密码。
func (s *AdminService) Verify(username, plainPassword string) bool {
	var a model.Admin
	if err := s.db.Where("username = ?", username).First(&a).Error; err != nil {
		return false
	}
	return a.PasswordHash == hashPassword(plainPassword)
}

// hashPassword 计算密码的 SHA-256 哈希。
func hashPassword(p string) string {
	sum := sha256.Sum256([]byte(p))
	return hex.EncodeToString(sum[:])
}

// TokenService 管理 API 令牌。
type TokenService struct {
	db *gorm.DB
}

// NewTokenService 构造令牌服务。
func NewTokenService(db *gorm.DB) *TokenService { return &TokenService{db: db} }

// Create 生成一个随机 API 令牌。
func (s *TokenService) Create(description string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := hex.EncodeToString(buf)
	if err := s.db.Create(&model.APIToken{Token: token, Description: description}).Error; err != nil {
		return "", err
	}
	return token, nil
}

// Verify 校验 API 令牌是否存在。
func (s *TokenService) Verify(token string) bool {
	var cnt int64
	s.db.Model(&model.APIToken{}).Where("token = ?", token).Count(&cnt)
	return cnt > 0
}
