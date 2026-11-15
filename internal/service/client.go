package service

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/model"
)

// ClientService 客户端 CRUD。创建时自动补齐 UUID / 订阅 ID / 协议密码。
type ClientService struct {
	db *gorm.DB
}

// NewClientService 构造客户端服务。
func NewClientService(db *gorm.DB) *ClientService { return &ClientService{db: db} }

// List 返回全部客户端（按创建时间排序）。
func (s *ClientService) List() ([]model.Client, error) {
	var out []model.Client
	err := s.db.Order("created_at ASC").Find(&out).Error
	return out, err
}

// Get 按 ID 获取客户端。
func (s *ClientService) Get(id string) (*model.Client, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("client: 无效的 ID")
	}
	var c model.Client
	if err := s.db.First(&c, "id = ?", uid).Error; err != nil {
		return nil, err
	}
	return &c, nil
}

// GetBySubID 按订阅 ID 获取客户端（订阅服务用）。
func (s *ClientService) GetBySubID(subID string) (*model.Client, error) {
	var c model.Client
	if err := s.db.First(&c, "sub_id = ?", subID).Error; err != nil {
		return nil, err
	}
	return &c, nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Create 新建客户端：Email 必填且唯一；UUID/SubID/Password 缺省自动生成。
func (s *ClientService) Create(c *model.Client) error {
	if c.Email == "" {
		return fmt.Errorf("client: email 不能为空")
	}
	var cnt int64
	if err := s.db.Model(&model.Client{}).Where("email = ?", c.Email).Count(&cnt).Error; err != nil {
		return err
	}
	if cnt > 0 {
		return fmt.Errorf("client: email %q 已存在", c.Email)
	}
	if c.ID == uuid.Nil {
		c.ID = model.NewID()
	}
	if c.UUID == "" {
		c.UUID = uuid.NewString()
	}
	if c.SubID == "" {
		c.SubID = randomHex(8)
	}
	if c.Password == "" {
		c.Password = randomHex(8)
	}
	return s.db.Create(c).Error
}

// Update 更新客户端（Email 仍须唯一）。
func (s *ClientService) Update(c *model.Client) error {
	if _, err := s.Get(c.ID.String()); err != nil {
		return err
	}
	if c.Email == "" {
		return fmt.Errorf("client: email 不能为空")
	}
	var cnt int64
	if err := s.db.Model(&model.Client{}).Where("email = ? AND id <> ?", c.Email, c.ID).Count(&cnt).Error; err != nil {
		return err
	}
	if cnt > 0 {
		return fmt.Errorf("client: email %q 已存在", c.Email)
	}
	return s.db.Save(c).Error
}

// Delete 删除客户端。
func (s *ClientService) Delete(id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("client: 无效的 ID")
	}
	return s.db.Delete(&model.Client{}, "id = ?", uid).Error
}
