package service

import (
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/model"
	"github.com/sle58083/cx-box/internal/renderer"
)

// OutboundService 出站 CRUD（保存前走 renderer 校验）。
type OutboundService struct {
	db *gorm.DB
}

// NewOutboundService 构造出站服务。
func NewOutboundService(db *gorm.DB) *OutboundService { return &OutboundService{db: db} }

// List 返回全部出站（按名称排序）。
func (s *OutboundService) List() ([]model.Outbound, error) {
	var out []model.Outbound
	err := s.db.Order("name ASC").Find(&out).Error
	return out, err
}

// Get 按 ID 获取出站。
func (s *OutboundService) Get(id string) (*model.Outbound, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("outbound: 无效的 ID")
	}
	var ob model.Outbound
	if err := s.db.First(&ob, "id = ?", uid).Error; err != nil {
		return nil, err
	}
	return &ob, nil
}

func (s *OutboundService) validate(ob *model.Outbound) error {
	if ob.Name == "" {
		return fmt.Errorf("outbound: 名称（tag）不能为空")
	}
	r, ok := renderer.Get(ob.Type)
	if !ok {
		return fmt.Errorf("outbound: 不支持的协议类型 %q", ob.Type)
	}
	return r.ValidateOutbound(*ob)
}

// Create 新建出站。
func (s *OutboundService) Create(ob *model.Outbound) error {
	if err := s.validate(ob); err != nil {
		return err
	}
	if ob.ID == uuid.Nil {
		ob.ID = model.NewID()
	}
	if ob.Status == "" {
		ob.Status = model.StatusEnabled
	}
	return s.db.Create(ob).Error
}

// Update 更新出站。
func (s *OutboundService) Update(ob *model.Outbound) error {
	if _, err := s.Get(ob.ID.String()); err != nil {
		return err
	}
	if err := s.validate(ob); err != nil {
		return err
	}
	return s.db.Save(ob).Error
}

// Delete 删除出站。
func (s *OutboundService) Delete(id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("outbound: 无效的 ID")
	}
	return s.db.Delete(&model.Outbound{}, "id = ?", uid).Error
}
