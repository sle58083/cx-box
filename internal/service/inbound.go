package service

import (
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/model"
	"github.com/sle58083/cx-box/internal/renderer"
)

// InboundService 入站 CRUD（保存前走 renderer 校验，协议规则的唯一权威在渲染器）。
type InboundService struct {
	db *gorm.DB
}

// NewInboundService 构造入站服务。
func NewInboundService(db *gorm.DB) *InboundService { return &InboundService{db: db} }

// List 返回全部入站（按端口排序）。
func (s *InboundService) List() ([]model.Inbound, error) {
	var out []model.Inbound
	err := s.db.Order("port ASC").Find(&out).Error
	return out, err
}

// Get 按 ID 获取入站。
func (s *InboundService) Get(id string) (*model.Inbound, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("inbound: 无效的 ID")
	}
	var in model.Inbound
	if err := s.db.First(&in, "id = ?", uid).Error; err != nil {
		return nil, err
	}
	return &in, nil
}

// validate 做协议级校验（渲染器）+ 通用字段校验。
func (s *InboundService) validate(in *model.Inbound) error {
	if in.Name == "" {
		return fmt.Errorf("inbound: 名称（tag）不能为空")
	}
	if in.Port < 1 || in.Port > 65535 {
		return fmt.Errorf("inbound: 端口必须在 1-65535 之间")
	}
	r, ok := renderer.Get(in.Type)
	if !ok {
		return fmt.Errorf("inbound: 不支持的协议类型 %q", in.Type)
	}
	return r.ValidateInbound(*in)
}

// Create 新建入站。
func (s *InboundService) Create(in *model.Inbound) error {
	if err := s.validate(in); err != nil {
		return err
	}
	if in.ID == uuid.Nil {
		in.ID = model.NewID()
	}
	if in.Status == "" {
		in.Status = model.StatusEnabled
	}
	return s.db.Create(in).Error
}

// Update 更新入站（按 ID 全量更新可编辑字段）。
func (s *InboundService) Update(in *model.Inbound) error {
	if _, err := s.Get(in.ID.String()); err != nil {
		return err
	}
	if err := s.validate(in); err != nil {
		return err
	}
	return s.db.Save(in).Error
}

// Delete 删除入站。
func (s *InboundService) Delete(id string) error {
	uid, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("inbound: 无效的 ID")
	}
	return s.db.Delete(&model.Inbound{}, "id = ?", uid).Error
}
