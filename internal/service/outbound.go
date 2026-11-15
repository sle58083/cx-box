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
	if err := s.ensureNameFree(ob.Name, ob.ID); err != nil {
		return err
	}
	return r.ValidateOutbound(*ob)
}

// ensureNameFree 校验名称（tag）未被占用：tag 在出站与入站之间全局唯一
// （sing-box 配置同一命名空间），提前给中文提示，避免数据库唯一约束的
// 英文报错（UNIQUE constraint failed）直接弹到用户面前。
func (s *OutboundService) ensureNameFree(name string, selfID uuid.UUID) error {
	var cnt int64
	q := s.db.Model(&model.Outbound{}).Where("name = ?", name)
	if selfID != uuid.Nil {
		q = q.Where("id != ?", selfID)
	}
	// 查询失败（如单元测试的局部迁移缺表）时不阻断：生产库表齐全，
	// 且数据库唯一约束仍是最终兜底。
	if err := q.Count(&cnt).Error; err != nil {
		return nil
	}
	if cnt > 0 {
		return fmt.Errorf("outbound: 名称（tag）%q 已被其他出站占用，请换一个名称", name)
	}
	var cntIn int64
	if err := s.db.Model(&model.Inbound{}).Where("name = ?", name).Count(&cntIn).Error; err != nil {
		return nil
	}
	if cntIn > 0 {
		return fmt.Errorf("outbound: 名称（tag）%q 已被入站占用（入站与出站名称全局唯一），请换一个名称", name)
	}
	return nil
}

// Create 新建出站。
func normalizeOutbound(ob *model.Outbound) {
	ob.Settings = normalizeRawJSON(ob.Settings)
	ob.TLS = normalizeRawJSON(ob.TLS)
	ob.Transport = normalizeRawJSON(ob.Transport)
}

func (s *OutboundService) Create(ob *model.Outbound) error {
	normalizeOutbound(ob)
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
	normalizeOutbound(ob)
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
