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
	if err := s.ensureNameFree(in.Name, in.ID); err != nil {
		return err
	}
	return r.ValidateInbound(*in)
}

// ensureNameFree 校验名称（tag）未被占用：tag 在入站与出站之间全局唯一
// （sing-box 配置同一命名空间），提前给中文提示，避免数据库唯一约束的
// 英文报错（UNIQUE constraint failed）直接弹到用户面前。
func (s *InboundService) ensureNameFree(name string, selfID uuid.UUID) error {
	var cnt int64
	q := s.db.Model(&model.Inbound{}).Where("name = ?", name)
	if selfID != uuid.Nil {
		q = q.Where("id != ?", selfID)
	}
	// 查询失败（如单元测试的局部迁移缺表）时不阻断：生产库表齐全，
	// 且数据库唯一约束仍是最终兜底。
	if err := q.Count(&cnt).Error; err != nil {
		return nil
	}
	if cnt > 0 {
		return fmt.Errorf("inbound: 名称（tag）%q 已被其他入站占用，请换一个名称", name)
	}
	var cntOut int64
	if err := s.db.Model(&model.Outbound{}).Where("name = ?", name).Count(&cntOut).Error; err != nil {
		return nil
	}
	if cntOut > 0 {
		return fmt.Errorf("inbound: 名称（tag）%q 已被出站占用（入站与出站名称全局唯一），请换一个名称", name)
	}
	return nil
}

// avoidPortConflict 新建入站时自动避让已占用端口：请求端口已被其他入站
// （或面板/订阅端口）占用时，顺延到下一个空闲端口，避免应用配置时
// sing-box 因 bind 冲突起不来。最终端口以 Create 返回的 in.Port 为准。
func (s *InboundService) avoidPortConflict(in *model.Inbound) {
	used := map[int]bool{}
	var ports []int
	if err := s.db.Model(&model.Inbound{}).Pluck("port", &ports).Error; err == nil {
		for _, p := range ports {
			used[p] = true
		}
	}
	var st model.Setting
	if err := s.db.First(&st).Error; err == nil {
		used[st.PanelPort] = true
		used[st.SubPort] = true
	}
	if !used[in.Port] {
		return
	}
	for p := in.Port + 1; p <= 65535; p++ {
		if !used[p] {
			in.Port = p
			return
		}
	}
	for p := 1024; p < in.Port; p++ {
		if !used[p] {
			in.Port = p
			return
		}
	}
}

// Create 新建入站。
// normalizeRawJSON 把 JSON 字面量 null 归一为空：客户端把空字段发成
// "settings": null 时若原样落库，读取方 Unmarshal 会得到 nil map，
// 再写入就 panic（configsvc/sub 都踩中过）。写边界统一拦下。
func normalizeRawJSON(raw []byte) []byte {
	if string(raw) == "null" {
		return nil
	}
	return raw
}

func normalizeInbound(in *model.Inbound) {
	in.Settings = normalizeRawJSON(in.Settings)
	in.TLS = normalizeRawJSON(in.TLS)
	in.Transport = normalizeRawJSON(in.Transport)
}

func (s *InboundService) Create(in *model.Inbound) error {
	normalizeInbound(in)
	s.avoidPortConflict(in)
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
	normalizeInbound(in)
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
