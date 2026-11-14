// Package service 提供设置与账号的业务逻辑。
package service

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/sle58083/cx-box/internal/model"
)

// SettingService 管理面板全局设置。
type SettingService struct {
	db *gorm.DB
}

// NewSettingService 构造设置服务。
func NewSettingService(db *gorm.DB) *SettingService { return &SettingService{db: db} }

// Get 获取当前设置；不存在时创建默认值。
func (s *SettingService) Get() (*model.Setting, error) {
	var st model.Setting
	if err := s.db.First(&st).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			st = model.Setting{
				PanelPort: 2095,
				PanelPath: "/app/",
				SubPort:   2096,
				SubPath:   "/sub/",
			}
			if cerr := s.db.Create(&st).Error; cerr != nil {
				return nil, fmt.Errorf("setting: 创建默认设置失败: %w", cerr)
			}
			return &st, nil
		}
		return nil, err
	}
	return &st, nil
}

// Update 更新设置字段（仅更新非零值）。
func (s *SettingService) Update(st *model.Setting) error {
	return s.db.Model(&model.Setting{}).Where("id = ?", st.ID).Updates(st).Error
}
