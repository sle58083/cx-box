// Package model 定义 cx-box 的核心数据模型（单体单机，对标 s-ui）。
package model

import (
	"time"

	"github.com/google/uuid"
)

// Base 是所有模型的公共字段。
type Base struct {
	ID        uuid.UUID `gorm:"type:text;primaryKey" json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NewID 生成新的 UUID 主键。
func NewID() uuid.UUID { return uuid.New() }
