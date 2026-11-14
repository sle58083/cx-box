// Package db 负责 SQLite 数据库初始化与迁移。
package db

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/sle58083/cx-box/internal/model"
)

// Open 打开（或创建）SQLite 数据库并执行迁移。
// dbPath 为空时使用默认路径 db/cx-box.db（相对可执行文件所在目录）。
func Open(dbPath string) (*gorm.DB, error) {
	if dbPath == "" {
		dir, err := os.Executable()
		if err != nil {
			return nil, err
		}
		dbPath = filepath.Join(filepath.Dir(dir), "db", "cx-box.db")
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, fmt.Errorf("db: 创建目录失败: %w", err)
	}

	g, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		// 静默 SQL 日志，避免 CLI 输出被 GORM 查询日志污染。
		Logger: logger.New(log.New(os.Stderr, "", log.LstdFlags), logger.Config{
			LogLevel: logger.Silent,
		}),
	})
	if err != nil {
		return nil, fmt.Errorf("db: 打开失败: %w", err)
	}

	// SQLite WAL 模式：降低锁冲突，一核 1G 环境内存占用极低。
	if err := g.Exec("PRAGMA journal_mode=WAL").Error; err != nil {
		return nil, fmt.Errorf("db: 设置 WAL 失败: %w", err)
	}

	return g, nil
}

// Migrate 执行自动迁移（创建表结构）。
func Migrate(g *gorm.DB) error {
	if err := g.AutoMigrate(
		&model.Setting{},
		&model.Admin{},
		&model.APIToken{},
		&model.Inbound{},
		&model.Outbound{},
		&model.Client{},
		&model.Certificate{},
		&model.TrafficRecord{},
		&model.RoutingRule{},
	); err != nil {
		return fmt.Errorf("db: 迁移失败: %w", err)
	}
	return nil
}
