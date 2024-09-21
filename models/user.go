package models

import (
	"time"

	"gorm.io/gorm"
)

// User 用户模型
// @Description 用户模型
type User struct {
	gorm.Model
	Username string `gorm:"unique" json:"username"` // 用户名，唯一
	Password string `json:"password"`               // 密码
}

// GormModel gorm.Model 的手动定义
// @Description gorm.Model
// @Property ID int `json:"id"`
// @Property CreatedAt time.Time `json:"created_at"`
// @Property UpdatedAt time.Time `json:"updated_at"`
// @Property DeletedAt *time.Time `json:"deleted_at"`
type GormModel struct {
	ID        uint       `json:"id"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at"`
}
