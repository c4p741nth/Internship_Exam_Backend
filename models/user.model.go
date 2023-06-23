package models

import uuid "github.com/satori/go.uuid"

type User struct {
	ID         uuid.UUID `gorm:"type:uuid;default:uuid_generate_v4();primary_key"`
	PrefixName string    `gorm:"type:varchar(6);not null"`
	FirstName  string    `gorm:"type:varchar(50);not null"`
	Lastname   string    `gorm:"type:varchar(50);not null"`
	Email      string    `gorm:"uniqueIndex;not null"`
	CitizenID  string    `gorm:"uniqueIndex;not null"`
	Password   string    `gorm:"not null"`
	Role       int       `gorm:"not null"`
	CreatedAt  int64     `gorm:"not null"`
	UpdatedAt  int64     `gorm:"not null"`
}

type RegisterInput struct {
	PrefixName      string `json:"prefixname" binding:"required"`
	Firstname       string `json:"firstname" binding:"required"`
	Lastname        string `json:"lastname" binding:"required"`
	CitizenID       string `json:"citizenid" binding:"required"`
	Password        string `json:"password" binding:"required"`
	PasswordConfirm string `json:"passwordconfirm" binding:"required"`
	Email           string `json:"email" binding:"required"`
	Role            int    `json:"role"`
}

type LoginInput struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type ForgotPasswordInput struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}
