package domain

import "time"

// PasswordResetToken — одноразовый токен для сброса пароля.
// Хранится в БД, истекает через 15 минут, помечается used=true после использования.
type PasswordResetToken struct {
	ID        int64
	UserID    int64
	Token     string
	ExpiresAt time.Time
	Used      bool
	CreatedAt time.Time
}

// PasswordResetRequestInput — тело запроса на отправку письма со ссылкой сброса.
type PasswordResetRequestInput struct {
	Email string `json:"email"`
}

// PasswordResetConfirmInput — тело запроса на установку нового пароля.
type PasswordResetConfirmInput struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}
