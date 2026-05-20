// Пакет domain содержит бизнес-сущности приложения — структуры данных,
// которые описывают предметную область независимо от БД, HTTP или любого другого транспорта.
// Этот слой не импортирует ничего из внутренних пакетов — он является ядром приложения.
package domain

import "time"

// User — основная сущность пользователя в системе.
// PasswordHash хранит bcrypt-хэш пароля; открытый пароль никогда не сохраняется.
// IsActive позволяет деактивировать аккаунт без его удаления из БД.
type User struct {
	ID           int64
	Email        string
	PasswordHash string
	IsActive     bool
	CreatedAt    time.Time
}

// RegisterInput — данные, которые клиент передаёт при регистрации нового аккаунта.
// Теги json используются для декодирования тела HTTP-запроса.
type RegisterInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginInput — данные, которые клиент передаёт при входе в систему.
// После успешной проверки клиент получает пару токенов (AccessToken + RefreshToken).
type LoginInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// ChangePasswordInput — данные для смены пароля.
// CurrentPassword нужен чтобы убедиться что запрос делает именно владелец аккаунта,
// а не кто-то, кто завладел чужим access-токеном.
type ChangePasswordInput struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}
