// Пакет service содержит бизнес-логику приложения.
// Ошибки вынесены в отдельный файл, чтобы HTTP-хендлеры могли сравнивать их
// через errors.Is и возвращать нужный HTTP-статус (400, 401, 409 и т.д.).
package service

import "errors"

var (
	// ErrEmailTaken — попытка зарегистрироваться с уже занятым email.
	// Хендлер должен вернуть 409 Conflict.
	ErrEmailTaken = errors.New("email already taken")

	// ErrInvalidCredentials — неверный email или пароль при логине.
	// Намеренно не уточняем что именно неверно — это затрудняет перебор существующих email.
	// Хендлер должен вернуть 401 Unauthorized.
	ErrInvalidCredentials = errors.New("invalid email or password")

	// ErrTokenNotFound — refresh-токен не найден в БД.
	// Хендлер должен вернуть 401 Unauthorized.
	ErrTokenNotFound = errors.New("refresh token not found")

	// ErrTokenExpired — refresh-токен найден, но истёк срок его действия.
	// Хендлер должен вернуть 401 Unauthorized.
	ErrTokenExpired = errors.New("refresh token expired")

	// ErrTokenRevoked — refresh-токен был уже использован или отозван при логауте.
	// Хендлер должен вернуть 401 Unauthorized.
	ErrTokenRevoked = errors.New("refresh token revoked")

	// ErrResetTokenNotFound — токен сброса пароля не найден в БД.
	// Хендлер должен вернуть 400 Bad Request.
	ErrResetTokenNotFound = errors.New("reset token not found")

	// ErrResetTokenExpired — токен сброса пароля просрочен (TTL 15 минут).
	// Хендлер должен вернуть 400 Bad Request.
	ErrResetTokenExpired = errors.New("reset token expired")

	// ErrResetTokenUsed — токен сброса пароля уже был использован.
	// Каждый токен одноразовый. Хендлер должен вернуть 400 Bad Request.
	ErrResetTokenUsed = errors.New("reset token already used")

	// ErrInvalidCurrentPassword — текущий пароль при смене пароля не совпадает с хранимым.
	// Отдельная от ErrInvalidCredentials, чтобы хендлер мог дать точное сообщение.
	// Хендлер должен вернуть 401 Unauthorized.
	ErrInvalidCurrentPassword = errors.New("current password is incorrect")
)
