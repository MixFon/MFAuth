// Пакет repository определяет интерфейсы доступа к данным.
// Бизнес-логика (service) зависит только от этих интерфейсов, а не от конкретных реализаций.
// Это позволяет легко подменить PostgreSQL на любое другое хранилище, не меняя остальной код.
package repository

import (
	"context"

	"github.com/mixfon/mfauth/internal/domain"
)

// UserRepository описывает операции с пользователями в хранилище.
type UserRepository interface {
	// Create сохраняет нового пользователя и заполняет поле ID.
	Create(ctx context.Context, user *domain.User) error

	// FindByEmail возвращает пользователя по email.
	// Используется при логине для проверки пароля.
	FindByEmail(ctx context.Context, email string) (*domain.User, error)

	// FindByID возвращает пользователя по идентификатору.
	// Используется в защищённых эндпоинтах (например, GET /auth/me).
	FindByID(ctx context.Context, id int64) (*domain.User, error)
}

// TokenRepository описывает операции с refresh-токенами в хранилище.
type TokenRepository interface {
	// Save сохраняет новый refresh-токен в БД.
	Save(ctx context.Context, token *domain.RefreshToken) error

	// FindByToken ищет токен по его строковому значению.
	// Используется при обновлении access-токена (/auth/refresh).
	FindByToken(ctx context.Context, token string) (*domain.RefreshToken, error)

	// Revoke помечает токен как отозванный (revoked=true).
	// Используется при логауте и при ротации токенов.
	Revoke(ctx context.Context, token string) error

	// RevokeAllForUser отзывает все токены пользователя.
	// Используется при смене пароля или принудительном логауте со всех устройств.
	RevokeAllForUser(ctx context.Context, userID int64) error

	// DeleteExpired удаляет просроченные токены из БД.
	// Рекомендуется вызывать периодически, чтобы таблица не разрасталась.
	DeleteExpired(ctx context.Context) error
}
