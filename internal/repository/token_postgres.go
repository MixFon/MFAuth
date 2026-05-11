// Реализация TokenRepository поверх PostgreSQL через стандартный database/sql.
package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/mixfon/mfauth/internal/domain"
)

// tokenPostgres — конкретная реализация TokenRepository для PostgreSQL.
type tokenPostgres struct {
	db *sql.DB
}

// NewTokenRepository создаёт новый экземпляр TokenRepository, работающий с PostgreSQL.
func NewTokenRepository(db *sql.DB) TokenRepository {
	return &tokenPostgres{db: db}
}

// Save сохраняет новый refresh-токен в таблицу refresh_tokens.
// RETURNING id, created_at заполняет соответствующие поля структуры.
func (r *tokenPostgres) Save(ctx context.Context, token *domain.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (user_id, token, expires_at)
		VALUES ($1, $2, $3)
		RETURNING id, created_at`

	err := r.db.QueryRowContext(ctx, query,
		token.UserID,
		token.Token,
		token.ExpiresAt,
	).Scan(&token.ID, &token.CreatedAt)

	if err != nil {
		return fmt.Errorf("save refresh token: %w", err)
	}
	return nil
}

// FindByToken ищет refresh-токен по его строковому значению.
// Возвращает ErrNotFound если токен не существует.
// Вызывающий код должен дополнительно проверить поля Revoked и ExpiresAt.
func (r *tokenPostgres) FindByToken(ctx context.Context, token string) (*domain.RefreshToken, error) {
	query := `
		SELECT id, user_id, token, expires_at, revoked, created_at
		FROM refresh_tokens
		WHERE token = $1`

	var t domain.RefreshToken
	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&t.ID,
		&t.UserID,
		&t.Token,
		&t.ExpiresAt,
		&t.Revoked,
		&t.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find refresh token: %w", err)
	}
	return &t, nil
}

// Revoke помечает один токен как отозванный.
// Используется при ротации: старый токен отзывается, выдаётся новый.
func (r *tokenPostgres) Revoke(ctx context.Context, token string) error {
	query := `UPDATE refresh_tokens SET revoked = TRUE WHERE token = $1`

	if _, err := r.db.ExecContext(ctx, query, token); err != nil {
		return fmt.Errorf("revoke token: %w", err)
	}
	return nil
}

// RevokeAllForUser отзывает все активные токены пользователя.
// Полезно при логауте со всех устройств или при подозрении на компрометацию аккаунта.
func (r *tokenPostgres) RevokeAllForUser(ctx context.Context, userID int64) error {
	query := `UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND revoked = FALSE`

	if _, err := r.db.ExecContext(ctx, query, userID); err != nil {
		return fmt.Errorf("revoke all user tokens: %w", err)
	}
	return nil
}

// DeleteExpired удаляет все просроченные токены из таблицы.
// Таблица без очистки будет расти бесконечно, так как при каждом логине
// создаётся новый токен со сроком жизни 30 дней.
// Рекомендуется вызывать раз в сутки (например, при старте сервера).
func (r *tokenPostgres) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM refresh_tokens WHERE expires_at < NOW()`

	if _, err := r.db.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("delete expired tokens: %w", err)
	}
	return nil
}
