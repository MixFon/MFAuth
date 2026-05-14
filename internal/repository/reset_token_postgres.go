// Реализация ResetTokenRepository поверх PostgreSQL.
package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/mixfon/mfauth/internal/domain"
)

// resetTokenPostgres — конкретная реализация ResetTokenRepository для PostgreSQL.
type resetTokenPostgres struct {
	db *sql.DB
}

// NewResetTokenRepository создаёт новый экземпляр ResetTokenRepository для PostgreSQL.
func NewResetTokenRepository(db *sql.DB) ResetTokenRepository {
	return &resetTokenPostgres{db: db}
}

// Save сохраняет новый токен сброса пароля в БД.
func (r *resetTokenPostgres) Save(ctx context.Context, token *domain.PasswordResetToken) error {
	query := `
		INSERT INTO password_reset_tokens (user_id, token, expires_at)
		VALUES ($1, $2, $3)
		RETURNING id, created_at`

	err := r.db.QueryRowContext(ctx, query,
		token.UserID,
		token.Token,
		token.ExpiresAt,
	).Scan(&token.ID, &token.CreatedAt)
	if err != nil {
		return fmt.Errorf("save reset token: %w", err)
	}
	return nil
}

// FindByToken ищет токен по строковому значению.
// Возвращает ErrNotFound если токен не существует.
func (r *resetTokenPostgres) FindByToken(ctx context.Context, token string) (*domain.PasswordResetToken, error) {
	query := `
		SELECT id, user_id, token, expires_at, used, created_at
		FROM password_reset_tokens
		WHERE token = $1`

	var t domain.PasswordResetToken
	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&t.ID,
		&t.UserID,
		&t.Token,
		&t.ExpiresAt,
		&t.Used,
		&t.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find reset token: %w", err)
	}
	return &t, nil
}

// MarkUsed помечает токен как использованный, чтобы он не мог быть применён повторно.
func (r *resetTokenPostgres) MarkUsed(ctx context.Context, token string) error {
	query := `UPDATE password_reset_tokens SET used = TRUE WHERE token = $1`
	if _, err := r.db.ExecContext(ctx, query, token); err != nil {
		return fmt.Errorf("mark reset token used: %w", err)
	}
	return nil
}

// DeleteExpired удаляет просроченные токены из БД.
// Рекомендуется вызывать периодически для очистки таблицы.
func (r *resetTokenPostgres) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM password_reset_tokens WHERE expires_at < $1`
	if _, err := r.db.ExecContext(ctx, query, time.Now()); err != nil {
		return fmt.Errorf("delete expired reset tokens: %w", err)
	}
	return nil
}
