// Реализация UserRepository поверх PostgreSQL через стандартный database/sql.
// Весь SQL сосредоточен здесь — остальной код работает через интерфейс UserRepository.
package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/mixfon/mfauth/internal/domain"
)

// ErrNotFound возвращается когда запись не найдена в БД.
// Определяем собственную ошибку, чтобы не пропускать sql.ErrNoRows за пределы пакета.
var ErrNotFound = errors.New("record not found")

// userPostgres — конкретная реализация UserRepository для PostgreSQL.
type userPostgres struct {
	db *sql.DB
}

// NewUserRepository создаёт новый экземпляр UserRepository, работающий с PostgreSQL.
func NewUserRepository(db *sql.DB) UserRepository {
	return &userPostgres{db: db}
}

// Create вставляет нового пользователя в таблицу users.
// RETURNING id заполняет поле user.ID сгенерированным значением без дополнительного SELECT.
func (r *userPostgres) Create(ctx context.Context, user *domain.User) error {
	query := `
		INSERT INTO users (email, password_hash, is_active)
		VALUES ($1, $2, $3)
		RETURNING id, created_at`

	err := r.db.QueryRowContext(ctx, query,
		user.Email,
		user.PasswordHash,
		user.IsActive,
	).Scan(&user.ID, &user.CreatedAt)

	if err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	return nil
}

// FindByEmail ищет пользователя по email адресу.
// Возвращает ErrNotFound если пользователь не существует.
func (r *userPostgres) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
		SELECT id, email, password_hash, is_active, created_at
		FROM users
		WHERE email = $1`

	var u domain.User
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&u.ID,
		&u.Email,
		&u.PasswordHash,
		&u.IsActive,
		&u.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find user by email: %w", err)
	}
	return &u, nil
}

// UpdatePassword обновляет хэш пароля пользователя.
// Используется при сбросе пароля — принимает уже готовый bcrypt-хэш, не открытый пароль.
func (r *userPostgres) UpdatePassword(ctx context.Context, userID int64, passwordHash string) error {
	query := `UPDATE users SET password_hash = $1 WHERE id = $2`
	if _, err := r.db.ExecContext(ctx, query, passwordHash, userID); err != nil {
		return fmt.Errorf("update password: %w", err)
	}
	return nil
}

// FindByID ищет пользователя по первичному ключу.
// Возвращает ErrNotFound если пользователь не существует.
func (r *userPostgres) FindByID(ctx context.Context, id int64) (*domain.User, error) {
	query := `
		SELECT id, email, password_hash, is_active, created_at
		FROM users
		WHERE id = $1`

	var u domain.User
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&u.ID,
		&u.Email,
		&u.PasswordHash,
		&u.IsActive,
		&u.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find user by id: %w", err)
	}
	return &u, nil
}
