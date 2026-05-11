// Пакет database отвечает за подключение к PostgreSQL и запуск миграций.
// Использует стандартный database/sql с pgx в качестве драйвера.
// Миграции читаются из embed.FS — файлы .sql встраиваются прямо в бинарник
// при сборке, поэтому на сервере не нужна отдельная папка с SQL-файлами.
package database

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // регистрирует pgx как драйвер "pgx" для database/sql
)

// migrationsFS встраивает все .sql файлы из папки migrations в бинарник.
// Директива //go:embed должна находиться непосредственно перед объявлением переменной.
//
//go:embed migrations/*.sql
var migrationsFS embed.FS

// New открывает соединение с PostgreSQL и проверяет его доступность.
// DSN — строка подключения формата postgres://user:pass@host:port/dbname
func New(dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// Настройки пула соединений.
	// На небольшом VPS достаточно 10 соединений — PostgreSQL по умолчанию
	// поддерживает 100, часть резервируется для служебных подключений.
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Проверяем реальное соединение с БД (Open сам по себе его не устанавливает).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err = db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}

	return db, nil
}

// Migrate читает SQL-файлы миграций в алфавитном порядке и применяет их.
// Перед запуском создаёт служебную таблицу schema_migrations для отслеживания
// уже применённых миграций — повторный запуск безопасен (идемпотентен).
func Migrate(db *sql.DB) error {
	// Создаём таблицу учёта миграций если её ещё нет.
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			name       TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	// Читаем список .sql файлов из встроенной файловой системы.
	entries, err := fs.Glob(migrationsFS, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("glob migrations: %w", err)
	}
	sort.Strings(entries) // гарантируем порядок 001, 002, 003...

	for _, path := range entries {
		name := path[len("migrations/"):] // "001_create_users.sql"

		// Проверяем, была ли эта миграция уже применена.
		var exists bool
		err = db.QueryRow(`SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE name=$1)`, name).Scan(&exists)
		if err != nil {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		if exists {
			continue // пропускаем уже применённые
		}

		// Читаем содержимое файла и берём только часть до "-- +migrate Down".
		content, err := migrationsFS.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		upSQL := extractUp(string(content))

		// Применяем миграцию и фиксируем её в schema_migrations в одной транзакции.
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin tx for %s: %w", name, err)
		}

		if _, err = tx.Exec(upSQL); err != nil {
			tx.Rollback()
			return fmt.Errorf("exec migration %s: %w", name, err)
		}

		if _, err = tx.Exec(`INSERT INTO schema_migrations (name) VALUES ($1)`, name); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %s: %w", name, err)
		}

		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}
	}

	return nil
}

// extractUp возвращает SQL-код из секции UP миграции.
// Всё что идёт после маркера "-- +migrate Down" — отбрасывается.
func extractUp(content string) string {
	const downMarker = "-- +migrate Down"
	if idx := strings.Index(content, downMarker); idx != -1 {
		content = content[:idx]
	}
	// Убираем маркер UP если он есть — PostgreSQL его не поймёт.
	content = strings.ReplaceAll(content, "-- +migrate Up", "")
	return strings.TrimSpace(content)
}
