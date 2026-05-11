---
name: MFAuth project state
description: Прогресс реализации Go-сервиса авторизации для iOS и Desktop приложений
type: project
---

Проект: автономный сервис авторизации на Go, деплоится на отдельный VPS.
Клиенты: iOS (Swift) и Desktop приложение.

**Why:** Отдельный модуль авторизации, разворачивается независимо от основного приложения.

**How to apply:** При продолжении работы — начинать с шага 3 (internal/service).

## Технологический стек
- HTTP: `net/http` (Go 1.22+ ServeMux с method routing), НЕТ фреймворков
- БД: PostgreSQL + `database/sql` + `pgx/v5` только как драйвер
- JWT: кастомная реализация на `crypto/hmac` + `crypto/sha256` (без библиотек)
- Пароли: `golang.org/x/crypto/bcrypt`, cost=12
- Логи: `log/slog` (JSON формат)
- Refresh токены: хранятся в PostgreSQL (Redis не используется)
- Всего внешних зависимостей: 2 (pgx/v5 и golang.org/x/crypto)

## Что уже реализовано (шаги 1-2)

### Шаг 1 — Инициализация
- `go.mod` — модуль `github.com/mixfon/mfauth`
- `internal/config/config.go` — загрузка конфига из os.Getenv с fallback-значениями
- `internal/domain/user.go` — User, RegisterInput, LoginInput
- `internal/domain/token.go` — RefreshToken, TokenPair, RefreshInput
- `pkg/hash/hash.go` — bcrypt Password() и CheckPassword()
- `pkg/jwt/jwt.go` — Generate() и Verify() на HMAC-SHA256 без библиотек
- `pkg/validate/validate.go` — Email() и Password() через regexp
- `cmd/server/main.go` — HTTP сервер с graceful shutdown (SIGINT/SIGTERM)

### Шаг 2 — БД и Repository
- `internal/database/database.go` — подключение к PostgreSQL, пул соединений, runner миграций через embed.FS + schema_migrations таблица
- `internal/database/migrations/001_create_users.sql` — таблица users
- `internal/database/migrations/002_create_refresh_tokens.sql` — таблица refresh_tokens с ON DELETE CASCADE
- `internal/repository/repository.go` — интерфейсы UserRepository и TokenRepository
- `internal/repository/user_postgres.go` — реализация: Create, FindByEmail, FindByID
- `internal/repository/token_postgres.go` — реализация: Save, FindByToken, Revoke, RevokeAllForUser, DeleteExpired

## Что осталось реализовать

- **Шаг 3** — `internal/service/auth.go`: AuthService с методами Register, Login, Refresh, Logout
- **Шаг 4** — `internal/middleware/auth.go`: JWT middleware для защищённых эндпоинтов
- **Шаг 5** — `internal/handler/auth.go`: HTTP хендлеры (POST /auth/register, login, refresh, logout; GET /auth/me)
- **Шаг 6** — Подключить всё в `cmd/server/main.go` (dependency injection вручную)
- **Шаг 7** — `docker/Dockerfile` (multi-stage build) + `docker/docker-compose.yml`
- **Шаг 8** — nginx конфиг + TLS (Let's Encrypt)

## Эндпоинты (планируемые)
- POST /auth/register
- POST /auth/login
- POST /auth/refresh
- POST /auth/logout
- GET  /auth/me  (защищённый JWT middleware)
- GET  /health
