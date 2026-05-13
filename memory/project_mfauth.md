---
name: MFAuth project state
description: Прогресс реализации Go-сервиса авторизации для iOS и Desktop приложений
type: project
---

Проект: автономный сервис авторизации на Go, деплоится на отдельный VPS.
Клиенты: iOS (Swift) и Desktop приложение.

**Why:** Отдельный модуль авторизации, разворачивается независимо от основного приложения.

**How to apply:** При продолжении работы — начинать с шага 7 (Docker).

## Технологический стек
- HTTP: `net/http` (Go 1.22+ ServeMux с method routing), НЕТ фреймворков
- БД: PostgreSQL + `database/sql` + `pgx/v5` только как драйвер
- JWT: кастомная реализация на `crypto/hmac` + `crypto/sha256` (без библиотек)
- Пароли: `golang.org/x/crypto/bcrypt`, cost=12
- Логи: `log/slog` (JSON формат)
- Refresh токены: хранятся в PostgreSQL (Redis не используется), token rotation при каждом refresh
- Refresh token: 32 байта crypto/rand → hex-строка 64 символа, в БД хранится как есть (не хешируется)
- Всего внешних зависимостей: 2 (pgx/v5 и golang.org/x/crypto)

## Что реализовано (шаги 1-6) — всё компилируется

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
- `internal/repository/user_postgres.go` — реализация: Create, FindByEmail, FindByID (возвращает ErrNotFound при отсутствии)
- `internal/repository/token_postgres.go` — реализация: Save, FindByToken, Revoke, RevokeAllForUser, DeleteExpired

### Шаг 3 — Service
- `internal/service/errors.go` — ErrEmailTaken, ErrInvalidCredentials, ErrTokenNotFound, ErrTokenExpired, ErrTokenRevoked
- `internal/service/auth.go` — интерфейс AuthService + реализация: Register, Login, Refresh, Logout, generateTokenPair
- Важно: repository.ErrNotFound обрабатывается через errors.Is — не пробрасывается наружу

### Шаг 4 — Middleware
- `internal/middleware/auth.go` — middleware Auth(secret) проверяет JWT из заголовка Authorization: Bearer <token>
- Хелперы UserIDFromContext и UserEmailFromContext для извлечения данных в хендлерах
- Различает ErrExpiredToken и ErrInvalidToken — разные сообщения в ответе

### Шаг 5 — Handlers
- `internal/handler/auth.go` — Register (201), Login (200), Refresh (200), Logout (204), Me (200)
- Приватные хелперы: decodeJSON (с DisallowUnknownFields), writeJSON, errorResponse
- Маппинг ошибок сервиса → HTTP статусы через errors.Is

### Шаг 6 — Dependency injection в main.go
- `cmd/server/main.go` обновлён: db → userRepo + tokenRepo → authService → authHandler
- Все маршруты зарегистрированы, GET /auth/me обёрнут в middleware.Auth

## Что осталось реализовать

- **Шаг 7** — `docker/Dockerfile` (multi-stage build) + `docker/docker-compose.yml`
- **Шаг 8** — nginx конфиг + TLS (Let's Encrypt)

## Эндпоинты (реализованы)
- POST /auth/register — 201 / 400 / 409 / 500
- POST /auth/login    — 200 / 400 / 401 / 500
- POST /auth/refresh  — 200 / 400 / 401 / 500
- POST /auth/logout   — 204 / 400 / 401 / 500
- GET  /auth/me       — 200 (защищён middleware.Auth)
- GET  /health        — 200 {"status":"ok"}
