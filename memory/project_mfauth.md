---
name: MFAuth project state
description: Прогресс реализации Go-сервиса авторизации для iOS и Desktop приложений
type: project
---

Проект: автономный сервис авторизации на Go, деплоится на отдельный VPS.
Клиенты: iOS (Swift) и Desktop приложение.

**Why:** Отдельный модуль авторизации, разворачивается независимо от основного приложения.

**How to apply:** Все шаги 1-9 реализованы. При продолжении — начинать со следующего запланированного шага (см. раздел "Запланировано").

## Технологический стек
- HTTP: `net/http` (Go 1.22+ ServeMux с method routing), НЕТ фреймворков
- БД: PostgreSQL + `database/sql` + `pgx/v5` только как драйвер
- JWT: кастомная реализация на `crypto/hmac` + `crypto/sha256` (без библиотек)
- Пароли: `golang.org/x/crypto/bcrypt`, cost=12
- Логи: `log/slog` (JSON формат)
- Refresh токены: хранятся в PostgreSQL (Redis не используется), token rotation при каждом refresh
- Refresh token: 32 байта crypto/rand → hex-строка 64 символа, в БД хранится как есть (не хешируется)
- Всего внешних зависимостей: 2 (pgx/v5 и golang.org/x/crypto)

## Что реализовано — всё компилируется, тесты проходят

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

### Шаг 7 — Docker
- `docker/Dockerfile` — multi-stage build: golang:1.26-alpine (сборка) → alpine:latest (runtime)
- `docker/docker-compose.yml` — сервисы: postgres (с healthcheck) + mfauth + nginx
- `.dockerignore` — исключает .git, .env, *.md из контекста сборки
- Порт 8080 не торчит наружу — доступен только nginx внутри Docker-сети

### Шаг 8 — nginx + TLS
- `nginx/nginx.conf` — HTTP→HTTPS редирект, reverse proxy на mfauth:8080, TLS 1.2/1.3
- Сертификаты Let's Encrypt монтируются с хоста VPS: /etc/letsencrypt

### Шаг 9 — Тесты
- `pkg/jwt/jwt_test.go` — 5 тестов: валидный токен, истёкший, неверный секрет, malformed, tampered payload
- `pkg/hash/hash_test.go` — 4 теста: хеш непустой, уникальные соли, верный/неверный пароль
- `pkg/validate/validate_test.go` — 2 table-driven теста: email и password валидация
- `internal/service/auth_test.go` — 13 тестов: Register, Login, Refresh, Logout через mock-репозитории
- Итого 24 теста, все проходят

## Эндпоинты (реализованы)
- POST /auth/register — 201 / 400 / 409 / 500
- POST /auth/login    — 200 / 400 / 401 / 500
- POST /auth/refresh  — 200 / 400 / 401 / 500
- POST /auth/logout   — 204 / 400 / 401 / 500
- GET  /auth/me       — 200 (защищён middleware.Auth)
- GET  /health        — 200 {"status":"ok"}

### Шаг 10 — Восстановление пароля по email
- `internal/database/migrations/003_create_password_reset_tokens.sql` — таблица password_reset_tokens (TTL 15 мин, одноразовые)
- `internal/domain/reset_token.go` — PasswordResetToken, PasswordResetRequestInput, PasswordResetConfirmInput
- `internal/repository/reset_token_postgres.go` — ResetTokenRepository: Save, FindByToken, MarkUsed, DeleteExpired
- `pkg/email/email.go` — Sender на net/smtp (без зависимостей): STARTTLS (587) и SSL (465)
- UserRepository расширен методом UpdatePassword
- AuthService расширен: RequestPasswordReset, ConfirmPasswordReset + интерфейс EmailSender
- Два новых эндпоинта: POST /auth/password/reset/request и /confirm
- При подтверждении: смена пароля + RevokeAllForUser (принудительный выход со всех устройств)
- Конфиг: SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM, APP_URL
- Тестов: 31 (было 24, добавлено 7)

### Шаг 11 — Выход со всех устройств
- `POST /auth/logout/all` — защищён middleware.Auth, userID берётся из контекста (без тела запроса)
- Новый метод `LogoutAll(ctx, userID)` в интерфейсе и реализации AuthService — вызывает tokenRepo.RevokeAllForUser
- Новый хендлер `LogoutAll` в handler/auth.go — возвращает 204 No Content
- Маршрут зарегистрирован в main.go рядом с GET /auth/me (оба защищены authMiddleware)
- Тестов: 33 (было 31, добавлено 2: success + repo error)

### Шаг 12 — Смена пароля
- `POST /auth/password/change` — защищён middleware.Auth, userID из контекста
- Новая структура `domain.ChangePasswordInput` (current_password + new_password)
- Новая ошибка `service.ErrInvalidCurrentPassword` (отдельная от ErrInvalidCredentials)
- Метод `ChangePassword(ctx, userID, input)` в сервисе: FindByID → CheckPassword → validate → hash → UpdatePassword
- Хендлер: ErrInvalidCurrentPassword → 401, ошибки валидации → 400, успех → 200
- Тестов: 36 (было 33, добавлено 3: success, wrong current password, weak new password)

## Запланировано (в порядке реализации)

- **Swagger / OpenAPI** — документация всех эндпоинтов для iOS и Desktop разработчиков. Вероятно через swaggo/swag или ручной spec файл.

### Социальная авторизация (Google + Yandex)

Приложения ещё в разработке — архитектура заложена заранее.

**Схема:** мобильное/десктопное приложение использует SDK провайдера, получает `id_token`, отправляет его на сервер. Сервер верифицирует подпись, читает `sub`+`email`, находит или создаёт пользователя, возвращает наш `TokenPair`.

**Новые эндпоинты (публичные, без middleware.Auth):**
- `POST /auth/social/google` — тело: `{"id_token": "..."}`
- `POST /auth/social/yandex` — тело: `{"id_token": "..."}`

**Новые переменные окружения:**
- `GOOGLE_CLIENT_ID` — из Google Cloud Console (APIs & Services → Credentials → OAuth 2.0 Client ID)
- `YANDEX_CLIENT_ID` — из oauth.yandex.ru (создать приложение, доступы: login:email, login:info)

**Логика поиска/создания пользователя:**
1. Ищем в `social_accounts` по (provider, provider_id=sub)
2. Нашли → загружаем пользователя
3. Не нашли → ищем по email: нашли → привязываем соцсеть к существующему аккаунту
4. Email новый → создаём пользователя с пустым PasswordHash + запись в social_accounts

**Пользователи без пароля:** не могут войти через `/auth/login`, но могут установить пароль через `/auth/password/reset/request`.

**Порядок реализации (5 шагов):**

1. `migrations/004_create_social_accounts.sql` + `internal/domain/social.go`
   - Таблица: `id`, `user_id` (FK → users), `provider`, `provider_id`, `created_at`, UNIQUE(provider, provider_id)
   - Структуры: `SocialAccount`, `SocialLoginInput{IDToken string}`

2. `pkg/jwks/jwks.go` + тесты — самая сложная часть
   - JWKS-клиент: загружает публичные RSA-ключи провайдера по URL
   - Кеш с TTL 1 час (sync.RWMutex) — не ходим к провайдеру на каждый запрос
   - `Verify(token, issuer, audience)` — проверяет подпись (RS256) + exp + iss + aud
   - Google JWKS URL: `https://www.googleapis.com/oauth2/v3/certs`
   - Yandex JWKS URL: `https://login.yandex.ru/info` (уточнить актуальный endpoint)
   - Только стандартная библиотека: `crypto/rsa`, `crypto/x509`, `encoding/base64`

3. `internal/repository/repository.go` + `social_postgres.go`
   - Интерфейс `SocialRepository`: `FindByProvider(ctx, provider, providerID)`, `Create(ctx, account)`

4. `internal/config/config.go` — добавить `GoogleClientID`, `YandexClientID`

5. `internal/service/auth.go` + `handler/auth.go` + `cmd/server/main.go`
   - Методы сервиса: `LoginWithGoogle(ctx, idToken)`, `LoginWithYandex(ctx, idToken)`
   - Хендлеры + регистрация маршрутов + wire-up socialRepo в main.go
