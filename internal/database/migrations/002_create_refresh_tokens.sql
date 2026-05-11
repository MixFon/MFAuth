-- Миграция 002: создание таблицы refresh-токенов.
-- Зависит от миграции 001 (таблица users должна существовать).

-- +migrate Up

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token      VARCHAR(512) NOT NULL UNIQUE, -- случайная строка, передаётся клиенту
    expires_at TIMESTAMPTZ NOT NULL,
    revoked    BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Индекс по token: используется при каждом обновлении access-токена
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token   ON refresh_tokens (token);
-- Индекс по user_id: используется при logout (отзыв всех токенов пользователя)
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens (user_id);

-- +migrate Down

DROP INDEX IF EXISTS idx_refresh_tokens_user_id;
DROP INDEX IF EXISTS idx_refresh_tokens_token;
DROP TABLE IF EXISTS refresh_tokens;
