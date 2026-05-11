-- Миграция 001: создание таблицы пользователей.
-- Направление UP — применить изменения.

-- +migrate Up

CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL PRIMARY KEY,
    email         VARCHAR(255) NOT NULL UNIQUE,  -- уникальный идентификатор аккаунта
    password_hash VARCHAR(255) NOT NULL,          -- bcrypt-хэш, открытый пароль не хранится
    is_active     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Индекс по email: используется при каждом логине (SELECT по email)
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

-- Направление DOWN — откатить изменения.
-- +migrate Down

DROP INDEX IF EXISTS idx_users_email;
DROP TABLE IF EXISTS users;
