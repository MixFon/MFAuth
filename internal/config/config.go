// Пакет config отвечает за загрузку конфигурации приложения из переменных окружения.
// Все настройки (порт сервера, строка подключения к БД, секреты JWT) задаются через
// env-переменные, что позволяет менять конфигурацию без пересборки бинарника —
// это стандартная практика для деплоя на VPS и в Docker-контейнерах.
package config

import (
	"os"
	"strconv"
	"time"
)

// Config — корневая структура конфигурации приложения.
// Объединяет настройки всех подсистем: сервера, базы данных, JWT и email.
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	Email    EmailConfig
}

// ServerConfig содержит параметры HTTP-сервера.
// ReadTimeout и WriteTimeout защищают от медленных клиентов — соединение
// принудительно закрывается, если клиент не успевает передать запрос или
// получить ответ за отведённое время.
type ServerConfig struct {
	Port         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// DatabaseConfig содержит строку подключения к PostgreSQL (DSN).
// Формат DSN: postgres://user:password@host:port/dbname?sslmode=disable
type DatabaseConfig struct {
	DSN string
}

// JWTConfig содержит секреты и время жизни токенов авторизации.
// Используются два разных секрета для Access и Refresh токенов —
// это позволяет инвалидировать все Refresh токены, не затрагивая Access токены, и наоборот.
type JWTConfig struct {
	AccessSecret    string
	RefreshSecret   string
	AccessTokenTTL  time.Duration // короткое время жизни (по умолчанию 15 минут)
	RefreshTokenTTL time.Duration // длинное время жизни (по умолчанию 30 дней)
}

// EmailConfig содержит параметры SMTP для отправки писем.
// AppURL — базовый URL приложения, вставляется в письмо как ссылка сброса пароля.
// Для iOS-приложений это может быть deep link: myapp://reset-password
type EmailConfig struct {
	SMTPHost string
	SMTPPort string // 587 (STARTTLS) или 465 (SSL/TLS)
	User     string
	Pass     string
	From     string
	AppURL   string
}

// Load читает переменные окружения и возвращает заполненный Config.
// Для каждого параметра задано значение по умолчанию — это упрощает
// локальную разработку без обязательного .env файла.
func Load() *Config {
	return &Config{
		Server: ServerConfig{
			Port:         getEnv("SERVER_PORT", "8080"),
			ReadTimeout:  getDurationEnv("SERVER_READ_TIMEOUT_SEC", 10) * time.Second,
			WriteTimeout: getDurationEnv("SERVER_WRITE_TIMEOUT_SEC", 10) * time.Second,
		},
		Database: DatabaseConfig{
			DSN: getEnv("DATABASE_DSN", "postgres://postgres:postgres@localhost:5432/mfauth?sslmode=disable"),
		},
		JWT: JWTConfig{
			AccessSecret:    getEnv("JWT_ACCESS_SECRET", "change_me_access_secret"),
			RefreshSecret:   getEnv("JWT_REFRESH_SECRET", "change_me_refresh_secret"),
			AccessTokenTTL:  getDurationEnv("JWT_ACCESS_TTL_MIN", 15) * time.Minute,
			RefreshTokenTTL: getDurationEnv("JWT_REFRESH_TTL_DAY", 30) * 24 * time.Hour,
		},
		Email: EmailConfig{
			SMTPHost: getEnv("SMTP_HOST", ""),
			SMTPPort: getEnv("SMTP_PORT", "587"),
			User:     getEnv("SMTP_USER", ""),
			Pass:     getEnv("SMTP_PASS", ""),
			From:     getEnv("SMTP_FROM", ""),
			AppURL:   getEnv("APP_URL", "https://example.com"),
		},
	}
}

// getEnv возвращает значение переменной окружения по ключу.
// Если переменная не задана или пустая — возвращает fallback.
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// getDurationEnv читает числовое значение из переменной окружения и возвращает его
// как time.Duration. Множитель (секунды, минуты, дни) применяется на стороне вызывающего кода.
// При ошибке парсинга возвращает fallback.
func getDurationEnv(key string, fallback int64) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return time.Duration(fallback)
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return time.Duration(fallback)
	}
	return time.Duration(n)
}
