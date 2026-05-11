package domain

import "time"

// RefreshToken — сущность долгосрочного токена, хранящегося в PostgreSQL.
// При каждом обновлении Access токена старый Refresh токен помечается как Revoked
// и создаётся новый — это называется "rotating refresh tokens" и предотвращает
// повторное использование перехваченного токена.
type RefreshToken struct {
	ID        int64
	UserID    int64
	Token     string    // случайная строка, хранится в БД и отправляется клиенту
	ExpiresAt time.Time // после этого времени токен недействителен
	Revoked   bool      // true — токен был использован или пользователь вышел
	CreatedAt time.Time
}

// TokenPair — ответ сервера при успешном входе или обновлении токена.
// AccessToken — короткоживущий JWT (15 мин), используется для доступа к API.
// RefreshToken — долгоживущий токен (30 дней), используется только для получения нового AccessToken.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// RefreshInput — тело запроса на обновление Access токена.
// Клиент отправляет свой текущий Refresh токен, сервер возвращает новую пару токенов.
type RefreshInput struct {
	RefreshToken string `json:"refresh_token"`
}
