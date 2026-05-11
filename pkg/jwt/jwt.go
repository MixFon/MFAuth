// Пакет jwt реализует создание и верификацию JSON Web Tokens (JWT) стандарта RFC 7519.
// Реализация использует только стандартную библиотеку Go: crypto/hmac, crypto/sha256,
// encoding/base64, encoding/json — без сторонних зависимостей.
//
// Формат токена: Base64URL(header) . Base64URL(payload) . Base64URL(HMAC-SHA256 подпись)
// Алгоритм подписи: HS256 (HMAC с SHA-256).
package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var (
	// ErrInvalidToken возвращается когда структура токена нарушена или подпись не совпадает.
	ErrInvalidToken = errors.New("invalid token")
	// ErrExpiredToken возвращается когда токен структурно корректен, но истёк срок его действия.
	ErrExpiredToken = errors.New("token expired")
)

// Claims — полезная нагрузка (payload) JWT токена.
// Содержит идентификатор пользователя, email и временны́е метки.
// Краткие имена полей (uid, exp, iat) уменьшают размер токена — это важно,
// так как токен передаётся в каждом HTTP-запросе.
type Claims struct {
	UserID int64  `json:"uid"`
	Email  string `json:"email"`
	Exp    int64  `json:"exp"` // Unix timestamp: момент истечения токена
	Iat    int64  `json:"iat"` // Unix timestamp: момент выпуска токена
}

// header — фиксированная Base64URL-строка заголовка JWT.
// Вычисляется один раз при старте, так как алгоритм (HS256) никогда не меняется.
var header = base64url(mustJSON(map[string]string{
	"alg": "HS256",
	"typ": "JWT",
}))

// Generate создаёт подписанный JWT токен для указанного пользователя.
// secret — секретный ключ из конфига (разный для Access и Refresh токенов).
// ttl — время жизни токена; после его истечения Verify вернёт ErrExpiredToken.
func Generate(userID int64, email, secret string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID,
		Email:  email,
		Exp:    now.Add(ttl).Unix(),
		Iat:    now.Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	// Тело токена = закодированный заголовок + закодированный payload
	body := header + "." + base64url(payload)
	sig := sign(body, secret)
	return body + "." + sig, nil
}

// Verify проверяет подпись токена и срок его действия.
// Возвращает Claims если токен валиден, иначе — одну из ошибок ErrInvalidToken / ErrExpiredToken.
// Проверка подписи выполняется до декодирования payload — это предотвращает
// обработку данных из токена с неверной подписью.
func Verify(token, secret string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	// Сначала проверяем подпись, чтобы не доверять данным из неподписанного токена
	body := parts[0] + "." + parts[1]
	if sign(body, secret) != parts[2] {
		return nil, ErrInvalidToken
	}

	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}

	var c Claims
	if err = json.Unmarshal(raw, &c); err != nil {
		return nil, ErrInvalidToken
	}

	if time.Now().Unix() > c.Exp {
		return nil, ErrExpiredToken
	}
	return &c, nil
}

// sign вычисляет HMAC-SHA256 подпись для строки data с использованием секретного ключа.
// Возвращает Base64URL-строку без padding символов '='.
func sign(data, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	return base64url(mac.Sum(nil))
}

// base64url кодирует байты в Base64 URL-safe формат без padding (=).
// Именно этот формат требует стандарт JWT (RFC 7519).
func base64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// mustJSON сериализует значение в JSON. Используется только для статических данных
// (заголовок JWT), поэтому паника при ошибке допустима — она означает баг в коде, не в данных.
func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
