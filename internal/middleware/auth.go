// Пакет middleware содержит HTTP-middleware для цепочки обработки запросов.
// Middleware оборачивает хендлер и выполняет сквозную логику: аутентификацию,
// логирование, rate limiting и т.д. — до или после основного хендлера.
package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/mixfon/mfauth/pkg/jwt"
)

// contextKey — приватный тип для ключей контекста.
// Использование собственного типа (не string) предотвращает конфликты ключей
// с другими пакетами, которые тоже могут класть значения в контекст.
type contextKey int

const (
	// contextKeyUserID — ключ для хранения ID пользователя в контексте запроса.
	contextKeyUserID contextKey = iota
	// contextKeyUserEmail — ключ для хранения email пользователя в контексте запроса.
	contextKeyUserEmail
)

// Auth возвращает middleware, которое проверяет JWT в заголовке Authorization.
// secret — тот же секрет, которым подписывались access-токены (cfg.JWT.AccessSecret).
// Если токен валиден — кладёт userID и email в контекст и передаёт запрос дальше.
// Если невалиден или отсутствует — немедленно отвечает 401 и прерывает цепочку.
func Auth(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Заголовок должен выглядеть как: Authorization: Bearer <token>
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeUnauthorized(w, "missing authorization header")
				return
			}

			// Отрезаем префикс "Bearer " и получаем сам токен.
			tokenStr, ok := strings.CutPrefix(authHeader, "Bearer ")
			if !ok || tokenStr == "" {
				writeUnauthorized(w, "invalid authorization header format")
				return
			}

			claims, err := jwt.Verify(tokenStr, secret)
			if err != nil {
				// Различаем истёкший токен от невалидного — клиент может
				// обработать их по-разному: на expired сделать refresh, на invalid — выйти.
				if err == jwt.ErrExpiredToken {
					writeUnauthorized(w, "token expired")
					return
				}
				writeUnauthorized(w, "invalid token")
				return
			}

			// Кладём данные пользователя в контекст — хендлер достанет их через хелперы ниже.
			ctx := context.WithValue(r.Context(), contextKeyUserID, claims.UserID)
			ctx = context.WithValue(ctx, contextKeyUserEmail, claims.Email)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// UserIDFromContext извлекает ID пользователя из контекста запроса.
// Возвращает (id, true) если middleware отработал и пользователь аутентифицирован.
// Возвращает (0, false) если вызвано вне защищённого маршрута.
func UserIDFromContext(ctx context.Context) (int64, bool) {
	id, ok := ctx.Value(contextKeyUserID).(int64)
	return id, ok
}

// UserEmailFromContext извлекает email пользователя из контекста запроса.
func UserEmailFromContext(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(contextKeyUserEmail).(string)
	return email, ok
}

// writeUnauthorized пишет JSON-ответ с кодом 401 и текстом ошибки.
// Вынесено в хелпер чтобы не дублировать код в каждой ветке проверки.
func writeUnauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
