package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// responseWriter оборачивает стандартный http.ResponseWriter, чтобы перехватить
// статус-код ответа. Стандартный ResponseWriter не отдаёт статус после WriteHeader —
// только так можно узнать что ответил хендлер.
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

// RequestID генерирует уникальный ID для каждого входящего запроса,
// кладёт его в контекст и добавляет в заголовок ответа X-Request-ID.
// Это позволяет связать несколько строк лога, относящихся к одному запросу.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := generateRequestID()
		// X-Request-ID в ответе удобен при отладке: iOS-клиент видит его в заголовках.
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), contextKeyRequestID, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Logger возвращает middleware, которое логирует каждый HTTP-запрос после его завершения.
// Логирует: метод, путь, статус, время выполнения в мс, IP клиента, request ID.
// Размещается после RequestID в цепочке, чтобы ID уже был в контексте.
func Logger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Оборачиваем ResponseWriter чтобы перехватить статус-код.
			ww := &responseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(ww, r)

			log.Info("request",
				"request_id", RequestIDFromContext(r.Context()),
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.status,
				"duration_ms", time.Since(start).Milliseconds(),
				"ip", ClientIP(r),
			)
		})
	}
}

// ClientIP извлекает реальный IP клиента из запроса.
// За reverse proxy (nginx) реальный IP передаётся в X-Forwarded-For или X-Real-IP.
// Если этих заголовков нет — берём RemoteAddr напрямую.
func ClientIP(r *http.Request) string {
	// X-Forwarded-For может содержать цепочку прокси через запятую:
	// "client, proxy1, proxy2" — берём первый, это и есть исходный клиент.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i != -1 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// RemoteAddr имеет формат "host:port" — отрезаем порт.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// generateRequestID генерирует случайный 8-байтовый ID в hex-формате (16 символов).
// crypto/rand гарантирует непредсказуемость — коллизии практически исключены.
func generateRequestID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
