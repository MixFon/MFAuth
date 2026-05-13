// Пакет handler содержит HTTP-хендлеры — тонкий слой между транспортом и бизнес-логикой.
// Хендлер отвечает только за: разбор запроса, вызов сервиса, формирование ответа.
// Никакой бизнес-логики здесь нет — всё делегируется в service.AuthService.
package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/mixfon/mfauth/internal/middleware"
	"github.com/mixfon/mfauth/internal/service"
	"github.com/mixfon/mfauth/internal/domain"
	"github.com/mixfon/mfauth/pkg/validate"
)

// AuthHandler объединяет все HTTP-хендлеры, связанные с авторизацией.
// Зависит от интерфейса AuthService, а не от конкретной реализации.
type AuthHandler struct {
	service service.AuthService
	log     *slog.Logger
}

// NewAuthHandler создаёт новый AuthHandler.
func NewAuthHandler(svc service.AuthService, log *slog.Logger) *AuthHandler {
	return &AuthHandler{service: svc, log: log}
}

// Register обрабатывает POST /auth/register.
// Создаёт нового пользователя. Возвращает 201 при успехе.
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var input domain.RegisterInput
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse("invalid request body"))
		return
	}

	err := h.service.Register(r.Context(), input)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrEmailTaken):
			writeJSON(w, http.StatusConflict, errorResponse("email already taken"))
		case errors.Is(err, validate.ErrEmailInvalid),
			errors.Is(err, validate.ErrPasswordTooShort),
			errors.Is(err, validate.ErrPasswordTooLong):
			writeJSON(w, http.StatusBadRequest, errorResponse(err.Error()))
		default:
			h.log.Error("register failed", "err", err)
			writeJSON(w, http.StatusInternalServerError, errorResponse("internal server error"))
		}
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"message": "user registered successfully"})
}

// Login обрабатывает POST /auth/login.
// Проверяет учётные данные и возвращает пару токенов.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var input domain.LoginInput
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse("invalid request body"))
		return
	}

	pair, err := h.service.Login(r.Context(), input)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidCredentials):
			writeJSON(w, http.StatusUnauthorized, errorResponse("invalid email or password"))
		default:
			h.log.Error("login failed", "err", err)
			writeJSON(w, http.StatusInternalServerError, errorResponse("internal server error"))
		}
		return
	}

	writeJSON(w, http.StatusOK, pair)
}

// Refresh обрабатывает POST /auth/refresh.
// Принимает действующий refresh-токен и возвращает новую пару токенов.
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var input domain.RefreshInput
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse("invalid request body"))
		return
	}

	pair, err := h.service.Refresh(r.Context(), input)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrTokenNotFound),
			errors.Is(err, service.ErrTokenExpired),
			errors.Is(err, service.ErrTokenRevoked):
			writeJSON(w, http.StatusUnauthorized, errorResponse(err.Error()))
		default:
			h.log.Error("refresh failed", "err", err)
			writeJSON(w, http.StatusInternalServerError, errorResponse("internal server error"))
		}
		return
	}

	writeJSON(w, http.StatusOK, pair)
}

// Logout обрабатывает POST /auth/logout.
// Отзывает refresh-токен. Возвращает 204 без тела ответа.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var input domain.RefreshInput
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse("invalid request body"))
		return
	}

	err := h.service.Logout(r.Context(), input.RefreshToken)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrTokenNotFound):
			writeJSON(w, http.StatusUnauthorized, errorResponse("token not found"))
		default:
			h.log.Error("logout failed", "err", err)
			writeJSON(w, http.StatusInternalServerError, errorResponse("internal server error"))
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Me обрабатывает GET /auth/me.
// Защищён middleware.Auth — userID и email уже лежат в контексте из JWT.
// Запроса к БД не делает: вся нужная информация есть в токене.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID, _ := middleware.UserIDFromContext(r.Context())
	email, _ := middleware.UserEmailFromContext(r.Context())

	writeJSON(w, http.StatusOK, map[string]any{
		"id":    userID,
		"email": email,
	})
}

// decodeJSON читает тело запроса и десериализует JSON в dst.
// Возвращает ошибку если тело пустое, невалидный JSON или не соответствует структуре.
func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

// writeJSON сериализует body в JSON и пишет ответ с указанным HTTP-статусом.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// errorResponse формирует стандартное тело ошибки: {"error": "..."}.
// Единый формат ошибок упрощает обработку на стороне клиента.
func errorResponse(message string) map[string]string {
	return map[string]string{"error": message}
}
