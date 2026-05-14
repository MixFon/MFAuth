package service_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/mixfon/mfauth/internal/config"
	"github.com/mixfon/mfauth/internal/domain"
	"github.com/mixfon/mfauth/internal/repository"
	"github.com/mixfon/mfauth/internal/service"
	"github.com/mixfon/mfauth/pkg/hash"
	"github.com/mixfon/mfauth/pkg/validate"
)

// testPasswordHash — bcrypt-хэш "password123", вычисляется один раз для всех тестов логина.
var testPasswordHash = func() string {
	h, err := hash.Password("password123")
	if err != nil {
		panic(err)
	}
	return h
}()

// newTestService создаёт AuthService с тестовым конфигом и тихим логгером.
// Для resetTokenRepo и mailer используются пустые заглушки — подходит для тестов Register/Login/Refresh/Logout.
func newTestService(userRepo repository.UserRepository, tokenRepo repository.TokenRepository) service.AuthService {
	return newTestServiceFull(userRepo, tokenRepo, &mockResetTokenRepo{}, &mockEmailSender{})
}

// newTestServiceFull создаёт AuthService со всеми зависимостями явно.
// Используется в тестах RequestPasswordReset и ConfirmPasswordReset.
func newTestServiceFull(
	userRepo repository.UserRepository,
	tokenRepo repository.TokenRepository,
	resetRepo repository.ResetTokenRepository,
	mailer service.EmailSender,
) service.AuthService {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			AccessSecret:    "test-access-secret",
			RefreshSecret:   "test-refresh-secret",
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 30 * 24 * time.Hour,
		},
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return service.NewAuthService(userRepo, tokenRepo, resetRepo, mailer, cfg, log)
}

// =============================================================================
// Mock репозитории
// Функциональные поля позволяют настраивать поведение в каждом тесте отдельно.
// Нулевые значения (nil) дают безопасное поведение по умолчанию.
// =============================================================================

type mockUserRepo struct {
	createFn         func(ctx context.Context, user *domain.User) error
	findByEmailFn    func(ctx context.Context, email string) (*domain.User, error)
	findByIDFn       func(ctx context.Context, id int64) (*domain.User, error)
	updatePasswordFn func(ctx context.Context, userID int64, passwordHash string) error
}

func (m *mockUserRepo) Create(ctx context.Context, user *domain.User) error {
	if m.createFn != nil {
		return m.createFn(ctx, user)
	}
	return nil
}

func (m *mockUserRepo) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	if m.findByEmailFn != nil {
		return m.findByEmailFn(ctx, email)
	}
	return nil, repository.ErrNotFound
}

func (m *mockUserRepo) FindByID(ctx context.Context, id int64) (*domain.User, error) {
	if m.findByIDFn != nil {
		return m.findByIDFn(ctx, id)
	}
	return nil, repository.ErrNotFound
}

func (m *mockUserRepo) UpdatePassword(ctx context.Context, userID int64, passwordHash string) error {
	if m.updatePasswordFn != nil {
		return m.updatePasswordFn(ctx, userID, passwordHash)
	}
	return nil
}

// mockResetTokenRepo — заглушка ResetTokenRepository для тестов.
type mockResetTokenRepo struct {
	saveFn         func(ctx context.Context, token *domain.PasswordResetToken) error
	findByTokenFn  func(ctx context.Context, token string) (*domain.PasswordResetToken, error)
	markUsedFn     func(ctx context.Context, token string) error
	deleteExpiredFn func(ctx context.Context) error
}

func (m *mockResetTokenRepo) Save(ctx context.Context, token *domain.PasswordResetToken) error {
	if m.saveFn != nil {
		return m.saveFn(ctx, token)
	}
	return nil
}

func (m *mockResetTokenRepo) FindByToken(ctx context.Context, token string) (*domain.PasswordResetToken, error) {
	if m.findByTokenFn != nil {
		return m.findByTokenFn(ctx, token)
	}
	return nil, repository.ErrNotFound
}

func (m *mockResetTokenRepo) MarkUsed(ctx context.Context, token string) error {
	if m.markUsedFn != nil {
		return m.markUsedFn(ctx, token)
	}
	return nil
}

func (m *mockResetTokenRepo) DeleteExpired(ctx context.Context) error {
	if m.deleteExpiredFn != nil {
		return m.deleteExpiredFn(ctx)
	}
	return nil
}

// mockEmailSender — заглушка EmailSender.
type mockEmailSender struct {
	sendPasswordResetFn func(to, token string) error
}

func (m *mockEmailSender) SendPasswordReset(to, token string) error {
	if m.sendPasswordResetFn != nil {
		return m.sendPasswordResetFn(to, token)
	}
	return nil
}

type mockTokenRepo struct {
	saveFn             func(ctx context.Context, token *domain.RefreshToken) error
	findByTokenFn      func(ctx context.Context, token string) (*domain.RefreshToken, error)
	revokeFn           func(ctx context.Context, token string) error
	revokeAllForUserFn func(ctx context.Context, userID int64) error
	deleteExpiredFn    func(ctx context.Context) error
}

func (m *mockTokenRepo) Save(ctx context.Context, token *domain.RefreshToken) error {
	if m.saveFn != nil {
		return m.saveFn(ctx, token)
	}
	return nil
}

func (m *mockTokenRepo) FindByToken(ctx context.Context, token string) (*domain.RefreshToken, error) {
	if m.findByTokenFn != nil {
		return m.findByTokenFn(ctx, token)
	}
	return nil, repository.ErrNotFound
}

func (m *mockTokenRepo) Revoke(ctx context.Context, token string) error {
	if m.revokeFn != nil {
		return m.revokeFn(ctx, token)
	}
	return nil
}

func (m *mockTokenRepo) RevokeAllForUser(ctx context.Context, userID int64) error {
	if m.revokeAllForUserFn != nil {
		return m.revokeAllForUserFn(ctx, userID)
	}
	return nil
}

func (m *mockTokenRepo) DeleteExpired(ctx context.Context) error {
	if m.deleteExpiredFn != nil {
		return m.deleteExpiredFn(ctx)
	}
	return nil
}

// =============================================================================
// Register
// =============================================================================

func TestRegister_Success(t *testing.T) {
	svc := newTestService(&mockUserRepo{}, &mockTokenRepo{})

	err := svc.Register(context.Background(), domain.RegisterInput{
		Email:    "test@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Errorf("Register: %v", err)
	}
}

func TestRegister_InvalidEmail(t *testing.T) {
	svc := newTestService(&mockUserRepo{}, &mockTokenRepo{})

	err := svc.Register(context.Background(), domain.RegisterInput{
		Email:    "not-an-email",
		Password: "password123",
	})
	if !errors.Is(err, validate.ErrEmailInvalid) {
		t.Errorf("err = %v, want ErrEmailInvalid", err)
	}
}

func TestRegister_PasswordTooShort(t *testing.T) {
	svc := newTestService(&mockUserRepo{}, &mockTokenRepo{})

	err := svc.Register(context.Background(), domain.RegisterInput{
		Email:    "test@example.com",
		Password: "short",
	})
	if !errors.Is(err, validate.ErrPasswordTooShort) {
		t.Errorf("err = %v, want ErrPasswordTooShort", err)
	}
}

func TestRegister_EmailTaken(t *testing.T) {
	userRepo := &mockUserRepo{
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return &domain.User{ID: 1, Email: "test@example.com"}, nil
		},
	}
	svc := newTestService(userRepo, &mockTokenRepo{})

	err := svc.Register(context.Background(), domain.RegisterInput{
		Email:    "test@example.com",
		Password: "password123",
	})
	if !errors.Is(err, service.ErrEmailTaken) {
		t.Errorf("err = %v, want ErrEmailTaken", err)
	}
}

// =============================================================================
// Login
// =============================================================================

func TestLogin_Success(t *testing.T) {
	userRepo := &mockUserRepo{
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return &domain.User{ID: 1, Email: "test@example.com", PasswordHash: testPasswordHash}, nil
		},
	}
	svc := newTestService(userRepo, &mockTokenRepo{})

	pair, err := svc.Login(context.Background(), domain.LoginInput{
		Email:    "test@example.com",
		Password: "password123",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Error("expected non-empty token pair")
	}
}

func TestLogin_UserNotFound(t *testing.T) {
	svc := newTestService(&mockUserRepo{}, &mockTokenRepo{})

	_, err := svc.Login(context.Background(), domain.LoginInput{
		Email:    "unknown@example.com",
		Password: "password123",
	})
	if !errors.Is(err, service.ErrInvalidCredentials) {
		t.Errorf("err = %v, want ErrInvalidCredentials", err)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	userRepo := &mockUserRepo{
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return &domain.User{ID: 1, Email: "test@example.com", PasswordHash: testPasswordHash}, nil
		},
	}
	svc := newTestService(userRepo, &mockTokenRepo{})

	_, err := svc.Login(context.Background(), domain.LoginInput{
		Email:    "test@example.com",
		Password: "wrongpassword",
	})
	if !errors.Is(err, service.ErrInvalidCredentials) {
		t.Errorf("err = %v, want ErrInvalidCredentials", err)
	}
}

// =============================================================================
// Refresh
// =============================================================================

func TestRefresh_Success(t *testing.T) {
	storedToken := &domain.RefreshToken{
		UserID:    1,
		Token:     "valid-refresh-token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Revoked:   false,
	}
	userRepo := &mockUserRepo{
		findByIDFn: func(_ context.Context, _ int64) (*domain.User, error) {
			return &domain.User{ID: 1, Email: "test@example.com"}, nil
		},
	}
	tokenRepo := &mockTokenRepo{
		findByTokenFn: func(_ context.Context, _ string) (*domain.RefreshToken, error) {
			return storedToken, nil
		},
	}
	svc := newTestService(userRepo, tokenRepo)

	pair, err := svc.Refresh(context.Background(), domain.RefreshInput{RefreshToken: "valid-refresh-token"})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Error("expected non-empty token pair")
	}
}

func TestRefresh_TokenNotFound(t *testing.T) {
	svc := newTestService(&mockUserRepo{}, &mockTokenRepo{})

	_, err := svc.Refresh(context.Background(), domain.RefreshInput{RefreshToken: "unknown-token"})
	if !errors.Is(err, service.ErrTokenNotFound) {
		t.Errorf("err = %v, want ErrTokenNotFound", err)
	}
}

func TestRefresh_TokenRevoked(t *testing.T) {
	tokenRepo := &mockTokenRepo{
		findByTokenFn: func(_ context.Context, _ string) (*domain.RefreshToken, error) {
			return &domain.RefreshToken{Revoked: true, ExpiresAt: time.Now().Add(time.Hour)}, nil
		},
	}
	svc := newTestService(&mockUserRepo{}, tokenRepo)

	_, err := svc.Refresh(context.Background(), domain.RefreshInput{RefreshToken: "revoked-token"})
	if !errors.Is(err, service.ErrTokenRevoked) {
		t.Errorf("err = %v, want ErrTokenRevoked", err)
	}
}

func TestRefresh_TokenExpired(t *testing.T) {
	tokenRepo := &mockTokenRepo{
		findByTokenFn: func(_ context.Context, _ string) (*domain.RefreshToken, error) {
			return &domain.RefreshToken{Revoked: false, ExpiresAt: time.Now().Add(-time.Hour)}, nil
		},
	}
	svc := newTestService(&mockUserRepo{}, tokenRepo)

	_, err := svc.Refresh(context.Background(), domain.RefreshInput{RefreshToken: "expired-token"})
	if !errors.Is(err, service.ErrTokenExpired) {
		t.Errorf("err = %v, want ErrTokenExpired", err)
	}
}

// =============================================================================
// Logout
// =============================================================================

func TestLogout_Success(t *testing.T) {
	tokenRepo := &mockTokenRepo{
		findByTokenFn: func(_ context.Context, _ string) (*domain.RefreshToken, error) {
			return &domain.RefreshToken{UserID: 1, Token: "valid-token"}, nil
		},
	}
	svc := newTestService(&mockUserRepo{}, tokenRepo)

	err := svc.Logout(context.Background(), "valid-token")
	if err != nil {
		t.Errorf("Logout: %v", err)
	}
}

func TestLogout_TokenNotFound(t *testing.T) {
	svc := newTestService(&mockUserRepo{}, &mockTokenRepo{})

	err := svc.Logout(context.Background(), "unknown-token")
	if !errors.Is(err, service.ErrTokenNotFound) {
		t.Errorf("err = %v, want ErrTokenNotFound", err)
	}
}

// =============================================================================
// RequestPasswordReset
// =============================================================================

func TestRequestPasswordReset_Success(t *testing.T) {
	userRepo := &mockUserRepo{
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return &domain.User{ID: 1, Email: "test@example.com"}, nil
		},
	}
	var sentTo, sentToken string
	mailer := &mockEmailSender{
		sendPasswordResetFn: func(to, token string) error {
			sentTo, sentToken = to, token
			return nil
		},
	}
	svc := newTestServiceFull(userRepo, &mockTokenRepo{}, &mockResetTokenRepo{}, mailer)

	err := svc.RequestPasswordReset(context.Background(), "test@example.com")
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if sentTo != "test@example.com" {
		t.Errorf("email sent to %q, want %q", sentTo, "test@example.com")
	}
	if len(sentToken) != 64 {
		t.Errorf("token length = %d, want 64 (hex of 32 bytes)", len(sentToken))
	}
}

// Если email не зарегистрирован — сервис молча возвращает nil, не раскрывая факт регистрации.
func TestRequestPasswordReset_UnknownEmail(t *testing.T) {
	svc := newTestServiceFull(&mockUserRepo{}, &mockTokenRepo{}, &mockResetTokenRepo{}, &mockEmailSender{})

	err := svc.RequestPasswordReset(context.Background(), "unknown@example.com")
	if err != nil {
		t.Errorf("expected nil for unknown email, got: %v", err)
	}
}

// =============================================================================
// ConfirmPasswordReset
// =============================================================================

func TestConfirmPasswordReset_Success(t *testing.T) {
	resetRepo := &mockResetTokenRepo{
		findByTokenFn: func(_ context.Context, _ string) (*domain.PasswordResetToken, error) {
			return &domain.PasswordResetToken{
				UserID:    1,
				Token:     "valid-reset-token",
				ExpiresAt: time.Now().Add(15 * time.Minute),
				Used:      false,
			}, nil
		},
	}
	svc := newTestServiceFull(&mockUserRepo{}, &mockTokenRepo{}, resetRepo, &mockEmailSender{})

	err := svc.ConfirmPasswordReset(context.Background(), domain.PasswordResetConfirmInput{
		Token:       "valid-reset-token",
		NewPassword: "newpassword123",
	})
	if err != nil {
		t.Fatalf("ConfirmPasswordReset: %v", err)
	}
}

func TestConfirmPasswordReset_TokenNotFound(t *testing.T) {
	svc := newTestServiceFull(&mockUserRepo{}, &mockTokenRepo{}, &mockResetTokenRepo{}, &mockEmailSender{})

	err := svc.ConfirmPasswordReset(context.Background(), domain.PasswordResetConfirmInput{
		Token: "unknown-token", NewPassword: "newpassword123",
	})
	if !errors.Is(err, service.ErrResetTokenNotFound) {
		t.Errorf("err = %v, want ErrResetTokenNotFound", err)
	}
}

func TestConfirmPasswordReset_TokenExpired(t *testing.T) {
	resetRepo := &mockResetTokenRepo{
		findByTokenFn: func(_ context.Context, _ string) (*domain.PasswordResetToken, error) {
			return &domain.PasswordResetToken{
				ExpiresAt: time.Now().Add(-time.Minute),
				Used:      false,
			}, nil
		},
	}
	svc := newTestServiceFull(&mockUserRepo{}, &mockTokenRepo{}, resetRepo, &mockEmailSender{})

	err := svc.ConfirmPasswordReset(context.Background(), domain.PasswordResetConfirmInput{
		Token: "expired-token", NewPassword: "newpassword123",
	})
	if !errors.Is(err, service.ErrResetTokenExpired) {
		t.Errorf("err = %v, want ErrResetTokenExpired", err)
	}
}

func TestConfirmPasswordReset_TokenUsed(t *testing.T) {
	resetRepo := &mockResetTokenRepo{
		findByTokenFn: func(_ context.Context, _ string) (*domain.PasswordResetToken, error) {
			return &domain.PasswordResetToken{
				ExpiresAt: time.Now().Add(15 * time.Minute),
				Used:      true,
			}, nil
		},
	}
	svc := newTestServiceFull(&mockUserRepo{}, &mockTokenRepo{}, resetRepo, &mockEmailSender{})

	err := svc.ConfirmPasswordReset(context.Background(), domain.PasswordResetConfirmInput{
		Token: "used-token", NewPassword: "newpassword123",
	})
	if !errors.Is(err, service.ErrResetTokenUsed) {
		t.Errorf("err = %v, want ErrResetTokenUsed", err)
	}
}

func TestConfirmPasswordReset_WeakPassword(t *testing.T) {
	resetRepo := &mockResetTokenRepo{
		findByTokenFn: func(_ context.Context, _ string) (*domain.PasswordResetToken, error) {
			return &domain.PasswordResetToken{
				ExpiresAt: time.Now().Add(15 * time.Minute),
				Used:      false,
			}, nil
		},
	}
	svc := newTestServiceFull(&mockUserRepo{}, &mockTokenRepo{}, resetRepo, &mockEmailSender{})

	err := svc.ConfirmPasswordReset(context.Background(), domain.PasswordResetConfirmInput{
		Token: "valid-token", NewPassword: "short",
	})
	if !errors.Is(err, validate.ErrPasswordTooShort) {
		t.Errorf("err = %v, want ErrPasswordTooShort", err)
	}
}
