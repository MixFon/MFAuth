package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/mixfon/mfauth/internal/config"
	"github.com/mixfon/mfauth/internal/domain"
	"github.com/mixfon/mfauth/internal/repository"
	"github.com/mixfon/mfauth/pkg/hash"
	"github.com/mixfon/mfauth/pkg/jwt"
	"github.com/mixfon/mfauth/pkg/validate"
)

// EmailSender описывает единственную операцию, нужную сервису для отправки писем.
// Интерфейс позволяет подменить реальный SMTP-отправитель заглушкой в тестах.
type EmailSender interface {
	SendPasswordReset(to, token string) error
}

// AuthService описывает методы бизнес-логики авторизации.
// Хендлеры зависят от этого интерфейса, а не от конкретной реализации —
// это упрощает тестирование и позволяет подменить реализацию без изменения хендлеров.
type AuthService interface {
	Register(ctx context.Context, input domain.RegisterInput) error
	Login(ctx context.Context, input domain.LoginInput) (domain.TokenPair, error)
	Refresh(ctx context.Context, input domain.RefreshInput) (domain.TokenPair, error)
	Logout(ctx context.Context, refreshToken string) error
	LogoutAll(ctx context.Context, userID int64) error
	ChangePassword(ctx context.Context, userID int64, input domain.ChangePasswordInput) error
	RequestPasswordReset(ctx context.Context, email string) error
	ConfirmPasswordReset(ctx context.Context, input domain.PasswordResetConfirmInput) error
}

// authService — конкретная реализация AuthService.
// Все зависимости приходят через конструктор NewAuthService.
type authService struct {
	userRepo       repository.UserRepository
	tokenRepo      repository.TokenRepository
	resetTokenRepo repository.ResetTokenRepository
	mailer         EmailSender
	cfg            *config.Config
	log            *slog.Logger
}

// NewAuthService создаёт новый экземпляр сервиса авторизации.
// Принимает репозитории, email-отправитель, конфиг и логгер — никакого глобального состояния.
func NewAuthService(
	userRepo repository.UserRepository,
	tokenRepo repository.TokenRepository,
	resetTokenRepo repository.ResetTokenRepository,
	mailer EmailSender,
	cfg *config.Config,
	log *slog.Logger,
) AuthService {
	return &authService{
		userRepo:       userRepo,
		tokenRepo:      tokenRepo,
		resetTokenRepo: resetTokenRepo,
		mailer:         mailer,
		cfg:            cfg,
		log:            log,
	}
}

// Register регистрирует нового пользователя.
// Порядок: валидация → проверка уникальности email → хеширование пароля → сохранение в БД.
func (s *authService) Register(ctx context.Context, input domain.RegisterInput) error {
	// Валидируем входные данные до обращения к БД.
	if err := validate.Email(input.Email); err != nil {
		return err
	}
	if err := validate.Password(input.Password); err != nil {
		return err
	}

	// Проверяем что email ещё не занят.
	// ErrNotFound означает что пользователь не существует — это нормально при регистрации.
	existing, err := s.userRepo.FindByEmail(ctx, input.Email)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return err
	}
	if existing != nil {
		return ErrEmailTaken
	}

	// Хешируем пароль перед сохранением — открытый пароль никогда не попадает в БД.
	passwordHash, err := hash.Password(input.Password)
	if err != nil {
		return err
	}

	user := &domain.User{
		Email:        input.Email,
		PasswordHash: passwordHash,
		IsActive:     true,
	}

	if err = s.userRepo.Create(ctx, user); err != nil {
		return err
	}

	s.log.Info("user registered", "email", input.Email, "user_id", user.ID)
	return nil
}

// Login проверяет учётные данные и возвращает пару токенов.
// Порядок: поиск пользователя → проверка пароля → генерация токенов → сохранение refresh-токена.
func (s *authService) Login(ctx context.Context, input domain.LoginInput) (domain.TokenPair, error) {
	user, err := s.userRepo.FindByEmail(ctx, input.Email)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return domain.TokenPair{}, err
	}
	// Не уточняем клиенту что именно неверно: email или пароль.
	// ErrNotFound (user == nil) и неверный пароль — одинаковый ответ 401.
	if user == nil || !hash.CheckPassword(input.Password, user.PasswordHash) {
		return domain.TokenPair{}, ErrInvalidCredentials
	}

	pair, err := s.generateTokenPair(ctx, user)
	if err != nil {
		return domain.TokenPair{}, err
	}

	s.log.Info("user logged in", "user_id", user.ID)
	return pair, nil
}

// Refresh выдаёт новую пару токенов в обмен на валидный refresh-токен.
// Старый токен немедленно отзывается — это и есть token rotation.
func (s *authService) Refresh(ctx context.Context, input domain.RefreshInput) (domain.TokenPair, error) {
	stored, err := s.tokenRepo.FindByToken(ctx, input.RefreshToken)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return domain.TokenPair{}, err
	}
	if stored == nil {
		return domain.TokenPair{}, ErrTokenNotFound
	}
	if stored.Revoked {
		return domain.TokenPair{}, ErrTokenRevoked
	}
	if time.Now().After(stored.ExpiresAt) {
		return domain.TokenPair{}, ErrTokenExpired
	}

	// Отзываем старый токен до выдачи нового.
	// Если что-то пойдёт не так дальше, старый токен уже не сработает — это безопаснее.
	if err = s.tokenRepo.Revoke(ctx, input.RefreshToken); err != nil {
		return domain.TokenPair{}, err
	}

	user, err := s.userRepo.FindByID(ctx, stored.UserID)
	if err != nil {
		return domain.TokenPair{}, err
	}

	pair, err := s.generateTokenPair(ctx, user)
	if err != nil {
		return domain.TokenPair{}, err
	}

	s.log.Info("tokens refreshed", "user_id", user.ID)
	return pair, nil
}

// Logout отзывает refresh-токен пользователя.
// Access-токен не трогаем — он короткоживущий и истечёт сам.
func (s *authService) Logout(ctx context.Context, refreshToken string) error {
	stored, err := s.tokenRepo.FindByToken(ctx, refreshToken)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return err
	}
	if stored == nil {
		return ErrTokenNotFound
	}

	if err = s.tokenRepo.Revoke(ctx, refreshToken); err != nil {
		return err
	}

	s.log.Info("user logged out", "user_id", stored.UserID)
	return nil
}

// LogoutAll отзывает все refresh-токены пользователя — принудительный выход со всех устройств.
// Используется когда пользователь хочет завершить все активные сессии сразу.
func (s *authService) LogoutAll(ctx context.Context, userID int64) error {
	if err := s.tokenRepo.RevokeAllForUser(ctx, userID); err != nil {
		return err
	}

	s.log.Info("user logged out from all devices", "user_id", userID)
	return nil
}

// ChangePassword проверяет текущий пароль и устанавливает новый.
// Порядок: поиск пользователя → проверка текущего пароля → валидация нового → хеширование → сохранение.
func (s *authService) ChangePassword(ctx context.Context, userID int64, input domain.ChangePasswordInput) error {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}

	// Проверяем текущий пароль — убеждаемся что запрос делает именно владелец аккаунта.
	if !hash.CheckPassword(input.CurrentPassword, user.PasswordHash) {
		return ErrInvalidCurrentPassword
	}

	if err = validate.Password(input.NewPassword); err != nil {
		return err
	}

	passwordHash, err := hash.Password(input.NewPassword)
	if err != nil {
		return err
	}

	if err = s.userRepo.UpdatePassword(ctx, userID, passwordHash); err != nil {
		return err
	}

	s.log.Info("password changed", "user_id", userID)
	return nil
}

// RequestPasswordReset генерирует токен сброса пароля и отправляет письмо на указанный email.
// Если email не зарегистрирован — возвращает nil без ошибки, чтобы не раскрывать факт регистрации.
func (s *authService) RequestPasswordReset(ctx context.Context, email string) error {
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return err
	}
	// Email не зарегистрирован — отвечаем успехом, чтобы нельзя было перебором определить
	// какие адреса существуют в системе.
	if user == nil {
		return nil
	}

	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return err
	}
	token := hex.EncodeToString(buf)

	rt := &domain.PasswordResetToken{
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	if err = s.resetTokenRepo.Save(ctx, rt); err != nil {
		return err
	}

	if err = s.mailer.SendPasswordReset(email, token); err != nil {
		s.log.Error("failed to send password reset email", "email", email, "err", err)
		return err
	}

	s.log.Info("password reset requested", "user_id", user.ID)
	return nil
}

// ConfirmPasswordReset проверяет токен и устанавливает новый пароль.
// После смены пароля все refresh-токены пользователя отзываются — принудительный выход со всех устройств.
func (s *authService) ConfirmPasswordReset(ctx context.Context, input domain.PasswordResetConfirmInput) error {
	stored, err := s.resetTokenRepo.FindByToken(ctx, input.Token)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return err
	}
	if stored == nil {
		return ErrResetTokenNotFound
	}
	if stored.Used {
		return ErrResetTokenUsed
	}
	if time.Now().After(stored.ExpiresAt) {
		return ErrResetTokenExpired
	}

	if err = validate.Password(input.NewPassword); err != nil {
		return err
	}

	passwordHash, err := hash.Password(input.NewPassword)
	if err != nil {
		return err
	}

	// Обновляем пароль. Если запрос упадёт здесь — токен остаётся валидным, пользователь может повторить.
	if err = s.userRepo.UpdatePassword(ctx, stored.UserID, passwordHash); err != nil {
		return err
	}

	// Отмечаем токен использованным — повторное применение этого же токена невозможно.
	if err = s.resetTokenRepo.MarkUsed(ctx, input.Token); err != nil {
		return err
	}

	// Отзываем все refresh-токены: если злоумышленник имел активную сессию,
	// после смены пароля он теряет доступ.
	if err = s.tokenRepo.RevokeAllForUser(ctx, stored.UserID); err != nil {
		return err
	}

	s.log.Info("password reset confirmed", "user_id", stored.UserID)
	return nil
}

// generateTokenPair создаёт новую пару токенов для пользователя и сохраняет refresh-токен в БД.
// Вынесено в отдельный метод, так как используется и в Login, и в Refresh.
func (s *authService) generateTokenPair(ctx context.Context, user *domain.User) (domain.TokenPair, error) {
	accessToken, err := jwt.Generate(user.ID, user.Email, s.cfg.JWT.AccessSecret, s.cfg.JWT.AccessTokenTTL)
	if err != nil {
		return domain.TokenPair{}, err
	}

	// Генерируем refresh-токен: 32 случайных байта из crypto/rand → hex-строка 64 символа.
	// crypto/rand использует источник случайности ОС (/dev/urandom), что гарантирует непредсказуемость.
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return domain.TokenPair{}, err
	}
	refreshToken := hex.EncodeToString(buf)

	rt := &domain.RefreshToken{
		UserID:    user.ID,
		Token:     refreshToken,
		ExpiresAt: time.Now().Add(s.cfg.JWT.RefreshTokenTTL),
	}
	if err = s.tokenRepo.Save(ctx, rt); err != nil {
		return domain.TokenPair{}, err
	}

	return domain.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
