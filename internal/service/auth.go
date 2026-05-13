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

// AuthService описывает методы бизнес-логики авторизации.
// Хендлеры зависят от этого интерфейса, а не от конкретной реализации —
// это упрощает тестирование и позволяет подменить реализацию без изменения хендлеров.
type AuthService interface {
	Register(ctx context.Context, input domain.RegisterInput) error
	Login(ctx context.Context, input domain.LoginInput) (domain.TokenPair, error)
	Refresh(ctx context.Context, input domain.RefreshInput) (domain.TokenPair, error)
	Logout(ctx context.Context, refreshToken string) error
}

// authService — конкретная реализация AuthService.
// Все зависимости приходят через конструктор NewAuthService.
type authService struct {
	userRepo  repository.UserRepository
	tokenRepo repository.TokenRepository
	cfg       *config.Config
	log       *slog.Logger
}

// NewAuthService создаёт новый экземпляр сервиса авторизации.
// Принимает репозитории, конфиг и логгер — никакого глобального состояния.
func NewAuthService(
	userRepo repository.UserRepository,
	tokenRepo repository.TokenRepository,
	cfg *config.Config,
	log *slog.Logger,
) AuthService {
	return &authService{
		userRepo:  userRepo,
		tokenRepo: tokenRepo,
		cfg:       cfg,
		log:       log,
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
