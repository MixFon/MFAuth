// Точка входа в приложение MFAuth — сервис авторизации.
// Отвечает за инициализацию конфигурации, подключение к БД,
// запуск миграций, сборку HTTP-сервера и graceful shutdown.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mixfon/mfauth/internal/config"
	"github.com/mixfon/mfauth/internal/database"
	"github.com/mixfon/mfauth/internal/handler"
	"github.com/mixfon/mfauth/internal/middleware"
	"github.com/mixfon/mfauth/internal/repository"
	"github.com/mixfon/mfauth/internal/service"
	"github.com/mixfon/mfauth/pkg/email"
)

func main() {
	// slog — стандартный структурированный логгер Go (появился в 1.21).
	// JSON-формат удобен для сбора логов на VPS через logrotate или внешние системы (Loki, Datadog).
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Загружаем конфигурацию из переменных окружения.
	// В продакшене переменные задаются через .env файл или секреты Docker/systemd.
	cfg := config.Load()

	// Подключаемся к PostgreSQL.
	db, err := database.New(cfg.Database.DSN)
	if err != nil {
		log.Error("failed to connect to database", "err", err)
		os.Exit(1)
	}
	defer db.Close()
	log.Info("database connected")

	// Применяем SQL-миграции при каждом старте сервера.
	// Уже применённые миграции пропускаются — операция идемпотентна.
	if err = database.Migrate(db); err != nil {
		log.Error("failed to run migrations", "err", err)
		os.Exit(1)
	}
	log.Info("migrations applied")

	// Dependency injection вручную — создаём слои снизу вверх:
	// БД → репозитории → сервис → хендлеры.
	// Никакого DI-фреймворка: зависимости явные и легко прослеживаются.
	userRepo := repository.NewUserRepository(db)
	tokenRepo := repository.NewTokenRepository(db)
	resetTokenRepo := repository.NewResetTokenRepository(db)
	mailer := email.NewSender(email.Config{
		Host:   cfg.Email.SMTPHost,
		Port:   cfg.Email.SMTPPort,
		User:   cfg.Email.User,
		Pass:   cfg.Email.Pass,
		From:   cfg.Email.From,
		AppURL: cfg.Email.AppURL,
	})
	authService := service.NewAuthService(userRepo, tokenRepo, resetTokenRepo, mailer, cfg, log)
	authHandler := handler.NewAuthHandler(authService, log)

	// ServeMux — стандартный роутер Go. Начиная с Go 1.22 поддерживает
	// указание HTTP-метода прямо в паттерне: "POST /auth/login"
	mux := http.NewServeMux()

	// Публичные маршруты — не требуют токена.
	mux.HandleFunc("POST /auth/register", authHandler.Register)
	mux.HandleFunc("POST /auth/login", authHandler.Login)
	mux.HandleFunc("POST /auth/refresh", authHandler.Refresh)
	mux.HandleFunc("POST /auth/logout", authHandler.Logout)
	mux.HandleFunc("POST /auth/password/reset/request", authHandler.RequestPasswordReset)
	mux.HandleFunc("POST /auth/password/reset/confirm", authHandler.ConfirmPasswordReset)

	// Защищённый маршрут — оборачиваем в middleware.Auth.
	// middleware.Auth проверяет JWT и кладёт userID в контекст.
	// Если токен невалиден — middleware отвечает 401, до хендлера запрос не доходит.
	authMiddleware := middleware.Auth(cfg.JWT.AccessSecret)
	mux.Handle("GET /auth/me", authMiddleware(http.HandlerFunc(authHandler.Me)))
	mux.Handle("POST /auth/logout/all", authMiddleware(http.HandlerFunc(authHandler.LogoutAll)))
	mux.Handle("POST /auth/password/change", authMiddleware(http.HandlerFunc(authHandler.ChangePassword)))

	// Эндпоинт проверки работоспособности сервиса.
	// Используется балансировщиком нагрузки и системами мониторинга (uptime-проверки).
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	srv := &http.Server{
		Addr:    ":" + cfg.Server.Port,
		Handler: mux,
		// Таймауты защищают от slowloris-атак и зависших соединений.
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	// Запускаем HTTP-сервер в отдельной горутине, чтобы не блокировать
	// основной поток — он будет ожидать сигнала завершения.
	go func() {
		log.Info("server started", "port", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	// Ожидаем системный сигнал завершения: SIGINT (Ctrl+C) или SIGTERM (от Docker / systemd).
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Graceful shutdown: даём активным запросам до 10 секунд на завершение,
	// после чего принудительно закрываем сервер. Это предотвращает обрыв
	// запросов при перезапуске или обновлении сервиса на VPS.
	log.Info("shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error("forced shutdown", "err", err)
	}
	log.Info("server stopped")
}
