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

	// ServeMux — стандартный роутер Go. Начиная с Go 1.22 поддерживает
	// указание HTTP-метода прямо в паттерне: "POST /auth/login"
	mux := http.NewServeMux()

	// TODO: регистрация хендлеров (следующие шаги)

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
