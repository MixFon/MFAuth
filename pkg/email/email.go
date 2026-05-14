// Пакет email отправляет письма через SMTP.
// Использует только стандартную библиотеку Go: net/smtp и crypto/tls.
// Поддерживает STARTTLS (порт 587) и SSL/TLS (порт 465).
package email

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
)

// Config содержит параметры SMTP-подключения.
type Config struct {
	Host   string // smtp.gmail.com, smtp.yandex.ru и т.д.
	Port   string // 587 (STARTTLS) или 465 (SSL/TLS)
	User   string // логин SMTP
	Pass   string // пароль SMTP
	From   string // адрес отправителя (может совпадать с User)
	AppURL string // базовый URL приложения для формирования ссылки в письме
}

// Sender отправляет письма через SMTP.
type Sender struct {
	cfg Config
}

// NewSender создаёт новый Sender с заданным конфигом.
func NewSender(cfg Config) *Sender {
	return &Sender{cfg: cfg}
}

// SendPasswordReset отправляет письмо с токеном сброса пароля на указанный адрес.
func (s *Sender) SendPasswordReset(to, token string) error {
	subject := "Password Reset"
	body := fmt.Sprintf(
		"You requested a password reset.\r\n\r\n"+
			"Enter this code in the app:\r\n\r\n    %s\r\n\r\n"+
			"Or open the link:\r\n    %s/reset-password?token=%s\r\n\r\n"+
			"The code expires in 15 minutes.\r\n"+
			"If you did not request a password reset, ignore this email.",
		token, s.cfg.AppURL, token,
	)

	msg := buildMessage(s.cfg.From, to, subject, body)
	addr := s.cfg.Host + ":" + s.cfg.Port

	// Порт 465 требует SSL-соединения до SMTP-handshake (SMTPS).
	// Порт 587 использует STARTTLS — обычное TCP-соединение, которое затем апгрейдится до TLS.
	if s.cfg.Port == "465" {
		return s.sendSSL(addr, to, msg)
	}

	auth := smtp.PlainAuth("", s.cfg.User, s.cfg.Pass, s.cfg.Host)
	return smtp.SendMail(addr, auth, s.cfg.From, []string{to}, msg)
}

// sendSSL устанавливает TLS-соединение с самого начала (для порта 465).
func (s *Sender) sendSSL(addr, to string, msg []byte) error {
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: s.cfg.Host})
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}

	client, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()

	auth := smtp.PlainAuth("", s.cfg.User, s.cfg.Pass, s.cfg.Host)
	if err = client.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	if err = client.Mail(s.cfg.From); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	if err = client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt to: %w", err)
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err = wc.Write(msg); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	return wc.Close()
}

// buildMessage собирает минимальное RFC 5322 сообщение в виде байтов.
func buildMessage(from, to, subject, body string) []byte {
	return []byte(
		"From: " + from + "\r\n" +
			"To: " + to + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"Content-Type: text/plain; charset=UTF-8\r\n" +
			"\r\n" +
			body,
	)
}
