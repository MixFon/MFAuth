// Пакет validate содержит функции валидации входных данных от клиента.
// Валидация выполняется на границе системы — до передачи данных в бизнес-логику,
// чтобы сервис не обрабатывал заведомо некорректные запросы.
package validate

import (
	"errors"
	"regexp"
)

// emailRe — регулярное выражение для проверки формата email адреса.
// Компилируется один раз при старте пакета (MustCompile паникует при невалидном regexp).
var emailRe = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

var (
	ErrEmailInvalid     = errors.New("invalid email format")
	ErrPasswordTooShort = errors.New("password must be at least 8 characters")
	// Верхний предел 72 символа — ограничение алгоритма bcrypt: байты сверх этого лимита игнорируются,
	// что создаёт ложное ощущение уникальности длинных паролей.
	ErrPasswordTooLong = errors.New("password must be at most 72 characters")
)

// Email проверяет, что строка соответствует формату email адреса.
// Не проверяет существование почтового ящика — только синтаксис.
func Email(email string) error {
	if !emailRe.MatchString(email) {
		return ErrEmailInvalid
	}
	return nil
}

// Password проверяет, что пароль соответствует минимальным требованиям безопасности.
// Минимум 8 символов защищает от тривиально простых паролей.
// Максимум 72 символа — ограничение bcrypt (см. ErrPasswordTooLong).
func Password(password string) error {
	switch {
	case len(password) < 8:
		return ErrPasswordTooShort
	case len(password) > 72:
		return ErrPasswordTooLong
	}
	return nil
}
