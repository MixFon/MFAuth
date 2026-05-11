// Пакет hash предоставляет функции для безопасного хранения паролей с использованием bcrypt.
// bcrypt — адаптивная хэш-функция: параметр cost регулирует вычислительную сложность,
// что защищает от брутфорса даже при утечке базы данных.
package hash

import "golang.org/x/crypto/bcrypt"

// cost — вычислительная сложность bcrypt (2^cost итераций).
// Значение 12 — хороший баланс между безопасностью и временем отклика (~250мс на современном CPU).
// Увеличение на 1 удваивает время вычисления.
const cost = 12

// Password хэширует открытый пароль и возвращает bcrypt-строку для хранения в БД.
// Каждый вызов генерирует уникальную соль, поэтому два одинаковых пароля
// дают разные хэши — сравнение возможно только через CheckPassword.
func Password(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), cost)
	return string(b), err
}

// CheckPassword проверяет соответствие открытого пароля сохранённому хэшу.
// Возвращает true только если пароль верный. Использует constant-time сравнение,
// что защищает от timing-атак.
func CheckPassword(plain, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}
