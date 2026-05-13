package jwt_test

import (
	"strings"
	"testing"
	"time"

	"github.com/mixfon/mfauth/pkg/jwt"
)

func TestGenerateAndVerify(t *testing.T) {
	token, err := jwt.Generate(1, "test@example.com", "secret", time.Hour)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	claims, err := jwt.Verify(token, "secret")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if claims.UserID != 1 {
		t.Errorf("UserID = %d, want 1", claims.UserID)
	}
	if claims.Email != "test@example.com" {
		t.Errorf("Email = %q, want %q", claims.Email, "test@example.com")
	}
}

func TestVerify_ExpiredToken(t *testing.T) {
	token, err := jwt.Generate(1, "test@example.com", "secret", -time.Hour)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	_, err = jwt.Verify(token, "secret")
	if err != jwt.ErrExpiredToken {
		t.Errorf("err = %v, want ErrExpiredToken", err)
	}
}

func TestVerify_WrongSecret(t *testing.T) {
	token, err := jwt.Generate(1, "test@example.com", "secret", time.Hour)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	_, err = jwt.Verify(token, "wrong-secret")
	if err != jwt.ErrInvalidToken {
		t.Errorf("err = %v, want ErrInvalidToken", err)
	}
}

func TestVerify_MalformedToken(t *testing.T) {
	cases := []string{"", "abc", "a.b", "a.b.c.d"}
	for _, tc := range cases {
		_, err := jwt.Verify(tc, "secret")
		if err != jwt.ErrInvalidToken {
			t.Errorf("Verify(%q) = %v, want ErrInvalidToken", tc, err)
		}
	}
}

func TestVerify_TamperedPayload(t *testing.T) {
	token, err := jwt.Generate(1, "test@example.com", "secret", time.Hour)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	parts := strings.Split(token, ".")
	// Подменяем payload — подпись больше не совпадёт с новым содержимым.
	parts[1] = "eyJ1aWQiOjk5OX0" // {"uid":999}
	tampered := strings.Join(parts, ".")

	_, err = jwt.Verify(tampered, "secret")
	if err != jwt.ErrInvalidToken {
		t.Errorf("err = %v, want ErrInvalidToken", err)
	}
}
