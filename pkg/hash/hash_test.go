package hash_test

import (
	"testing"

	"github.com/mixfon/mfauth/pkg/hash"
)

func TestPassword_ReturnsHash(t *testing.T) {
	h, err := hash.Password("password123")
	if err != nil {
		t.Fatalf("Password: %v", err)
	}
	if h == "" {
		t.Error("expected non-empty hash")
	}
}

func TestPassword_UniqueSalts(t *testing.T) {
	h1, _ := hash.Password("password123")
	h2, _ := hash.Password("password123")
	if h1 == h2 {
		t.Error("expected different hashes for same password (unique salts)")
	}
}

func TestCheckPassword_Correct(t *testing.T) {
	h, _ := hash.Password("password123")
	if !hash.CheckPassword("password123", h) {
		t.Error("CheckPassword = false, want true for correct password")
	}
}

func TestCheckPassword_Wrong(t *testing.T) {
	h, _ := hash.Password("password123")
	if hash.CheckPassword("wrongpassword", h) {
		t.Error("CheckPassword = true, want false for wrong password")
	}
}
