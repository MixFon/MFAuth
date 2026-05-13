package validate_test

import (
	"testing"

	"github.com/mixfon/mfauth/pkg/validate"
)

func TestEmail(t *testing.T) {
	cases := []struct {
		input   string
		wantErr error
	}{
		{"user@example.com", nil},
		{"user.name+tag@sub.domain.com", nil},
		{"", validate.ErrEmailInvalid},
		{"notanemail", validate.ErrEmailInvalid},
		{"missing@", validate.ErrEmailInvalid},
		{"@nodomain.com", validate.ErrEmailInvalid},
		{"no spaces@example.com", validate.ErrEmailInvalid},
	}

	for _, tc := range cases {
		err := validate.Email(tc.input)
		if err != tc.wantErr {
			t.Errorf("Email(%q) = %v, want %v", tc.input, err, tc.wantErr)
		}
	}
}

func TestPassword(t *testing.T) {
	cases := []struct {
		input   string
		wantErr error
	}{
		{"password1", nil},
		{"exactly8", nil},
		{string(make([]byte, 72)), nil}, // ровно 72 символа — максимум bcrypt
		{"short", validate.ErrPasswordTooShort},
		{"1234567", validate.ErrPasswordTooShort},
		{string(make([]byte, 73)), validate.ErrPasswordTooLong},
	}

	for _, tc := range cases {
		err := validate.Password(tc.input)
		if err != tc.wantErr {
			t.Errorf("Password(len=%d) = %v, want %v", len(tc.input), err, tc.wantErr)
		}
	}
}
