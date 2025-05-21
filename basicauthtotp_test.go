package basicauthtotp

import (
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

func TestIsValidTOTPCodeLength(t *testing.T) {
	tests := []struct {
		length   int
		expected bool
	}{
		{6, true},
		{8, true},
		{4, false},
		{7, false},
		{9, false},
		{0, false},
	}
	for _, tt := range tests {
		if got := isValidTOTPCodeLength(tt.length); got != tt.expected {
			t.Errorf("isValidTOTPCodeLength(%d) = %v; want %v", tt.length, got, tt.expected)
		}
	}
}

func TestValidateTOTPCode(t *testing.T) {
	// Generate a TOTP secret and code for testing
	secret := "JBSWY3DPEHPK3PXP" // base32 for "Hello!"
	code6, err := totp.GenerateCodeCustom(secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("failed to generate TOTP code: %v", err)
	}
	valid, err := validateTOTPCode(code6, secret, 6)
	if err != nil || !valid {
		t.Errorf("validateTOTPCode(6 digits) failed: valid=%v err=%v", valid, err)
	}

	code8, err := totp.GenerateCodeCustom(secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsEight,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("failed to generate TOTP code: %v", err)
	}
	valid, err = validateTOTPCode(code8, secret, 8)
	if err != nil || !valid {
		t.Errorf("validateTOTPCode(8 digits) failed: valid=%v err=%v", valid, err)
	}

	// Negative test: wrong code
	valid, err = validateTOTPCode("123456", secret, 6)
	if valid || err != nil {
		t.Errorf("validateTOTPCode should fail for wrong code, got valid=%v err=%v", valid, err)
	}
}
