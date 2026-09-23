package auth

import (
	"errors"
	"testing"
)

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		username string
		wantErr  error
	}{
		{name: "accepts passphrase", password: "quiet-orbit-cedar-42!", username: "alice"},
		{name: "rejects short", password: "short-password", username: "alice", wantErr: ErrPasswordTooShort},
		{name: "rejects common", password: "correcthorsebatterystaple", username: "alice", wantErr: ErrPasswordCommon},
		{name: "rejects username", password: "alice-uses-a-long-password", username: "Alice", wantErr: ErrPasswordContainsName},
		{name: "rejects repeated", password: "quiet-aaaa-cedar-42!", username: "alice", wantErr: ErrPasswordRepeatedChars},
		{name: "rejects leading whitespace", password: " quiet-orbit-cedar-42", username: "alice", wantErr: ErrPasswordWhitespace},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidatePassword(test.password, test.username)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("ValidatePassword() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestPasswordHashRoundTrip(t *testing.T) {
	encoded, err := HashPassword("quiet-orbit-cedar-42!")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if !VerifyPassword(encoded, "quiet-orbit-cedar-42!") {
		t.Fatal("VerifyPassword() rejected the correct password")
	}
	if VerifyPassword(encoded, "quiet-orbit-cedar-43!") {
		t.Fatal("VerifyPassword() accepted the wrong password")
	}
}
