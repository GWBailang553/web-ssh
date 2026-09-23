package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory      = 64 * 1024
	argonIterations  = 3
	argonParallelism = 2
	argonSaltLength  = 16
	argonKeyLength   = 32
)

var (
	ErrPasswordTooShort      = errors.New("password must contain at least 16 characters")
	ErrPasswordTooLong       = errors.New("password must contain at most 128 characters")
	ErrPasswordWhitespace    = errors.New("password must not start or end with whitespace")
	ErrPasswordControl       = errors.New("password must not contain control characters")
	ErrPasswordCommon        = errors.New("password is too common or easily guessed")
	ErrPasswordContainsName  = errors.New("password must not contain your username")
	ErrPasswordRepeatedChars = errors.New("password must not repeat one character four or more times")
)

// ValidatePassword applies a deliberately strict policy. No composition rule is
// used because length and blocklist checks provide better resistance against
// guessing while still allowing passphrases and password-manager output.
func ValidatePassword(password, username string) error {
	length := utf8.RuneCountInString(password)
	if length < 16 {
		return ErrPasswordTooShort
	}
	if length > 128 {
		return ErrPasswordTooLong
	}
	if strings.TrimSpace(password) != password {
		return ErrPasswordWhitespace
	}
	for _, r := range password {
		if unicode.IsControl(r) {
			return ErrPasswordControl
		}
	}

	normalized := normalize(password)
	if username != "" && strings.Contains(normalized, normalize(username)) {
		return ErrPasswordContainsName
	}
	if _, found := commonPasswords[normalized]; found {
		return ErrPasswordCommon
	}

	repeated := 1
	previous := rune(0)
	for index, r := range password {
		if index > 0 && r == previous {
			repeated++
			if repeated >= 4 {
				return ErrPasswordRepeatedChars
			}
		} else {
			repeated = 1
		}
		previous = r
	}
	return nil
}

func normalize(value string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(value) {
		switch r {
		case '0':
			r = 'o'
		case '1', '!', '|':
			r = 'i'
		case '3':
			r = 'e'
		case '4', '@':
			r = 'a'
		case '5', '$':
			r = 's'
		case '7':
			r = 't'
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLength)
	return fmt.Sprintf(
		"$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory,
		argonIterations,
		argonParallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}

	var memory uint32
	var iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false
	}
	if memory < 8*1024 || memory > 1024*1024 || iterations < 1 || iterations > 10 || parallelism < 1 || parallelism > 16 {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return false
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(expected) < 16 || len(expected) > 64 {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

var commonPasswords = func() map[string]struct{} {
	values := []string{
		"1234567890123456", "12345678901234567890", "passwordpassword",
		"password12345678", "qwertyuiop123456", "qwertyqwertyqwerty",
		"letmeinletmein", "administrator", "administrator123", "iloveyouiloveyou",
		"welcomewelcome", "changemechangeme", "correcthorsebatterystaple",
		"thisisapassword", "thisisaverysecurepassword", "abcdefghijklmnop",
		"aaaaaaaaaaaaaaaa", "1111111111111111", "0123456789012345",
		"thequickbrownfox", "monkeymonkeymonkey", "dragonpassword",
		"masterpassword", "trustno1trustno1", "baseballbaseball",
		"footballfootball", "supermanbatman", "sunshinepassword",
		"princessprincess", "starwarsstarwars", "computercomputer",
		"internetinternet", "securitysecurity", "websshwebsshwebssh",
	}
	result := make(map[string]struct{}, len(values)*2)
	for _, value := range values {
		result[normalize(value)] = struct{}{}
	}
	return result
}()
