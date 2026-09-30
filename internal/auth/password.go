package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Password limits. The upper bound keeps one hash cheap to refuse.
const (
	MinPasswordLen = 12
	MaxPasswordLen = 256
)

// hashIterations is the PBKDF2-HMAC-SHA256 work factor for new hashes
// (OWASP 2023). A stored hash carries its own count, so tests may lower
// this without breaking verification.
var hashIterations = 600000

const hashPrefix = "pbkdf2-sha256"

// CheckPassword enforces the length limits.
func CheckPassword(pw string) error {
	if len(pw) < MinPasswordLen || len(pw) > MaxPasswordLen {
		return fmt.Errorf("password must be %d to %d characters", MinPasswordLen, MaxPasswordLen)
	}
	return nil
}

// HashPassword returns "pbkdf2-sha256$<iterations>$<salt>$<key>" with a
// random 16-byte salt.
func HashPassword(pw string) (string, error) {
	if err := CheckPassword(pw); err != nil {
		return "", err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, pw, salt, hashIterations, 32)
	if err != nil {
		return "", err
	}
	enc := base64.RawStdEncoding
	return fmt.Sprintf("%s$%d$%s$%s", hashPrefix, hashIterations, enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

// VerifyPassword reports whether pw matches hash. A malformed hash never
// matches.
func VerifyPassword(hash, pw string) bool {
	if len(pw) > MaxPasswordLen {
		return false
	}
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != hashPrefix {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 || iter > 10000000 {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[2])
	want, err2 := enc.DecodeString(parts[3])
	if err := errors.Join(err1, err2); err != nil || len(want) == 0 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// SetHashIterations changes the work factor for new hashes and returns a
// function that restores it. Tests use it to keep hashing fast; the
// controller never calls it.
func SetHashIterations(n int) (restore func()) {
	old := hashIterations
	hashIterations = n
	return func() { hashIterations = old }
}
