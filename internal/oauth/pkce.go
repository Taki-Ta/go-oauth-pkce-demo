package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

func randomURLSafe(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func NewState() (string, error) {
	return randomURLSafe(24)
}

func NewPKCE() (verifier string, challenge string, err error) {
	verifier, err = randomURLSafe(32)
	if err != nil {
		return "", "", err
	}

	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}
