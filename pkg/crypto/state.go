package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
)

type stateGenerator struct {
}

func (sg stateGenerator) GenerateState(secret string) (string, error) {
	ts, err := randomHex(64)
	if err != nil {
		return "", err
	}

	hmac, err := hmacBase64(ts, secret)
	if err != nil {
		return "", err
	}

	return url.QueryEscape(strings.ReplaceAll(strings.Join([]string{hmac, ts}, "."), "+", "")), nil
}

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func hmacBase64(message string, secret string) (string, error) {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)

	if _, err := h.Write([]byte(message)); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}
