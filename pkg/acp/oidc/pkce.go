package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"

	"golang.org/x/oauth2"
)

// newCodeVerifier generates a new cryptographically random string to be used as a code verifier,
// as described here: https://datatracker.ietf.org/doc/html/rfc7636#section-4.1.
func newCodeVerifier(length int) (string, error) {
	if length < 43 || length > 128 {
		return "", errors.New("code verifier length must be between 43 and 128")
	}

	charSet := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
	var s strings.Builder
	for i := 0; i < length; i++ {
		r, err := rand.Int(rand.Reader, big.NewInt(int64(len(charSet))))
		if err != nil {
			return "", err
		}

		s.WriteByte(charSet[r.Int64()])
	}

	return s.String(), nil
}

// appendCodeChallengeOptions appends Oauth2 auth code options required for PKCE to the given options,
// as stated in https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
// and https://datatracker.ietf.org/doc/html/rfc7636#section-4.3.
//
// Note that we only support the "S256" challenge method, as "plain" is considered insecure.
func appendCodeChallengeOptions(opts []oauth2.AuthCodeOption, codeVerifier string) []oauth2.AuthCodeOption {
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return append(
		opts,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}
