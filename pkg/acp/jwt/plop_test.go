package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/require"
)

func Test_ExampleNewWithClaims_standardClaims(t *testing.T) {
	claims := &jwt.RegisteredClaims{
		Issuer:    "",
		Subject:   "",
		Audience:  nil,
		ExpiresAt: nil,
		NotBefore: nil,
		IssuedAt:  nil,
		ID:        "",
	}

	mySigningKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	ss, err := token.SignedString(mySigningKey)
	require.NoError(t, err)

	fmt.Printf("%v %v", ss, err)
}
