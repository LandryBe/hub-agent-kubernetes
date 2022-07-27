package oidc

import (
	"math/rand"
	"net/http"
	"strings"
	"time"
)

func getCookie(r *http.Request, name string) ([]byte, bool) {
	c, err := r.Cookie(name)
	if err != nil {
		return nil, false
	}

	return []byte(c.Value), true
}

func deleteCookie(r *http.Request, name string) {
	cs := r.Cookies()

	res := make([]*http.Cookie, 0, len(cs))
	for _, c := range cs {
		if !strings.HasPrefix(c.Name, name) {
			res = append(res, c)
		}
	}

	r.Header.Del("Cookie")
	for _, c := range res {
		r.Header.Add("Cookie", c.String())
	}
}

func parseSameSite(raw string) http.SameSite {
	switch strings.ToLower(raw) {
	case "lax":
		return http.SameSiteLaxMode
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteDefaultMode
	}
}

type random struct {
	rand    *rand.Rand
	charset string
}

// TODO: revisit, maybe use crypto/rand?
func newRandom() random {
	return random{
		rand:    rand.New(rand.NewSource(time.Now().UnixNano())),
		charset: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
	}
}

func (r random) Bytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = r.charset[r.rand.Intn(len(r.charset))]
	}
	return b
}

func (r random) String(n int) string {
	return string(r.Bytes(n))
}
