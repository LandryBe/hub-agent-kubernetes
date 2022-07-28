/*
Copyright (C) 2022 Traefik Labs

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

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
