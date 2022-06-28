package oidc

//
//import (
//	"context"
//	"crypto/tls"
//	"encoding/base64"
//	"net/http"
//	"net/http/httptest"
//	"net/url"
//	"strings"
//	"testing"
//	"time"
//
//	gooidc "github.com/coreos/go-oidc/v3/oidc"
//	"github.com/stretchr/testify/assert"
//	"github.com/stretchr/testify/require"
//	traefiktls "github.com/traefik/traefik/v2/pkg/tls"
//	"github.com/traefik/traefikee/v2/pkg/auth"
//	traefikeetls "github.com/traefik/traefikee/v2/pkg/config/tls"
//	"github.com/traefik/traefikee/v2/pkg/ptr"
//	"golang.org/x/oauth2"
//)
//
//func TestNewMiddlewareFromSource_ValidatesConfiguration(t *testing.T) {
//	tests := []struct {
//		name    string
//		name     *auth.OIDCConfig
//		cfg     Config
//		wantErr string
//	}{
//		{
//			name: "empty Issuer",
//			name: &auth.OIDCConfig{
//				Issuer:       "",
//				ClientID:     "bar",
//				ClientSecret: "bat",
//			},
//			cfg: Config{
//				RedirectURL: "test",
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//				},
//				Session: &AuthSession{
//					Secret: "secret1234567890",
//					Expiry: ptr.ptrInt(10),
//				},
//			},
//			wantErr: "missing issuer",
//		},
//		{
//			name: "empty ClientID",
//			name: &auth.OIDCConfig{
//				Issuer:       "foo",
//				ClientID:     "",
//				ClientSecret: "bat",
//			},
//			cfg: Config{
//				RedirectURL: "test",
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//				},
//				Session: &AuthSession{
//					Secret: "secret1234567890",
//					Expiry: ptr.ptrInt(10),
//				},
//			},
//			wantErr: "missing client ID",
//		},
//		{
//			name: "empty ClientSecret",
//			name: &auth.OIDCConfig{
//				Issuer:       "foo",
//				ClientID:     "bar",
//				ClientSecret: "",
//			},
//			cfg: Config{
//				RedirectURL: "test",
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//				},
//				Session: &AuthSession{
//					Secret: "secret1234567890",
//					Expiry: ptr.ptrInt(10),
//				},
//			},
//			wantErr: "missing client secret",
//		},
//		{
//			name: "empty RedirectURL",
//			name: &auth.OIDCConfig{
//				Issuer:       "foo",
//				ClientID:     "bar",
//				ClientSecret: "bar",
//			},
//			cfg: Config{
//				RedirectURL: "",
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//				},
//				Session: &AuthSession{
//					Secret: "secret1234567890",
//					Expiry: ptr.ptrInt(10),
//				},
//			},
//			wantErr: "missing redirect URL",
//		},
//		{
//			name: "empty Session Secret",
//			name: &auth.OIDCConfig{
//				Issuer:       "foo",
//				ClientID:     "bar",
//				ClientSecret: "bat",
//			},
//			cfg: Config{
//				RedirectURL: "test",
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//				},
//				Session: &AuthSession{
//					Secret: "",
//					Expiry: ptr.ptrInt(10),
//				},
//			},
//			wantErr: "missing session secret",
//		},
//		{
//			name: "empty State Secret",
//			name: &auth.OIDCConfig{
//				Issuer:       "foo",
//				ClientID:     "bar",
//				ClientSecret: "bat",
//			},
//			cfg: Config{
//				RedirectURL: "test",
//				StateCookie: &AuthStateCookie{},
//				Session: &AuthSession{
//					Secret: "secret1234567890",
//					Expiry: ptr.ptrInt(10),
//				},
//			},
//			wantErr: "missing state secret",
//		},
//		{
//			name: "zero session expiry",
//			name: &auth.OIDCConfig{
//				Issuer:       "foo",
//				ClientID:     "bar",
//				ClientSecret: "bat",
//			},
//			cfg: Config{
//				RedirectURL: "test",
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//				},
//				Session: &AuthSession{
//					Secret: "secret1234567890",
//					Expiry: ptr.ptrInt(0),
//				},
//			},
//			wantErr: "session expiry must be a non-zero positive value",
//		},
//		{
//			name: "negative session expiry",
//			name: &auth.OIDCConfig{
//				Issuer:       "foo",
//				ClientID:     "bar",
//				ClientSecret: "bat",
//			},
//			cfg: Config{
//				RedirectURL: "test",
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//				},
//				Session: &AuthSession{
//					Secret: "secret1234567890",
//					Expiry: ptr.ptrInt(-500),
//				},
//			},
//			wantErr: "session expiry must be a non-zero positive value",
//		},
//	}
//
//	for _, test := range tests {
//		t.Run(test.name, func(t *testing.T) {
//			ApplyDefaultValues(&test.cfg)
//			_, err := NewHandler(context.Background(), nil, test.name, test.cfg, nil, "oidc")
//
//			if test.wantErr != "" {
//				assert.Error(t, err)
//				assert.Equal(t, test.wantErr, err.Error())
//				return
//			}
//
//			assert.NoError(t, err)
//		})
//	}
//}
//
//func TestNewMiddlewareFromSource_SelfSignedIssuer(t *testing.T) {
//	certPem := []byte(`-----BEGIN CERTIFICATE-----
//MIIB/DCCAaGgAwIBAgIRAK5Wtyw1YesDMV3koA8fJsswCgYIKoZIzj0EAwIwLDET
//MBEGA1UEChMKQ29udGFpbm91czEVMBMGA1UEAxMMVHJhZWZpa0VFIENBMCAXDTE5
//MTIwNDA2NTIwMloYDzIxMTkxMTEwMDY1MjAyWjAWMRQwEgYDVQQDEwtzZXJ2ZXIu
//dGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLE9Ao3QpZNz5DzEnYHxz/Ot
//3xyBNRoFndrF5FrcpyLFg/Zi4tl82abnlr+eSN4kStD8lxFU5dEq79cJljDHQzaj
//gbcwgbQwDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1Ud
//EwEB/wQCMAAwKQYDVR0OBCIEIFy7RoCVcFDDZ3gtoPfrAcsUBw3HS6hSw7RiiCGF
//Xkm+MCsGA1UdIwQkMCKAIPOHvhXw6cD5Kx9NdmEwmGCGdWCH1lI75OVP9/Qqvpdm
//MCcGA1UdEQQgMB6CC3NlcnZlci50ZXN0gglsb2NhbGhvc3SHBH8AAAEwCgYIKoZI
//zj0EAwIDSQAwRgIhAOnI/7c0cv0QakZ7c/e8ijCNH5sG/2p4JbtsEDadlNvgAiEA
//wFlfYEb6TyjHQfXIZecpdKdmuB8Jm4SZIkDrFH1SlEw=
//-----END CERTIFICATE-----`)
//
//	keyPem := []byte(`-----BEGIN EC PRIVATE KEY-----
//MHcCAQEEIEf/bAjKUPuGEon0LU66l1Hk57SnZp2kA42cioePzzsdoAoGCCqGSM49
//AwEHoUQDQgAEsT0CjdClk3PkPMSdgfHP863fHIE1GgWd2sXkWtynIsWD9mLi2XzZ
//pueWv55I3iRK0PyXEVTl0Srv1wmWMMdDNg==
//-----END EC PRIVATE KEY-----`)
//
//	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		require.Equal(t, "/.well-known/openid-configuration", r.RequestURI)
//
//		w.Header().Set("Content-Type", "application/json")
//		_, err := w.Write([]byte(`{"issuer": "https://` + r.Host + `"}`))
//		require.NoError(t, err)
//	}))
//
//	cert, err := tls.X509KeyPair(certPem, keyPem)
//	require.NoError(t, err)
//
//	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
//	srv.StartTLS()
//
//	cfg := Config{
//		RedirectURL: "test",
//		StateCookie: &AuthStateCookie{
//			Secret: "secret1234567890",
//		},
//		Session: &AuthSession{
//			Secret: "secret1234567890",
//		},
//	}
//	ApplyDefaultValues(&cfg)
//
//	name := &auth.OIDCConfig{
//		Issuer:       srv.URL,
//		ClientID:     "client-id",
//		ClientSecret: "client-secret",
//		TLS:          &traefikeetls.TLS{CABundle: traefiktls.FileOrContent(certPem)},
//	}
//
//	_, err = NewHandler(context.Background(), nil, name, cfg, &sessionManagerMock{}, "oidc")
//	require.NoError(t, err)
//}
//
//func TestMiddleware_RedirectsCorrectly(t *testing.T) {
//	tests := []struct {
//		name    string
//		request *http.Request
//		cfg     Config
//
//		wantStatus      int
//		wantRedirect    bool
//		wantRedirectURL string
//		wantParams      map[string]string
//		wantCookies     map[string]*http.Cookie
//	}{
//		{
//			name:    "redirects with absolute redirect URL",
//			request: httptest.NewRequest(http.MethodGet, "/foo", nil),
//			cfg: Config{
//				RedirectURL: "http://example.com/callback",
//				AuthParams: map[string]string{
//					"hd": "example.com",
//				},
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//					Name:   "test",
//					Path:   "/",
//					MaxAge: ptr.ptrInt(600),
//				},
//				Session: &AuthSession{},
//			},
//			wantStatus:      http.StatusFound,
//			wantRedirect:    true,
//			wantRedirectURL: "http://example.com/callback",
//			wantParams: map[string]string{
//				"hd": "example.com",
//			},
//		},
//		{
//			name:    "redirects with relative redirect URL",
//			request: httptest.NewRequest(http.MethodGet, "http://blah.meh/foo", nil),
//			cfg: Config{
//				RedirectURL: "/callback",
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//					Name:   "test",
//					Path:   "/",
//					MaxAge: ptr.ptrInt(600),
//				},
//				Session: &AuthSession{},
//			},
//			wantStatus:      http.StatusFound,
//			wantRedirect:    true,
//			wantRedirectURL: "http://blah.meh/callback",
//		},
//		{
//			name:    "redirects with relative redirect scheme",
//			request: httptest.NewRequest(http.MethodGet, "https://blah.meh/foo", nil),
//			cfg: Config{
//				RedirectURL: "example.com/callback",
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//					Name:   "test",
//					Path:   "/",
//					MaxAge: ptr.ptrInt(600),
//				},
//				Session: &AuthSession{},
//			},
//			wantStatus:      http.StatusFound,
//			wantRedirect:    true,
//			wantRedirectURL: "https://example.com/callback",
//		},
//		{
//			name:    "returns unauthorized if login is disabled",
//			request: httptest.NewRequest(http.MethodGet, "/foo", nil),
//			cfg: Config{
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//				},
//				RedirectURL:  "example.com/callback",
//				DisableLogin: true,
//			},
//			wantStatus: http.StatusUnauthorized,
//		},
//		{
//			name:    "returns unauthorized if method is PUT",
//			request: httptest.NewRequest(http.MethodPut, "/foo", nil),
//			cfg: Config{
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//				},
//			},
//			wantStatus: http.StatusUnauthorized,
//		},
//		{
//			name:    "returns unauthorized if method is POST",
//			request: httptest.NewRequest(http.MethodPost, "/foo", nil),
//			cfg: Config{
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//				},
//			},
//			wantStatus: http.StatusUnauthorized,
//		},
//		{
//			name:    "returns unauthorized if method is DELETE",
//			request: httptest.NewRequest(http.MethodDelete, "/foo", nil),
//			cfg: Config{
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//				},
//			},
//			wantStatus: http.StatusUnauthorized,
//		},
//		{
//			name:    "returns unauthorized if method is PATCH",
//			request: httptest.NewRequest(http.MethodPatch, "/foo", nil),
//			cfg: Config{
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//				},
//			},
//			wantStatus: http.StatusUnauthorized,
//		},
//		{
//			name:    "returns unauthorized if path is favicon.ico",
//			request: httptest.NewRequest(http.MethodGet, "https://foo.com/favicon.ico", nil),
//			cfg: Config{
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//				},
//			},
//			wantStatus: http.StatusUnauthorized,
//		},
//		{
//			name:    "redirects with login url",
//			request: httptest.NewRequest(http.MethodGet, "https://blah.meh/auth/login", nil),
//			cfg: Config{
//				RedirectURL: "example.com/callback",
//				LoginURL:    "/auth/login",
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//					Name:   "test",
//					Path:   "/",
//					MaxAge: ptr.ptrInt(600),
//				},
//				Session: &AuthSession{},
//			},
//			wantStatus:      http.StatusFound,
//			wantRedirect:    true,
//			wantRedirectURL: "https://example.com/callback",
//		},
//		{
//			name:    "returns unauthorized if login url set and not requested",
//			request: httptest.NewRequest(http.MethodGet, "https://blah.meh/foo", nil),
//			cfg: Config{
//				RedirectURL: "example.com/callback",
//				LoginURL:    "/auth/login",
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//					Name:   "test",
//					Path:   "/",
//					MaxAge: ptr.ptrInt(600),
//				},
//				Session: &AuthSession{},
//			},
//			wantStatus: http.StatusUnauthorized,
//		},
//		{
//			name:    "redirects with custom state cookie domain",
//			request: httptest.NewRequest(http.MethodGet, "/foo", nil),
//			cfg: Config{
//				RedirectURL: "http://example.com/callback",
//				AuthParams: map[string]string{
//					"hd": "example.com",
//				},
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//					Name:   "test",
//					Path:   "/",
//					MaxAge: ptr.ptrInt(600),
//					Domain: "example.com",
//				},
//				Session: &AuthSession{},
//			},
//			wantStatus:      http.StatusFound,
//			wantRedirect:    true,
//			wantRedirectURL: "http://example.com/callback",
//			wantParams: map[string]string{
//				"hd": "example.com",
//			},
//			wantCookies: map[string]*http.Cookie{
//				"test": {
//					Name:     "test",
//					Path:     "/",
//					MaxAge:   600,
//					Domain:   "example.com",
//					HttpOnly: true,
//					SameSite: http.SameSiteLaxMode,
//				},
//			},
//		},
//	}
//
//	for _, test := range tests {
//		t.Run(test.name, func(t *testing.T) {
//			ApplyDefaultValues(&test.cfg)
//
//			oauth := &oauth2.Config{
//				Endpoint: oauth2.Endpoint{
//					AuthURL: "http://foobar.com",
//				},
//			}
//
//			session := sessionManagerMock{
//				getFn: func(r *http.Request) (*SessionData, error) {
//					return nil, nil
//				},
//			}
//
//			var gotNextCalled bool
//
//			next := func(w http.ResponseWriter, r *http.Request) {
//				gotNextCalled = true
//			}
//
//			subject, err := NewMiddleware(
//				http.HandlerFunc(next),
//				test.cfg,
//				oauth,
//				nil,
//				session,
//				&http.Client{},
//				"test",
//				false,
//			)
//			require.NoError(t, err)
//
//			w := httptest.NewRecorder()
//			subject.ServeHTTP(w, test.request)
//
//			assert.Equal(t, test.wantStatus, w.Code)
//			assert.False(t, gotNextCalled)
//
//			if test.wantRedirect {
//				assert.NotEmpty(t, w.Header().Get("location"))
//				u, err := url.Parse(w.Header().Get("location"))
//				assert.NoError(t, err)
//				assert.Equal(t, test.wantRedirectURL, u.Query().Get("redirect_uri"))
//
//				if test.wantParams != nil {
//					for k, v := range test.wantParams {
//						assert.Equal(t, v, u.Query().Get(k))
//					}
//				}
//
//				if test.wantCookies != nil {
//					resultCookies := map[string]*http.Cookie{}
//					for _, c := range w.Result().Cookies() {
//						resultCookies[c.Name] = c
//					}
//					for name, want := range test.wantCookies {
//						assert.NotEmpty(t, resultCookies[name])
//						// Here we don't care about the calculated value
//						want.Value = resultCookies[name].Value
//						assert.Equal(t, want.String(), resultCookies[name].String())
//					}
//				}
//			}
//		})
//	}
//}
//
//func TestMiddleware_ExchangesTokenOnCallback(t *testing.T) {
//	next := func(w http.ResponseWriter, r *http.Request) {}
//	cfg := Config{
//		RedirectURL: "http://foobar.com/callback",
//		StateCookie: &AuthStateCookie{
//			Secret:   "secret1234567890",
//			Name:     "test-state",
//			Path:     "/",
//			MaxAge:   ptr.ptrInt(600),
//			HTTPOnly: ptr.ptrBool(true),
//		},
//	}
//
//	oauth2tok := &oauth2.Token{
//		AccessToken: "access-token",
//		TokenType:   "bearer",
//	}
//
//	oauth2tok = oauth2tok.WithExtra(map[string]interface{}{"id_token": jwtToken})
//
//	oauth := oauthProviderMock{
//		exchangeFn: func(string, ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
//			return oauth2tok, nil
//		},
//	}
//
//	keySet := func(jwt string) ([]byte, error) { return parseJwt(t, jwt) }
//	verifier := gooidc.NewVerifier(
//		"https://openid.c2id.com",
//		keySetMock(keySet),
//		&gooidc.Config{
//			ClientID:             "client-12345",
//			SkipExpiryCheck:      true,
//			SkipIssuerCheck:      true,
//			SupportedSigningAlgs: []string{"ES256"},
//		},
//	)
//
//	var gotSession SessionData
//	session := sessionManagerMock{
//		getFn: func(r *http.Request) (*SessionData, error) {
//			return nil, nil
//		},
//		createFn: func(_ http.ResponseWriter, s SessionData) error {
//			gotSession = s
//			return nil
//		},
//	}
//
//	subject, err := NewMiddleware(
//		http.HandlerFunc(next),
//		cfg,
//		oauth,
//		verifier,
//		session,
//		&http.Client{},
//		"test",
//		false,
//	)
//	require.NoError(t, err)
//
//	state := StateData{
//		RedirectID: "aaaaa",
//		Nonce:      "n-0S6_WzA2Mj",
//		OriginURL:  "http://app.bar.com",
//	}
//
//	stateCookie, err := subject.newStateCookie(state)
//	require.NoError(t, err)
//
//	w := httptest.NewRecorder()
//
//	r := httptest.NewRequest(http.MethodGet, "http://foobar.com/callback?state=aaaaa", nil)
//	r.AddCookie(stateCookie)
//
//	subject.ServeHTTP(w, r)
//
//	assert.Equal(t, http.StatusFound, w.Code)
//	assert.Equal(t, state.OriginURL, w.Header().Get("location"))
//	assert.Equal(t, gotSession.AccessToken, oauth2tok.AccessToken)
//	assert.Equal(t, gotSession.IDToken, jwtToken)
//	assert.Equal(t, "test-state=; Path=/; Max-Age=0", w.Header().Get("Set-Cookie"))
//}
//
//func TestMiddleware_ExchangesTokenOnCallbackWithLoginURL(t *testing.T) {
//	next := func(w http.ResponseWriter, r *http.Request) {}
//	cfg := Config{
//		RedirectURL: "http://foobar.com/callback",
//		LoginURL:    "/login",
//		StateCookie: &AuthStateCookie{
//			Secret:   "secret1234567890",
//			Name:     "test-state",
//			Path:     "/",
//			MaxAge:   ptr.ptrInt(600),
//			HTTPOnly: ptr.ptrBool(true),
//		},
//	}
//
//	oauth2tok := &oauth2.Token{
//		AccessToken: "access-token",
//		TokenType:   "bearer",
//	}
//
//	oauth2tok = oauth2tok.WithExtra(map[string]interface{}{"id_token": jwtToken})
//
//	oauth := oauthProviderMock{
//		exchangeFn: func(string, ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
//			return oauth2tok, nil
//		},
//	}
//
//	keySet := func(jwt string) ([]byte, error) { return parseJwt(t, jwt) }
//	verifier := gooidc.NewVerifier(
//		"https://openid.c2id.com",
//		keySetMock(keySet),
//		&gooidc.Config{
//			ClientID:             "client-12345",
//			SkipExpiryCheck:      true,
//			SkipIssuerCheck:      true,
//			SupportedSigningAlgs: []string{"ES256"},
//		},
//	)
//
//	var gotSession SessionData
//	session := sessionManagerMock{
//		getFn: func(r *http.Request) (*SessionData, error) {
//			return nil, nil
//		},
//		createFn: func(_ http.ResponseWriter, s SessionData) error {
//			gotSession = s
//			return nil
//		},
//	}
//
//	subject, err := NewMiddleware(
//		http.HandlerFunc(next),
//		cfg,
//		oauth,
//		verifier,
//		session,
//		&http.Client{},
//		"test",
//		false,
//	)
//	require.NoError(t, err)
//
//	state := StateData{
//		RedirectID: "aaaaa",
//		Nonce:      "n-0S6_WzA2Mj",
//		OriginURL:  "http://foobar.com/login",
//	}
//
//	stateCookie, err := subject.newStateCookie(state)
//	require.NoError(t, err)
//
//	w := httptest.NewRecorder()
//
//	r := httptest.NewRequest(http.MethodGet, "http://foobar.com/callback?state=aaaaa", nil)
//	r.AddCookie(stateCookie)
//
//	subject.ServeHTTP(w, r)
//
//	assert.Equal(t, http.StatusNoContent, w.Code)
//	assert.Equal(t, gotSession.AccessToken, oauth2tok.AccessToken)
//	assert.Equal(t, gotSession.IDToken, jwtToken)
//	assert.Equal(t, "test-state=; Path=/; Max-Age=0", w.Header().Get("Set-Cookie"))
//}
//
//func TestMiddleware_ExchangesTokenOnCallbackWithLoginURLAndRedirect(t *testing.T) {
//	next := func(w http.ResponseWriter, r *http.Request) {}
//	cfg := Config{
//		RedirectURL:          "http://foobar.com/callback",
//		LoginURL:             "/login",
//		PostLoginRedirectURL: "/example/private",
//		StateCookie: &AuthStateCookie{
//			Secret:   "secret1234567890",
//			Name:     "test-state",
//			Path:     "/",
//			MaxAge:   ptr.ptrInt(600),
//			HTTPOnly: ptr.ptrBool(true),
//		},
//	}
//
//	oauth2tok := &oauth2.Token{
//		AccessToken: "access-token",
//		TokenType:   "bearer",
//	}
//
//	oauth2tok = oauth2tok.WithExtra(map[string]interface{}{"id_token": jwtToken})
//
//	oauth := oauthProviderMock{
//		exchangeFn: func(string, ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
//			return oauth2tok, nil
//		},
//	}
//
//	keySet := func(jwt string) ([]byte, error) { return parseJwt(t, jwt) }
//	verifier := gooidc.NewVerifier(
//		"https://openid.c2id.com",
//		keySetMock(keySet),
//		&gooidc.Config{
//			ClientID:             "client-12345",
//			SkipExpiryCheck:      true,
//			SkipIssuerCheck:      true,
//			SupportedSigningAlgs: []string{"ES256"},
//		},
//	)
//
//	var gotSession SessionData
//	session := sessionManagerMock{
//		getFn: func(r *http.Request) (*SessionData, error) {
//			return nil, nil
//		},
//		createFn: func(_ http.ResponseWriter, s SessionData) error {
//			gotSession = s
//			return nil
//		},
//	}
//
//	subject, err := NewMiddleware(
//		http.HandlerFunc(next),
//		cfg,
//		oauth,
//		verifier,
//		session,
//		&http.Client{},
//		"test",
//		false,
//	)
//	require.NoError(t, err)
//
//	state := StateData{
//		RedirectID: "aaaaa",
//		Nonce:      "n-0S6_WzA2Mj",
//		OriginURL:  "http://foobar.com/login",
//	}
//
//	stateCookie, err := subject.newStateCookie(state)
//	require.NoError(t, err)
//
//	w := httptest.NewRecorder()
//
//	r := httptest.NewRequest(http.MethodGet, "http://foobar.com/callback?state=aaaaa", nil)
//	r.AddCookie(stateCookie)
//
//	subject.ServeHTTP(w, r)
//
//	assert.Equal(t, http.StatusFound, w.Code)
//	assert.Equal(t, "http://foobar.com/example/private", w.Header().Get("location"))
//	assert.Equal(t, gotSession.AccessToken, oauth2tok.AccessToken)
//	assert.Equal(t, gotSession.IDToken, jwtToken)
//	assert.Equal(t, "test-state=; Path=/; Max-Age=0", w.Header().Get("Set-Cookie"))
//}
//
//func TestMiddleware_ForwardsCorrectly(t *testing.T) {
//	tests := []struct {
//		name    string
//		cfg     Config
//		expiry  time.Time
//		idToken string
//		headers map[string]string
//
//		wantStatus              int
//		wantNextCalled          bool
//		wantUpdateSessionCalled bool
//		wantForwardedHeaders    map[string]string
//	}{
//		{
//			name: "returns bad request if the stored id token is bad",
//			cfg: Config{
//				Session: &AuthSession{
//					Secret: "secret1234567890",
//				},
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//				},
//			},
//			idToken:    "badtoken, very bad token.",
//			wantStatus: http.StatusBadRequest,
//		},
//		{
//			name: "returns forbidden if the claims are not valid",
//			cfg: Config{
//				Claims: "Equals(`group`,`dev`)",
//				Session: &AuthSession{
//					Secret:  "secret1234567890",
//					Sliding: ptr.ptrBool(false),
//				},
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//				},
//			},
//			idToken:    jwtToken,
//			wantStatus: http.StatusForbidden,
//		},
//		{
//			name: "recreates session if sliding sessions are enabled",
//			cfg: Config{
//				Claims: "Equals(`group`,`admin`)",
//				Session: &AuthSession{
//					Secret:  "secret1234567890",
//					Sliding: ptr.ptrBool(true),
//				},
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//				},
//				ForwardHeaders: map[string]string{
//					"X-App-Group": "group",
//				},
//				Username: "group",
//			},
//			idToken:                 jwtToken,
//			wantStatus:              http.StatusOK,
//			wantNextCalled:          true,
//			wantUpdateSessionCalled: true,
//			wantForwardedHeaders: map[string]string{
//				"X-App-Group":   "admin",
//				"Authorization": "Bearer test",
//			},
//		},
//		{
//			name: "refreshes token if expired",
//			cfg: Config{
//				Claims: "Equals(`group`,`admin`)",
//				Session: &AuthSession{
//					Secret:  "secret1234567890",
//					Refresh: ptr.ptrBool(true),
//				},
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//				},
//				ForwardHeaders: map[string]string{
//					"X-App-Group": "group",
//				},
//				Username: "group",
//			},
//			expiry:                  time.Now().Add(-1 * time.Minute),
//			idToken:                 jwtToken,
//			wantStatus:              http.StatusOK,
//			wantNextCalled:          true,
//			wantUpdateSessionCalled: true,
//			wantForwardedHeaders: map[string]string{
//				"X-App-Group":   "admin",
//				"Authorization": "Bearer refreshed-token",
//			},
//		},
//		{
//			name: "forwards call (and header is canonicalized)",
//			cfg: Config{
//				Claims: "Equals(`group`,`admin`)",
//				Session: &AuthSession{
//					Secret:  "secret1234567890",
//					Sliding: ptr.ptrBool(false),
//				},
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//				},
//				ForwardHeaders: map[string]string{
//					"x-App-Group": "group",
//				},
//				Username: "group",
//			},
//			idToken:        jwtToken,
//			wantStatus:     http.StatusOK,
//			wantNextCalled: true,
//			wantForwardedHeaders: map[string]string{
//				"X-App-Group":   "admin",
//				"Authorization": "Bearer test",
//			},
//		},
//		{
//			name: "overwrite forwarded headers",
//			cfg: Config{
//				Claims: "Equals(`group`,`admin`)",
//				Session: &AuthSession{
//					Secret:  "secret1234567890",
//					Sliding: ptr.ptrBool(false),
//				},
//				StateCookie: &AuthStateCookie{
//					Secret: "secret1234567890",
//				},
//				ForwardHeaders: map[string]string{
//					"x-App-Group": "group",
//				},
//				Username: "group",
//			},
//			idToken: jwtToken,
//			headers: map[string]string{
//				"x-App-Group":   "supergroup",
//				"Authorization": "Basic foo",
//			},
//			wantStatus:     http.StatusOK,
//			wantNextCalled: true,
//			wantForwardedHeaders: map[string]string{
//				"X-App-Group":   "admin",
//				"Authorization": "Bearer test",
//			},
//		},
//	}
//
//	for _, test := range tests {
//		t.Run(test.name, func(t *testing.T) {
//			ApplyDefaultValues(&test.cfg)
//
//			oauth := oauthProviderMock{
//				tokenSourceFn: func(t *oauth2.Token) oauth2.TokenSource {
//					tok := &oauth2.Token{
//						AccessToken:  "refreshed-token",
//						TokenType:    "test2",
//						RefreshToken: "test2",
//						Expiry:       time.Now(),
//					}
//					tok = tok.WithExtra(map[string]interface{}{"id_token": jwtToken})
//
//					return tokenSourceMock{token: tok}
//				},
//			}
//
//			var gotUpdateSessionCalled bool
//			session := sessionManagerMock{
//				getFn: func(r *http.Request) (*SessionData, error) {
//					expiry := test.expiry
//					if expiry.IsZero() {
//						expiry = time.Now().Add(time.Minute)
//					}
//
//					return &SessionData{
//						AccessToken: "test",
//						IDToken:     test.idToken,
//						Expiry:      expiry,
//					}, nil
//				},
//				updateFn: func(http.ResponseWriter, *http.Request, SessionData) error {
//					gotUpdateSessionCalled = true
//					return nil
//				},
//			}
//
//			keySet := func(jwt string) ([]byte, error) { return parseJwt(t, jwt) }
//			verifier := gooidc.NewVerifier(
//				"https://openid.c2id.com",
//				keySetMock(keySet),
//				&gooidc.Config{
//					ClientID:             "client-12345",
//					SkipExpiryCheck:      true,
//					SkipIssuerCheck:      true,
//					SupportedSigningAlgs: []string{"ES256"},
//				},
//			)
//
//			var gotNextCalled bool
//			next := func(w http.ResponseWriter, r *http.Request) {
//				gotNextCalled = true
//			}
//
//			subject, err := NewMiddleware(
//				http.HandlerFunc(next),
//				test.cfg,
//				oauth,
//				verifier,
//				session,
//				&http.Client{},
//				"test",
//				false,
//			)
//			require.NoError(t, err)
//
//			r := httptest.NewRequest(http.MethodGet, "/foo", nil)
//			for k, v := range test.headers {
//				r.Header.Add(k, v)
//			}
//			w := httptest.NewRecorder()
//
//			logDataTable := &accesslog.LogData{
//				Core: accesslog.CoreLogData{},
//			}
//			reqAccessLog := r.WithContext(context.WithValue(r.Context(), accesslog.DataTableKey, logDataTable))
//
//			subject.ServeHTTP(w, reqAccessLog)
//
//			assert.Equal(t, test.wantStatus, w.Code)
//			assert.Equal(t, test.wantNextCalled, gotNextCalled)
//			assert.Equal(t, test.wantUpdateSessionCalled, gotUpdateSessionCalled)
//			for hdrName, hdrValue := range test.wantForwardedHeaders {
//				assert.Equal(t, hdrValue, r.Header.Get(hdrName))
//			}
//			if w.Code == http.StatusOK {
//				assert.Equal(t, "admin", logDataTable.Core[accesslog.ClientUsername])
//			}
//		})
//	}
//}
//
//func TestMiddleware_LogsOutCorrectly(t *testing.T) {
//	tests := []struct {
//		name string
//
//		logoutURL string
//	}{
//		{
//			name: "logout URL is a path",
//
//			logoutURL: "/logout",
//		},
//		{
//			name: "logout URL is a host and path",
//
//			logoutURL: "example.com/logout",
//		},
//	}
//
//	for _, test := range tests {
//		t.Run(test.name, func(t *testing.T) {
//			var deleteCount int
//			session := sessionManagerMock{
//				deleteFn: func(_ http.ResponseWriter, _ *http.Request) error {
//					deleteCount++
//					return nil
//				},
//			}
//
//			subject, err := NewMiddleware(
//				nil,
//				Config{
//					StateCookie: &AuthStateCookie{
//						Secret: "secret1234567890",
//					},
//					LogoutURL: test.logoutURL,
//				},
//				nil,
//				nil,
//				session,
//				&http.Client{},
//				"test",
//				false,
//			)
//			require.NoError(t, err)
//
//			r := httptest.NewRequest(http.MethodDelete, "https://example.com/logout", nil)
//			w := httptest.NewRecorder()
//			subject.ServeHTTP(w, r)
//
//			assert.Equal(t, http.StatusNoContent, w.Code)
//			assert.Equal(t, 1, deleteCount)
//		})
//	}
//}
//
//func TestMiddleware_LogsOutCorrectlyWithRedirect(t *testing.T) {
//	var deleteCount int
//	session := sessionManagerMock{
//		deleteFn: func(_ http.ResponseWriter, _ *http.Request) error {
//			deleteCount++
//			return nil
//		},
//	}
//
//	subject, err := NewMiddleware(
//		nil,
//		Config{
//			StateCookie: &AuthStateCookie{
//				Secret: "secret1234567890",
//			},
//			LogoutURL:             "/logout",
//			PostLogoutRedirectURL: "/example/goodbyesweetworld",
//		},
//		nil,
//		nil,
//		session,
//		&http.Client{},
//		"test",
//		false,
//	)
//	require.NoError(t, err)
//
//	r := httptest.NewRequest(http.MethodDelete, "https://example.com/logout", nil)
//	w := httptest.NewRecorder()
//	subject.ServeHTTP(w, r)
//
//	assert.Equal(t, http.StatusFound, w.Code)
//	assert.Equal(t, "https://example.com/example/goodbyesweetworld", w.Header().Get("location"))
//	assert.Equal(t, 1, deleteCount)
//}
//
//type oauthProviderMock struct {
//	authCodeURLFn func(string, ...oauth2.AuthCodeOption) string
//	exchangeFn    func(string, ...oauth2.AuthCodeOption) (*oauth2.Token, error)
//	tokenSourceFn func(token *oauth2.Token) oauth2.TokenSource
//}
//
//func (p oauthProviderMock) AuthCodeURL(url string, opts ...oauth2.AuthCodeOption) string {
//	return p.authCodeURLFn(url, opts...)
//}
//
//func (p oauthProviderMock) Exchange(_ context.Context, code string, opts ...oauth2.AuthCodeOption) (*oauth2.Token, error) {
//	return p.exchangeFn(code, opts...)
//}
//
//func (p oauthProviderMock) TokenSource(_ context.Context, t *oauth2.Token) oauth2.TokenSource {
//	return p.tokenSourceFn(t)
//}
//
//type sessionManagerMock struct {
//	createFn func(http.ResponseWriter, SessionData) error
//	updateFn func(http.ResponseWriter, *http.Request, SessionData) error
//	deleteFn func(http.ResponseWriter, *http.Request) error
//	getFn    func(*http.Request) (*SessionData, error)
//}
//
//func (m sessionManagerMock) Create(w http.ResponseWriter, s SessionData) error {
//	return m.createFn(w, s)
//}
//
//func (m sessionManagerMock) Update(w http.ResponseWriter, r *http.Request, s SessionData) error {
//	return m.updateFn(w, r, s)
//}
//
//func (m sessionManagerMock) Delete(w http.ResponseWriter, req *http.Request) error {
//	return m.deleteFn(w, req)
//}
//
//func (m sessionManagerMock) Get(r *http.Request) (*SessionData, error) {
//	return m.getFn(r)
//}
//
//func (m sessionManagerMock) RemoveCookie(_ *http.Request) {
//	// not needed
//}
//
//type tokenSourceMock struct {
//	token *oauth2.Token
//	err   error
//}
//
//func (t tokenSourceMock) Token() (*oauth2.Token, error) {
//	return t.token, t.err
//}
//
//type keySetMock func(string) ([]byte, error)
//
//func (k keySetMock) VerifySignature(_ context.Context, jwt string) ([]byte, error) {
//	return k(jwt)
//}
//
//const jwtToken = `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsImlzcyI6Imh0dHBzOi8vb3BlbmlkLmMyaWQuY29tIiwiYXVkIjoiY2xpZW50LTEyMzQ1Iiwibm9uY2UiOiJuLTBTNl9XekEyTWoiLCJhdXRoX3RpbWUiOjEzMTEyODA5NjksImFjciI6ImMyaWQubG9hLmhpc2VjIiwiZ3JvdXAiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0.EVA0Ec03xmOfCpJGng8dvMe7OoN6LLUX84f5qL0hircxs03lmZhc2UXu3Ipb6QndtVU5AZBxZkWtvGs2Ls3RuA`
//
//func parseJwt(t *testing.T, raw string) ([]byte, error) {
//	t.Helper()
//
//	sp := strings.Split(raw, ".")
//
//	data := make([]byte, base64.RawURLEncoding.DecodedLen(len(sp[1])))
//
//	_, err := base64.RawURLEncoding.Decode(data, []byte(sp[1]))
//	require.NoError(t, err)
//
//	return data, nil
//}
