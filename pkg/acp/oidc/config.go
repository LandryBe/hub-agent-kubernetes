package oidc

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Config holds the configuration for the OIDC middleware.
type Config struct {
	Name         string `json:"name,omitempty"  toml:"name,omitempty" yaml:"name,omitempty"`
	Issuer       string `json:"issuer,omitempty"  toml:"issuer,omitempty" yaml:"issuer,omitempty"`
	ClientID     string `json:"clientId,omitempty"  toml:"clientId,omitempty" yaml:"clientId,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"  toml:"clientSecret,omitempty" yaml:"clientSecret,omitempty"`

	RedirectURL           string            `json:"redirectUrl,omitempty"  toml:"redirectUrl,omitempty" yaml:"redirectUrl,omitempty"`
	LoginURL              string            `json:"loginUrl,omitempty"  toml:"loginUrl,omitempty" yaml:"loginUrl,omitempty"`
	LogoutURL             string            `json:"logoutUrl,omitempty"  toml:"logoutUrl,omitempty" yaml:"logoutUrl,omitempty"`
	PostLoginRedirectURL  string            `json:"postLoginRedirectUrl,omitempty"  toml:"postLoginRedirectUrl,omitempty" yaml:"postLoginRedirectUrl,omitempty"`
	PostLogoutRedirectURL string            `json:"postLogoutRedirectUrl,omitempty"  toml:"postLogoutRedirectUrl,omitempty" yaml:"postLogoutRedirectUrl,omitempty"`
	DisableLogin          bool              `json:"disableLogin,omitempty"  toml:"disableLogin,omitempty" yaml:"disableLogin,omitempty"`
	Scopes                []string          `json:"scopes,omitempty" toml:"scopes,omitempty" yaml:"scopes,omitempty"`
	AuthParams            map[string]string `json:"authParams,omitempty" toml:"authParams,omitempty" yaml:"authParams,omitempty"`
	StateCookie           *AuthStateCookie  `json:"stateCookie,omitempty" toml:"stateCookie,omitempty" yaml:"stateCookie,omitempty"`
	Session               *AuthSession      `json:"session,omitempty" toml:"session,omitempty" yaml:"session,omitempty"`

	// ForwardHeaders defines headers that should be added to the request and populated with values extracted from the ID token.
	ForwardHeaders map[string]string `json:"forwardHeaders,omitempty" toml:"forwardHeaders,omitempty" yaml:"forwardHeaders,omitempty"`
	// Claims defines an expression to perform validation on the ID token. For example:
	//     Equals(`grp`, `admin`) && Equals(`scope`, `deploy`)
	Claims string `json:"claims,omitempty" toml:"claims,omitempty" yaml:"claims,omitempty"`
}

// AuthStateCookie carries the state cookie configuration.
type AuthStateCookie struct {
	Secret   string `json:"secret,omitempty" toml:"secret,omitempty" yaml:"secret,omitempty"`
	Path     string `json:"path,omitempty" toml:"path,omitempty" yaml:"path,omitempty"`
	Domain   string `json:"domain,omitempty" toml:"domain,omitempty" yaml:"domain,omitempty"`
	MaxAge   *int   `json:"maxAge,omitempty" toml:"maxAge,omitempty" yaml:"maxAge,omitempty"`
	SameSite string `json:"sameSite,omitempty" toml:"sameSite,omitempty" yaml:"sameSite,omitempty"`
	HTTPOnly *bool  `json:"httpOnly,omitempty" toml:"httpOnly,omitempty" yaml:"httpOnly,omitempty"`
	Secure   bool   `json:"secure,omitempty" toml:"secure,omitempty" yaml:"secure,omitempty"`
}

// AuthSession carries session and session cookie configuration.
type AuthSession struct {
	Store    string `json:"store,omitempty" toml:"store,omitempty" yaml:"store,omitempty"`
	Secret   string `json:"secret,omitempty" toml:"secret,omitempty" yaml:"secret,omitempty"`
	Path     string `json:"path,omitempty" toml:"path,omitempty" yaml:"path,omitempty"`
	Domain   string `json:"domain,omitempty" toml:"domain,omitempty" yaml:"domain,omitempty"`
	Expiry   *int   `json:"expiry,omitempty" toml:"expiry,omitempty" yaml:"expiry,omitempty"`
	SameSite string `json:"sameSite,omitempty" toml:"sameSite,omitempty" yaml:"sameSite,omitempty"`
	HTTPOnly *bool  `json:"httpOnly,omitempty" toml:"httpOnly,omitempty" yaml:"httpOnly,omitempty"`
	Secure   bool   `json:"secure,omitempty" toml:"secure,omitempty" yaml:"secure,omitempty"`
	Refresh  *bool  `json:"refresh,omitempty" toml:"refresh,omitempty" yaml:"refresh,omitempty"`
	Sliding  *bool  `json:"sliding,omitempty" toml:"sliding,omitempty" yaml:"sliding,omitempty"`
}

// ApplyDefaultValues applies default values on the given dynamic configuration.
func ApplyDefaultValues(cfg *Config) {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid"}
	}

	if cfg.StateCookie == nil {
		cfg.StateCookie = &AuthStateCookie{}
	}

	if cfg.StateCookie.MaxAge == nil {
		cfg.StateCookie.MaxAge = ptrInt(600)
	}

	if cfg.StateCookie.Path == "" {
		cfg.StateCookie.Path = "/"
	}

	if cfg.StateCookie.HTTPOnly == nil {
		cfg.StateCookie.HTTPOnly = ptrBool(true)
	}

	if cfg.StateCookie.SameSite == "" {
		cfg.StateCookie.SameSite = "lax"
	}

	if cfg.Session == nil {
		cfg.Session = &AuthSession{}
	}

	if cfg.Session.Expiry == nil {
		cfg.Session.Expiry = ptrInt(86400)
	}

	if cfg.Session.Path == "" {
		cfg.Session.Path = "/"
	}

	if cfg.Session.HTTPOnly == nil {
		cfg.Session.HTTPOnly = ptrBool(true)
	}

	if cfg.Session.SameSite == "" {
		cfg.Session.SameSite = "lax"
	}

	if cfg.Session.Refresh == nil {
		cfg.Session.Refresh = ptrBool(true)
	}

	if cfg.Session.Sliding == nil {
		cfg.Session.Sliding = ptrBool(true)
	}
}

func (cfg *Config) Validate() error {
	ApplyDefaultValues(cfg)

	if cfg.Name == "" {
		return errors.New("missing name")
	}

	if cfg.Issuer == "" {
		return errors.New("missing issuer")
	}

	if cfg.ClientID == "" {
		return errors.New("missing client ID")
	}

	if cfg.ClientSecret == "" {
		return errors.New("missing client secret")
	}

	if cfg.Session.Secret == "" {
		return errors.New("missing session secret")
	}

	switch len(cfg.Session.Secret) {
	case 16, 24, 32:
		break
	default:
		return errors.New("session secret must be 16, 24 or 32 characters long")
	}

	if *cfg.Session.Expiry <= 0 {
		return errors.New("session expiry must be a non-zero positive value")
	}

	if cfg.StateCookie.Secret == "" {
		return errors.New("missing state secret")
	}
	switch len(cfg.StateCookie.Secret) {
	case 16, 24, 32:
		break
	default:
		return errors.New("state secret must be 16, 24 or 32 characters long")
	}

	if cfg.RedirectURL == "" {
		return errors.New("missing redirect URL")
	}
	return nil
}

// ptrBool returns a pointer to boolean.
func ptrBool(v bool) *bool {
	return &v
}

// ptrInt returns a pointer to int.
func ptrInt(v int) *int {
	return &v
}

// Provider returns a provider instance from given auth source.
func BuildProvider(ctx context.Context, cfg *Config) (*oidc.Provider, error) {
	// TODO handle discovery param

	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("unable to create provider: %w", err)
	}

	return provider, nil
}
