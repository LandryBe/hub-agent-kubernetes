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

package v1alpha1

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AccessControlPolicy defines an access control policy.
// +kubebuilder:resource:scope=Cluster
type AccessControlPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec AccessControlPolicySpec `json:"spec,omitempty"`

	// The current status of this access control policy.
	// +optional
	Status AccessControlPolicyStatus `json:"status,omitempty"`
}

// AccessControlPolicySpec configures an access control policy.
type AccessControlPolicySpec struct {
	JWT       *AccessControlPolicyJWT       `json:"jwt,omitempty"`
	BasicAuth *AccessControlPolicyBasicAuth `json:"basicAuth,omitempty"`
	OIDC      *AccessControlOIDC            `json:"oidc,omitempty"`
}

// Hash return AccessControlPolicySpec hash.
func (a AccessControlPolicySpec) Hash() (string, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return "", fmt.Errorf("encode ACP spec: %w", err)
	}

	hash := sha1.New()
	hash.Write(b)

	return base64.StdEncoding.EncodeToString(hash.Sum(nil)), nil
}

// AccessControlPolicyJWT configures a JWT access control policy.
type AccessControlPolicyJWT struct {
	SigningSecret              string            `json:"signingSecret,omitempty"`
	SigningSecretBase64Encoded bool              `json:"signingSecretBase64Encoded,omitempty"`
	PublicKey                  string            `json:"publicKey,omitempty"`
	JWKsFile                   string            `json:"jwksFile,omitempty"`
	JWKsURL                    string            `json:"jwksUrl,omitempty"`
	StripAuthorizationHeader   bool              `json:"stripAuthorizationHeader,omitempty"`
	ForwardHeaders             map[string]string `json:"forwardHeaders,omitempty"`
	TokenQueryKey              string            `json:"tokenQueryKey,omitempty"`
	Claims                     string            `json:"claims,omitempty"`
}

// AccessControlPolicyBasicAuth holds the HTTP basic authentication configuration.
type AccessControlPolicyBasicAuth struct {
	Users                    []string `json:"users,omitempty"`
	Realm                    string   `json:"realm,omitempty"`
	StripAuthorizationHeader bool     `json:"stripAuthorizationHeader,omitempty"`
	ForwardUsernameHeader    string   `json:"forwardUsernameHeader,omitempty"`
}

// AccessControlOIDC holds the OIDC authentication configuration.
type AccessControlOIDC struct {
	Issuer       string `json:"issuer,omitempty"  toml:"issuer,omitempty" yaml:"issuer,omitempty"`
	ClientID     string `json:"clientId,omitempty"  toml:"clientId,omitempty" yaml:"clientId,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"  toml:"clientSecret,omitempty" yaml:"clientSecret,omitempty"`
	RedirectURL  string `json:"redirectUrl,omitempty"  toml:"redirectUrl,omitempty" yaml:"redirectUrl,omitempty"`
	LogoutURL    string `json:"logoutUrl,omitempty" toml:"logoutUrl,omitempty" yaml:"logoutUrl,omitempty"`

	StateCookie StateCookie `json:"stateCookie" toml:"stateCookie" yaml:"stateCookie"`
	Session     Session     `json:"session" toml:"session" yaml:"session"`

	Scopes         []string          `json:"scopes,omitempty" toml:"scopes,omitempty" yaml:"scopes,omitempty"`
	ForwardHeaders map[string]string `json:"forwardHeaders,omitempty" toml:"forwardHeaders,omitempty" yaml:"forwardHeaders,omitempty"`
	Claims         string            `json:"claims,omitempty" toml:"claims,omitempty" yaml:"claims,omitempty"`
}

type StateCookie struct {
	Secret   string `json:"secret" toml:"secret" yaml:"secret"`
	SameSite string `json:"sameSite" toml:"sameSite" yaml:"sameSite"`
	Secure   bool   `json:"secure" toml:"secure" yaml:"secure"`
}

type Session struct {
	Secret   string `json:"secret" toml:"secret" yaml:"secret"`
	SameSite string `json:"sameSite" toml:"sameSite" yaml:"sameSite"`
	Secure   bool   `json:"secure" toml:"secure" yaml:"secure"`
	Refresh  bool   `json:"refresh" toml:"refresh" yaml:"refresh"`
}

// AccessControlPolicyStatus is the status of the access control policy.
type AccessControlPolicyStatus struct {
	Version  string      `json:"version,omitempty"`
	SyncedAt metav1.Time `json:"syncedAt,omitempty"`
	SpecHash string      `json:"specHash,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// AccessControlPolicyList defines a list of access control policy.
type AccessControlPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `son:"metadata,omitempty"`

	Items []AccessControlPolicy `json:"items"`
}
