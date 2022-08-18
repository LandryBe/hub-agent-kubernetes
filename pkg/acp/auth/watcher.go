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

package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/traefik/hub-agent-kubernetes/pkg/acp"
	"github.com/traefik/hub-agent-kubernetes/pkg/acp/basicauth"
	"github.com/traefik/hub-agent-kubernetes/pkg/acp/jwt"
	"github.com/traefik/hub-agent-kubernetes/pkg/acp/oidc"
	hubv1alpha1 "github.com/traefik/hub-agent-kubernetes/pkg/crd/api/hub/v1alpha1"
	corev1 "k8s.io/api/core/v1"
)

// NOTE: if we use the same watcher for all resources, then we need to restart it when new CRDs are
// created/removed like for example when Traefik is installed and IngressRoutes are added.
// Always listening to non-existing resources would cause errors.
// Also, if multiple clients of this watcher are not interested in the same resources
// add a parameter to NewWatcher to subscribe only to a subset of events.

type oidcSecret struct {
	ClientSecret   string
	SessionKey     string
	StateCookieKey string
}

// Watcher watches access control policy resources and builds configurations out of them.
type Watcher struct {
	configsMu sync.RWMutex
	configs   map[string]*acp.Config
	previous  map[string]*acp.Config

	secrets         map[string]oidcSecret
	previousSecrets map[string]oidcSecret

	refresh chan struct{}

	switcher *HTTPHandlerSwitcher
}

// NewWatcher returns a new watcher to track ACP resources. It calls the given Updater when an ACP is modified at most
// once every throttle.
func NewWatcher(switcher *HTTPHandlerSwitcher) *Watcher {
	return &Watcher{
		configs:  make(map[string]*acp.Config),
		secrets:  make(map[string]oidcSecret),
		refresh:  make(chan struct{}, 1),
		switcher: switcher,
	}
}

// Run launches listener if the watcher is dirty.
func (w *Watcher) Run(ctx context.Context) {
	for {
		select {
		case <-w.refresh:
			w.configsMu.RLock()

			if reflect.DeepEqual(w.previous, w.configs) && reflect.DeepEqual(w.secrets, w.previousSecrets) {
				w.configsMu.RUnlock()
				continue
			}

			cfgs := make(map[string]*acp.Config, len(w.configs))
			for k, v := range w.configs {
				cfgs[k] = v
			}

			w.previous = cfgs

			previousSecrets := make(map[string]oidcSecret, len(w.secrets))
			for k, v := range w.secrets {
				previousSecrets[k] = v
			}

			w.previousSecrets = previousSecrets

			w.configsMu.RUnlock()

			log.Debug().Msg("Refreshing ACP handlers")

			routes, err := buildRoutes(ctx, cfgs, w.secrets)
			if err != nil {
				log.Error().Err(err).Msg("Unable to switch ACP handlers")
				continue
			}

			w.switcher.UpdateHandler(routes)

		case <-ctx.Done():
			return
		}
	}
}

// OnAdd implements Kubernetes cache.ResourceEventHandler so it can be used as an informer event handler.
func (w *Watcher) OnAdd(obj interface{}) {
	switch v := obj.(type) {
	case *hubv1alpha1.AccessControlPolicy:
		w.configsMu.Lock()
		w.configs[v.ObjectMeta.Name] = acp.ConfigFromPolicy(v)
		w.configsMu.Unlock()

	case *corev1.Secret:
		w.configsMu.Lock()
		w.secrets[v.Namespace+"@"+v.Name] = oidcSecret{
			ClientSecret:   string(v.Data["clientSecret"]),
			SessionKey:     string(v.Data["sessionKey"]),
			StateCookieKey: string(v.Data["stateCookieKey"]),
		}
		w.configsMu.Unlock()

	default:
		log.Error().
			Str("component", "acp_watcher").
			Str("type", fmt.Sprintf("%T", obj)).
			Msg("Received add event of unknown type")
		return
	}

	select {
	case w.refresh <- struct{}{}:
	default:
	}
}

// OnUpdate implements Kubernetes cache.ResourceEventHandler so it can be used as an informer event handler.
func (w *Watcher) OnUpdate(_, newObj interface{}) {
	switch v := newObj.(type) {
	case *hubv1alpha1.AccessControlPolicy:
		w.configsMu.Lock()
		w.configs[v.ObjectMeta.Name] = acp.ConfigFromPolicy(v)
		w.configsMu.Unlock()

	case *corev1.Secret:
		w.configsMu.Lock()
		w.secrets[v.Namespace+"@"+v.Name] = oidcSecret{
			ClientSecret:   string(v.Data["clientSecret"]),
			SessionKey:     string(v.Data["sessionKey"]),
			StateCookieKey: string(v.Data["stateCookieKey"]),
		}
		w.configsMu.Unlock()

	default:
		log.Error().
			Str("component", "acp_watcher").
			Str("type", fmt.Sprintf("%T", newObj)).
			Msg("Received update event of unknown type")
		return
	}

	select {
	case w.refresh <- struct{}{}:
	default:
	}
}

// OnDelete implements Kubernetes cache.ResourceEventHandler so it can be used as an informer event handler.
func (w *Watcher) OnDelete(obj interface{}) {
	switch v := obj.(type) {
	case *hubv1alpha1.AccessControlPolicy:
		w.configsMu.Lock()
		delete(w.configs, v.ObjectMeta.Name)
		w.configsMu.Unlock()

	case *corev1.Secret:
		w.configsMu.Lock()
		delete(w.secrets, v.Namespace+"@"+v.Name)
		w.configsMu.Unlock()

	default:
		log.Error().
			Str("component", "acp_watcher").
			Str("type", fmt.Sprintf("%T", obj)).
			Msg("Received delete event of unknown type")
		return
	}

	select {
	case w.refresh <- struct{}{}:
	default:
	}
}

func buildRoutes(ctx context.Context, cfgs map[string]*acp.Config, secrets map[string]oidcSecret) (http.Handler, error) {
	mux := http.NewServeMux()

	for name, cfg := range cfgs {
		switch {
		case cfg.JWT != nil:
			jwtHandler, err := jwt.NewHandler(cfg.JWT, name)
			if err != nil {
				return nil, fmt.Errorf("create %q JWT ACP handler: %w", name, err)
			}

			path := "/" + name
			log.Debug().Str("acp_name", name).Str("path", path).Msg("Registering JWT ACP handler")
			mux.Handle(path, jwtHandler)

		case cfg.BasicAuth != nil:
			h, err := basicauth.NewHandler(cfg.BasicAuth, name)
			if err != nil {
				return nil, fmt.Errorf("create %q basic auth ACP handler: %w", name, err)
			}

			path := "/" + name
			log.Debug().Str("acp_name", name).Str("path", path).Msg("Registering basic auth ACP handler")
			mux.Handle(path, h)

		case cfg.OIDC != nil:
			if cfg.OIDC.Secret != nil {
				secret, ok := secrets[cfg.OIDC.Secret.Namespace+"@"+cfg.OIDC.Secret.Name]
				if !ok {
					log.Error().Str("acp_name", name).
						Str("secret_namespace", cfg.OIDC.Secret.Namespace).
						Str("secret_name", cfg.OIDC.Secret.Name).
						Msg("Secret is missing")
					continue
				}

				err := populateSecrets(cfg.OIDC, secret)
				if err != nil {
					log.Error().Str("acp_name", name).
						Str("secret_namespace", cfg.OIDC.Secret.Namespace).
						Str("secret_name", cfg.OIDC.Secret.Name).
						Err(err).Msg("error while populating secrets")
				}
			}

			h, err := oidc.NewHandler(ctx, cfg.OIDC, name)
			if err != nil {
				log.Error().Err(err).Msgf("create %q OIDC ACP handler", name)
				continue
			}

			path := "/" + name
			log.Debug().Str("acp_name", name).Str("path", path).Msg("Registering OIDC auth ACP handler")
			mux.Handle(path, h)

		default:
			return nil, fmt.Errorf("unknown handler type for ACP %s", name)
		}
	}

	return mux, nil
}

func populateSecrets(config *oidc.Config, secret oidcSecret) error {
	if secret.ClientSecret == "" {
		return errors.New("clientSecret is missing in secret")
	}

	if secret.SessionKey == "" {
		return errors.New("sessionKey is missing in secret")
	}

	if secret.StateCookieKey == "" {
		return errors.New("stateCookieKey is missing in secret")
	}

	config.ClientSecret = secret.ClientSecret

	if config.Session == nil {
		config.Session = &oidc.AuthSession{}
	}
	config.Session.Secret = secret.SessionKey

	if config.StateCookie == nil {
		config.StateCookie = &oidc.AuthStateCookie{}
	}
	config.StateCookie.Secret = secret.StateCookieKey

	return nil
}
