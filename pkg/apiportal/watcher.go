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

package apiportal

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/mitchellh/hashstructure/v2"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/rs/zerolog/log"
)

type Service struct {
	Name            string `json:"name"`
	Namespace       string `json:"namespace"`
	OpenApiPathPort int    `json:"openApiPathPort"`
	OpenAPIPath     string `json:"openAPIPath"`
}

type ApiPortal struct {
	Domain        string    `json:"domain"`
	CustomDomains []string  `json:"customDomains"`
	Name          string    `json:"name"`
	Services      []Service `json:"services"`
}

// ApiPortalService for the APIPortal service.
type ApiPortalService interface {
	GetAPIPortal(ctx context.Context) ([]ApiPortal, error)
}

// Watcher watches hub ACPs.
type Watcher struct {
	interval   time.Duration
	apiPortals ApiPortalService

	client http.Client

	switcher *HTTPHandlerSwitcher

	previous uint64
}

// NewWatcher returns a new Watcher.
func NewWatcher(switcher *HTTPHandlerSwitcher, client ApiPortalService) *Watcher {
	return &Watcher{
		switcher:   switcher,
		apiPortals: client,

		interval: 10 * time.Second,
	}
}

// Run runs Watcher.
func (w *Watcher) Run(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Stopping ACP watcher")
			return
		case <-t.C:
			ctxFetch, cancel := context.WithTimeout(ctx, 5*time.Second)
			apiPortals, err := w.apiPortals.GetAPIPortal(ctxFetch)
			if err != nil {
				log.Error().Err(err).Msg("Fetching ACPs")
				cancel()
				continue
			}
			cancel()

			// hash on API Portal is not good: openAPI can be update on service.
			hash, err := hashstructure.Hash(apiPortals, hashstructure.FormatV2, nil)
			if err != nil {
				log.Error().Err(err).Msg("Unable to hash")
			}

			if err == nil && w.previous == hash {
				log.Info().Msg("skip same API portal config")
				continue
			}
			w.previous = hash

			h, err := w.buildRoutes(ctx, apiPortals)
			if err != nil {
				log.Error().Err(err).Msg("unable to build routes")
				continue
			}
			w.switcher.UpdateHandler(h)
		}
	}
}

func (w *Watcher) buildRoutes(ctx context.Context, portals []ApiPortal) (http.Handler, error) {
	router := chi.NewRouter()

	for _, portal := range portals {
		handler, err := w.buildRoute(ctx, portal)
		if err != nil {
			return handler, err
		}

		path := "/" + portal.Name

		log.Info().Str("path", path).Msg("build routes")

		router.Get(path, handler)
	}

	return router, nil
}

func (w *Watcher) buildRoute(ctx context.Context, portal ApiPortal) (http.HandlerFunc, error) {
	loader := openapi3.NewLoader()
	paths := openapi3.Paths{}
	schemas := openapi3.Schemas{}

	for _, service := range portal.Services {
		u, err := url.Parse(fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", service.Name, service.Namespace, service.OpenApiPathPort))
		if err != nil {
			return nil, fmt.Errorf("parse url: %w", err)
		}

		p, err := url.Parse(service.OpenAPIPath)
		if err != nil {
			return nil, fmt.Errorf("invalid portal path: %w", err)
		}
		u.Path = p.Path
		u.RawQuery = p.RawQuery

		openAPI, err := loader.LoadFromURI(u)
		if err != nil {
			return nil, fmt.Errorf("load openAPI: %w", err)
		}

		if err := openAPI.Validate(ctx); err != nil {
			return nil, fmt.Errorf("load openAPI: %w", err)
		}

		// we only accept https
		// the url server is the API itself
		// we need to merge path
		for name, path := range openAPI.Paths {
			if _, found := paths[name]; found {
				// conflict
				return nil, fmt.Errorf("conflict for path %s", name)
			}

			paths[name] = path
		}

		for name, schema := range openAPI.Components.Schemas {
			if _, found := schemas[name]; found {
				return nil, fmt.Errorf("conflict for schema %s", name)
			}

			schemas[name] = schema
		}
		// TODO merge component
	}

	if err := paths.Validate(ctx); err != nil {
		return nil, fmt.Errorf("validate paths: %w", err)
	}

	openAPISpec := openapi3.T{
		OpenAPI: "3.0.3",
		Info: &openapi3.Info{
			Title:       "test Api Portal",
			Description: "description",
			Version:     "v0.0.1",
		},
		Paths: paths,
		Servers: openapi3.Servers{
			{
				URL:         portal.Domain,
				Description: "Generated domain",
				Variables:   nil,
			},
		},
		Components: openapi3.Components{
			Schemas: schemas,
		},
	}

	spec, err := openAPISpec.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("marshal spec: %w", err)
	}

	return func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")

		if _, err := rw.Write(spec); err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
		}
	}, nil
}
