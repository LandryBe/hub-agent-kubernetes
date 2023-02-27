/*
Copyright (C) 2022-2023 Traefik Labs

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

package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/traefik/hub-agent-kubernetes/pkg/api"
	hubv1alpha1 "github.com/traefik/hub-agent-kubernetes/pkg/crd/api/hub/v1alpha1"
	"github.com/traefik/hub-agent-kubernetes/pkg/platform"
	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// HandlerAPI is an HTTP handler that can be used as a Kubernetes Mutating Admission Controller.
type HandlerAPI struct {
	platform PlatformClient

	now func() time.Time
}

// NewHandlerAPI returns a new HandlerAPI.
func NewHandlerAPI(client PlatformClient) *HandlerAPI {
	return &HandlerAPI{
		platform: client,
		now:      time.Now,
	}
}

// ServeHTTP implements http.Handler.
func (h *HandlerAPI) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// We always decode the admission request in an admv1 object regardless
	// of the request version as it is strictly identical to the admv1beta1 object.
	var ar admv1.AdmissionReview
	if err := json.NewDecoder(req.Body).Decode(&ar); err != nil {
		log.Error().Err(err).Msg("Unable to decode admission request")
		http.Error(rw, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	l := log.Logger.With().Str("uid", string(ar.Request.UID)).Logger()
	if ar.Request != nil {
		l = l.With().
			Str("resource_kind", ar.Request.Kind.String()).
			Str("resource_name", ar.Request.Name).
			Logger()
	}
	ctx := l.WithContext(req.Context())

	patches, err := h.review(ctx, ar.Request)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("Unable to handle API admission request")

		setReviewErrorResponse(&ar, err)
	} else {
		setReviewResponse(&ar, patches)
	}

	if err = json.NewEncoder(rw).Encode(ar); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("Unable to encode admission response")
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
}

// review reviews a CREATE/UPDATE/DELETE operation on an API. It makes sure the operation is not based on
// an outdated version of the resource. As the backend is the source of truth, we cannot permit that.
func (h *HandlerAPI) review(ctx context.Context, req *admv1.AdmissionRequest) ([]byte, error) {
	logger := log.Ctx(ctx)

	if !isAPIRequest(req.Kind) {
		return nil, fmt.Errorf("unsupported resource %s", req.Kind.String())
	}

	logger.Info().Msg("Reviewing API resource")
	ctx = logger.WithContext(ctx)

	// TODO: Handle DryRun flag.
	if req.DryRun != nil && *req.DryRun {
		return nil, nil
	}

	var newAPI, oldAPI *hubv1alpha1.API
	if err := parseRaw(req.Object.Raw, &newAPI); err != nil {
		return nil, fmt.Errorf("parse raw API: %w", err)
	}
	if err := parseRaw(req.OldObject.Raw, &oldAPI); err != nil {
		return nil, fmt.Errorf("parse raw API: %w", err)
	}

	// Skip the review if the APIPortal hasn't changed since the last platform sync.
	if newAPI != nil {
		apiHash, err := api.HashAPI(newAPI)
		if err != nil {
			return nil, fmt.Errorf("compute API hash: %w", err)
		}

		if newAPI.Status.Hash == apiHash {
			return nil, nil
		}
	}

	switch req.Operation {
	case admv1.Create:
		return h.reviewCreateOperation(ctx, newAPI)
	case admv1.Update:
		return h.reviewUpdateOperation(ctx, oldAPI, newAPI)
	case admv1.Delete:
		return h.reviewDeleteOperation(ctx, oldAPI)
	default:
		return nil, fmt.Errorf("unsupported operation %q", req.Operation)
	}
}

func (h *HandlerAPI) reviewCreateOperation(ctx context.Context, a *hubv1alpha1.API) ([]byte, error) {
	log.Ctx(ctx).Info().Msg("Creating API resource")

	createReq := &platform.CreateAPIReq{
		Name:       a.Name,
		Namespace:  a.Namespace,
		Labels:     a.Labels,
		PathPrefix: a.Spec.PathPrefix,
		Service: platform.Service{
			Name: a.Spec.Service.Name,
			Port: int(a.Spec.Service.Port.Number),
		},
	}

	createdAPI, err := h.platform.CreateAPI(ctx, createReq)
	if err != nil {
		return nil, fmt.Errorf("create API: %w", err)
	}

	return h.buildPatches(createdAPI)
}

func (h *HandlerAPI) reviewUpdateOperation(ctx context.Context, oldAPI, newAPI *hubv1alpha1.API) ([]byte, error) {
	log.Ctx(ctx).Info().Msg("Updating API resource")

	updateReq := &platform.UpdateAPIReq{
		Labels:     newAPI.Labels,
		PathPrefix: newAPI.Spec.PathPrefix,
		Service: platform.Service{
			Name: newAPI.Spec.Service.Name,
			Port: int(newAPI.Spec.Service.Port.Number),
		},
	}

	updateAPI, err := h.platform.UpdateAPI(ctx, oldAPI.Namespace, oldAPI.Name, oldAPI.Status.Version, updateReq)
	if err != nil {
		return nil, fmt.Errorf("update API: %w", err)
	}

	return h.buildPatches(updateAPI)
}

func (h *HandlerAPI) reviewDeleteOperation(ctx context.Context, oldAPI *hubv1alpha1.API) ([]byte, error) {
	log.Ctx(ctx).Info().Msg("Deleting API resource")

	if err := h.platform.DeleteAPI(ctx, oldAPI.Namespace, oldAPI.Name, oldAPI.Status.Version); err != nil {
		return nil, fmt.Errorf("delete API: %w", err)
	}
	return nil, nil
}

func (h *HandlerAPI) buildPatches(p *api.API) ([]byte, error) {
	res, err := p.Resource()
	if err != nil {
		return nil, fmt.Errorf("build resource: %w", err)
	}

	return json.Marshal([]patch{
		{Op: "replace", Path: "/status", Value: res.Status},
	})
}

func parseRaw(raw []byte, obj any) (err error) {
	if raw != nil {
		if err = json.Unmarshal(raw, obj); err != nil {
			return fmt.Errorf("unmarshal reviewed newObj: %w", err)
		}
	}

	return nil
}

func isAPIRequest(kind metav1.GroupVersionKind) bool {
	return kind.Kind == "API" && kind.Group == "hub.traefik.io" && kind.Version == "v1alpha1"
}
