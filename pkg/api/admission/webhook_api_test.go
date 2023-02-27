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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/traefik/hub-agent-kubernetes/pkg/api"
	hubv1alpha1 "github.com/traefik/hub-agent-kubernetes/pkg/crd/api/hub/v1alpha1"
	"github.com/traefik/hub-agent-kubernetes/pkg/platform"
	admv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var testAPISpec = hubv1alpha1.APISpec{
	PathPrefix: "prefix",
	Service: hubv1alpha1.APIService{
		Name: "svc",
		Port: hubv1alpha1.APIServiceBackendPort{Number: 80},
	},
}

func TestHandlerAPI_ServeHTTP_createOperation(t *testing.T) {
	now := metav1.Now()

	const apiName = "my-api"

	admissionRev := admv1.AdmissionReview{
		Request: &admv1.AdmissionRequest{
			UID: "id",
			Kind: metav1.GroupVersionKind{
				Group:   "hub.traefik.io",
				Version: "v1alpha1",
				Kind:    "API",
			},
			Name:      apiName,
			Operation: admv1.Create,
			Object: runtime.RawExtension{
				Raw: mustMarshal(t, hubv1alpha1.API{
					TypeMeta: metav1.TypeMeta{
						Kind:       "API",
						APIVersion: "hub.traefik.io/v1alpha1",
					},
					ObjectMeta: metav1.ObjectMeta{Name: apiName},
					Spec:       testAPISpec,
				}),
			},
		},
		Response: &admv1.AdmissionResponse{},
	}
	wantCreateReq := &platform.CreateAPIReq{
		Name:       apiName,
		Namespace:  "",
		PathPrefix: "prefix",
		Service: platform.Service{
			Name: "svc",
			Port: 80,
		},
	}

	createdAPI := &api.API{
		Name:       apiName,
		Namespace:  "",
		PathPrefix: "prefix",
		Service: hubv1alpha1.APIService{
			Name: "svc",
			Port: hubv1alpha1.APIServiceBackendPort{Number: 80},
		},
		Version:   "version-1",
		CreatedAt: time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond),
		UpdatedAt: time.Now().UTC().Truncate(time.Millisecond),
	}

	client := newPlatformClientMock(t)
	client.OnCreateAPI(wantCreateReq).TypedReturns(createdAPI, nil).Once()

	h := NewHandlerAPI(client)
	h.now = func() time.Time { return now.Time }

	b := mustMarshal(t, admissionRev)
	rec := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", bytes.NewBuffer(b))
	require.NoError(t, err)

	h.ServeHTTP(rec, req)

	var gotAr admv1.AdmissionReview
	err = json.NewDecoder(rec.Body).Decode(&gotAr)
	require.NoError(t, err)

	jsonPatch := admv1.PatchTypeJSONPatch
	wantPatchType := &jsonPatch
	wantResp := admv1.AdmissionResponse{
		UID:       "id",
		Allowed:   true,
		PatchType: wantPatchType,
		Patch: mustMarshal(t, []patch{
			{Op: "replace", Path: "/status", Value: hubv1alpha1.APIStatus{
				Version:  "version-1",
				SyncedAt: now,
				Hash:     "UjuojgUOIKhGL1FUFVsBOg==",
			}},
		}),
	}

	assert.Equal(t, &wantResp, gotAr.Response)
}

func TestHandlerAPI_ServeHTTP_createOperationConflict(t *testing.T) {
	const apiName = "my-api"

	admissionRev := admv1.AdmissionReview{
		Request: &admv1.AdmissionRequest{
			UID: "id",
			Kind: metav1.GroupVersionKind{
				Group:   "hub.traefik.io",
				Version: "v1alpha1",
				Kind:    "API",
			},
			Name:      apiName,
			Operation: admv1.Create,
			Object: runtime.RawExtension{
				Raw: mustMarshal(t, hubv1alpha1.API{
					TypeMeta: metav1.TypeMeta{
						Kind:       "API",
						APIVersion: "hub.traefik.io/v1alpha1",
					},
					ObjectMeta: metav1.ObjectMeta{Name: apiName},
					Spec:       testAPISpec,
				}),
			},
		},
		Response: &admv1.AdmissionResponse{},
	}

	client := newPlatformClientMock(t)
	client.OnCreateAPIRaw(mock.Anything).TypedReturns(nil, errors.New("BOOM")).Once()

	h := NewHandlerAPI(client)

	b := mustMarshal(t, admissionRev)
	rec := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", bytes.NewBuffer(b))
	require.NoError(t, err)

	h.ServeHTTP(rec, req)

	var gotAr admv1.AdmissionReview
	err = json.NewDecoder(rec.Body).Decode(&gotAr)
	require.NoError(t, err)

	wantResp := admv1.AdmissionResponse{
		UID:     "id",
		Allowed: false,
		Result: &metav1.Status{
			Status:  "Failure",
			Message: "create API: BOOM",
		},
	}

	assert.Equal(t, &wantResp, gotAr.Response)
}

func TestHandlerAPI_ServeHTTP_updateOperation(t *testing.T) {
	now := metav1.Now()

	const (
		apiName = "my-api"
		version = "version-3"
	)

	newAPI := hubv1alpha1.API{
		TypeMeta: metav1.TypeMeta{
			Kind:       "API",
			APIVersion: "hub.traefik.io/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{Name: apiName, Namespace: "ns"},
		Spec: hubv1alpha1.APISpec{
			PathPrefix: "newPrefix",
			Service: hubv1alpha1.APIService{
				Name: "newSvc",
				Port: hubv1alpha1.APIServiceBackendPort{Number: 80},
			},
		},
	}
	oldAPI := hubv1alpha1.API{
		TypeMeta: metav1.TypeMeta{
			Kind:       "API",
			APIVersion: "hub.traefik.io/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{Name: apiName, Namespace: "ns"},
		Spec:       testAPISpec,
		Status: hubv1alpha1.APIStatus{
			Version: version,
		},
	}
	admissionRev := admv1.AdmissionReview{
		Request: &admv1.AdmissionRequest{
			UID: "id",
			Kind: metav1.GroupVersionKind{
				Group:   "hub.traefik.io",
				Version: "v1alpha1",
				Kind:    "API",
			},
			Name:      apiName,
			Operation: admv1.Update,
			Object: runtime.RawExtension{
				Raw: mustMarshal(t, newAPI),
			},
			OldObject: runtime.RawExtension{
				Raw: mustMarshal(t, oldAPI),
			},
		},
		Response: &admv1.AdmissionResponse{},
	}
	wantUpdateReq := &platform.UpdateAPIReq{
		PathPrefix: "newPrefix",
		Service: platform.Service{
			Name: "newSvc",
			Port: 80,
		},
	}

	updatedPortal := &api.API{
		Name:      apiName,
		Namespace: "ns",
		Version:   "version-4",
		CreatedAt: time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond),
		UpdatedAt: time.Now().UTC().Truncate(time.Millisecond),
	}

	client := newPlatformClientMock(t)
	client.OnUpdateAPI("ns", apiName, version, wantUpdateReq).
		TypedReturns(updatedPortal, nil).Once()

	h := NewHandlerAPI(client)
	h.now = func() time.Time { return now.Time }

	b := mustMarshal(t, admissionRev)
	rec := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", bytes.NewBuffer(b))
	require.NoError(t, err)

	h.ServeHTTP(rec, req)

	var gotAr admv1.AdmissionReview
	err = json.NewDecoder(rec.Body).Decode(&gotAr)
	require.NoError(t, err)

	jsonPatch := admv1.PatchTypeJSONPatch
	wantPatchType := &jsonPatch
	wantResp := admv1.AdmissionResponse{
		UID:       "id",
		Allowed:   true,
		PatchType: wantPatchType,
		Patch: mustMarshal(t, []patch{
			{Op: "replace", Path: "/status", Value: hubv1alpha1.APIStatus{
				Version:  "version-4",
				SyncedAt: now,
				Hash:     "DvCfUKvDDwq/Np1hoDqMcg==",
			}},
		}),
	}

	assert.Equal(t, &wantResp, gotAr.Response)
}

func TestHandlerAPI_ServeHTTP_updateOperationConflict(t *testing.T) {
	const (
		apiName = "my-api"
		version = "version-3"
	)

	admissionRev := admv1.AdmissionReview{
		Request: &admv1.AdmissionRequest{
			UID: "id",
			Kind: metav1.GroupVersionKind{
				Group:   "hub.traefik.io",
				Version: "v1alpha1",
				Kind:    "API",
			},
			Name:      apiName,
			Operation: admv1.Update,
			Object: runtime.RawExtension{
				Raw: mustMarshal(t, hubv1alpha1.API{
					TypeMeta: metav1.TypeMeta{
						Kind:       "API",
						APIVersion: "hub.traefik.io/v1alpha1",
					},
					ObjectMeta: metav1.ObjectMeta{Name: apiName},
					Spec:       testAPISpec,
				}),
			},
			OldObject: runtime.RawExtension{
				Raw: mustMarshal(t, hubv1alpha1.APIPortal{
					TypeMeta: metav1.TypeMeta{
						Kind:       "API",
						APIVersion: "hub.traefik.io/v1alpha1",
					},
					ObjectMeta: metav1.ObjectMeta{Name: apiName},
					Spec:       testPortalSpec,
					Status: hubv1alpha1.APIPortalStatus{
						Version:  version,
						SyncedAt: metav1.NewTime(time.Now().Add(-time.Hour)),
					},
				}),
			},
		},
		Response: &admv1.AdmissionResponse{},
	}

	client := newPlatformClientMock(t)
	client.OnUpdateAPIRaw(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		TypedReturns(nil, errors.New("BOOM")).Once()

	h := NewHandlerAPI(client)

	b := mustMarshal(t, admissionRev)
	rec := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", bytes.NewBuffer(b))
	require.NoError(t, err)

	h.ServeHTTP(rec, req)

	var gotAr admv1.AdmissionReview
	err = json.NewDecoder(rec.Body).Decode(&gotAr)
	require.NoError(t, err)

	wantResp := admv1.AdmissionResponse{
		UID:     "id",
		Allowed: false,
		Result: &metav1.Status{
			Status:  "Failure",
			Message: "update API: BOOM",
		},
	}

	assert.Equal(t, &wantResp, gotAr.Response)
}

func TestHandlerAPI_ServeHTTP_deleteOperation(t *testing.T) {
	const (
		apiName = "my-api"
		version = "version-3"
	)

	admissionRev := admv1.AdmissionReview{
		Request: &admv1.AdmissionRequest{
			UID: "id",
			Kind: metav1.GroupVersionKind{
				Group:   "hub.traefik.io",
				Version: "v1alpha1",
				Kind:    "API",
			},
			Name:      apiName,
			Operation: admv1.Delete,
			OldObject: runtime.RawExtension{
				Raw: mustMarshal(t, hubv1alpha1.API{
					TypeMeta: metav1.TypeMeta{
						Kind:       "API",
						APIVersion: "hub.traefik.io/v1alpha1",
					},
					ObjectMeta: metav1.ObjectMeta{Name: apiName, Namespace: "ns"},
					Spec:       testAPISpec,
					Status: hubv1alpha1.APIStatus{
						Version:  version,
						SyncedAt: metav1.NewTime(time.Now().Add(-time.Hour)),
					},
				}),
			},
		},
		Response: &admv1.AdmissionResponse{},
	}

	client := newPlatformClientMock(t)
	client.OnDeleteAPI("ns", apiName, version).TypedReturns(nil).Once()

	h := NewHandlerAPI(client)

	b := mustMarshal(t, admissionRev)
	rec := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", bytes.NewBuffer(b))
	require.NoError(t, err)

	h.ServeHTTP(rec, req)

	var gotAr admv1.AdmissionReview
	err = json.NewDecoder(rec.Body).Decode(&gotAr)
	require.NoError(t, err)

	wantResp := admv1.AdmissionResponse{
		UID:     "id",
		Allowed: true,
	}

	assert.Equal(t, &wantResp, gotAr.Response)
}

func TestHandlerAPI_ServeHTTP_deleteOperationConflict(t *testing.T) {
	const (
		apiName = "my-api"
		version = "version-3"
	)

	admissionRev := admv1.AdmissionReview{
		Request: &admv1.AdmissionRequest{
			UID: "id",
			Kind: metav1.GroupVersionKind{
				Group:   "hub.traefik.io",
				Version: "v1alpha1",
				Kind:    "API",
			},
			Name:      apiName,
			Operation: admv1.Delete,
			OldObject: runtime.RawExtension{
				Raw: mustMarshal(t, hubv1alpha1.API{
					TypeMeta: metav1.TypeMeta{
						Kind:       "API",
						APIVersion: "hub.traefik.io/v1alpha1",
					},
					ObjectMeta: metav1.ObjectMeta{Name: apiName},
					Spec:       testAPISpec,
					Status: hubv1alpha1.APIStatus{
						Version:  version,
						SyncedAt: metav1.NewTime(time.Now().Add(-time.Hour)),
					},
				}),
			},
		},
		Response: &admv1.AdmissionResponse{},
	}

	client := newPlatformClientMock(t)
	client.OnDeleteAPIRaw(mock.Anything, mock.Anything, mock.Anything).TypedReturns(errors.New("BOOM")).Once()

	h := NewHandlerAPI(client)

	b := mustMarshal(t, admissionRev)
	rec := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", bytes.NewBuffer(b))
	require.NoError(t, err)

	h.ServeHTTP(rec, req)

	var gotAr admv1.AdmissionReview
	err = json.NewDecoder(rec.Body).Decode(&gotAr)
	require.NoError(t, err)

	wantResp := admv1.AdmissionResponse{
		UID:     "id",
		Allowed: false,
		Result: &metav1.Status{
			Status:  "Failure",
			Message: "delete API: BOOM",
		},
	}

	assert.Equal(t, &wantResp, gotAr.Response)
}

func TestHandlerAPI_ServeHTTP_notAnAPI(t *testing.T) {
	b := mustMarshal(t, admv1.AdmissionReview{
		Request: &admv1.AdmissionRequest{
			UID: "id",
			Kind: metav1.GroupVersionKind{
				Group:   "core",
				Version: "v1",
				Kind:    "Ingress",
			},
			Name:      "my-ingress",
			Namespace: "default",
			Operation: admv1.Create,
			Object: runtime.RawExtension{
				Raw: []byte("{}"),
			},
		},
		Response: &admv1.AdmissionResponse{},
	})

	h := NewHandlerAPI(nil)

	rec := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", bytes.NewBuffer(b))
	require.NoError(t, err)

	h.ServeHTTP(rec, req)

	var gotAr admv1.AdmissionReview
	err = json.NewDecoder(rec.Body).Decode(&gotAr)
	require.NoError(t, err)

	wantResp := admv1.AdmissionResponse{
		UID:     "id",
		Allowed: false,
		Result: &metav1.Status{
			Status:  "Failure",
			Message: "unsupported resource core/v1, Kind=Ingress",
		},
	}

	assert.Equal(t, &wantResp, gotAr.Response)
}

func TestHandlerAPI_ServeHTTP_unsupportedOperation(t *testing.T) {
	b := mustMarshal(t, admv1.AdmissionReview{
		Request: &admv1.AdmissionRequest{
			UID: "id",
			Kind: metav1.GroupVersionKind{
				Group:   "hub.traefik.io",
				Version: "v1alpha1",
				Kind:    "API",
			},
			Name:      "whoami",
			Namespace: "default",
			Operation: admv1.Connect,
			Object: runtime.RawExtension{
				Raw: []byte("{}"),
			},
		},
		Response: &admv1.AdmissionResponse{},
	})

	h := NewHandlerAPI(nil)

	rec := httptest.NewRecorder()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/", bytes.NewBuffer(b))
	require.NoError(t, err)

	h.ServeHTTP(rec, req)

	var gotAr admv1.AdmissionReview
	err = json.NewDecoder(rec.Body).Decode(&gotAr)
	require.NoError(t, err)

	wantResp := admv1.AdmissionResponse{
		UID:     "id",
		Allowed: false,
		Result: &metav1.Status{
			Status:  "Failure",
			Message: `unsupported operation "CONNECT"`,
		},
	}

	assert.Equal(t, &wantResp, gotAr.Response)
}
