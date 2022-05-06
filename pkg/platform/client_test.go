package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/hub-agent-kubernetes/pkg/acp"
	"github.com/traefik/hub-agent-kubernetes/pkg/acp/jwt"
	hubv1alpha1 "github.com/traefik/hub-agent-kubernetes/pkg/crd/api/hub/v1alpha1"
	"github.com/traefik/hub-agent-kubernetes/pkg/edgeingress"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const testToken = "123"

func TestClient_Link(t *testing.T) {
	tests := []struct {
		desc             string
		returnStatusCode int
		wantClusterID    string
		wantErr          assert.ErrorAssertionFunc
	}{
		{
			desc:             "cluster successfully linked",
			returnStatusCode: http.StatusOK,
			wantClusterID:    "1",
			wantErr:          assert.NoError,
		},
		{
			desc:             "failed to link cluster",
			returnStatusCode: http.StatusTeapot,
			wantErr:          assert.Error,
			wantClusterID:    "",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			var callCount int

			mux := http.NewServeMux()
			mux.HandleFunc("/link", func(rw http.ResponseWriter, req *http.Request) {
				callCount++

				if req.Method != http.MethodPost {
					http.Error(rw, fmt.Sprintf("unsupported to method: %s", req.Method), http.StatusMethodNotAllowed)
					return
				}

				if req.Header.Get("Authorization") != "Bearer "+testToken {
					http.Error(rw, "Invalid token", http.StatusUnauthorized)
					return
				}

				b, err := io.ReadAll(req.Body)
				if err != nil {
					http.Error(rw, err.Error(), http.StatusInternalServerError)
					return
				}

				if !bytes.Equal([]byte(`{"kubeId":"1"}`), b) {
					http.Error(rw, fmt.Sprintf("invalid body: %s", string(b)), http.StatusBadRequest)
					return
				}

				rw.WriteHeader(test.returnStatusCode)
				_, _ = rw.Write([]byte(`{"clusterId":"1"}`))
			})

			srv := httptest.NewServer(mux)

			t.Cleanup(srv.Close)

			c := NewClient(srv.URL, testToken)
			c.httpClient = srv.Client()

			hubClusterID, err := c.Link(context.Background(), "1")
			test.wantErr(t, err)

			require.Equal(t, 1, callCount)

			assert.Equal(t, test.wantClusterID, hubClusterID)
		})
	}
}

func TestClient_GetConfig(t *testing.T) {
	tests := []struct {
		desc             string
		returnStatusCode int
		wantConfig       Config
		wantErr          assert.ErrorAssertionFunc
	}{
		{
			desc:             "get config succeeds",
			returnStatusCode: http.StatusOK,
			wantConfig: Config{
				Topology: TopologyConfig{
					GitProxyHost: "git-proxy-host",
					GitOrgName:   "git-org-name",
					GitRepoName:  "git-repo-name",
				},
				Metrics: MetricsConfig{
					Interval: time.Minute,
					Tables:   []string{"1m", "10m"},
				},
			},
			wantErr: assert.NoError,
		},
		{
			desc:             "get config fails",
			returnStatusCode: http.StatusTeapot,
			wantConfig:       Config{},
			wantErr:          assert.Error,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			var callCount int

			mux := http.NewServeMux()
			mux.HandleFunc("/config", func(rw http.ResponseWriter, req *http.Request) {
				callCount++

				if req.Method != http.MethodGet {
					http.Error(rw, fmt.Sprintf("unsupported to method: %s", req.Method), http.StatusMethodNotAllowed)
					return
				}

				if req.Header.Get("Authorization") != "Bearer "+testToken {
					http.Error(rw, "Invalid token", http.StatusUnauthorized)
					return
				}

				rw.WriteHeader(test.returnStatusCode)
				_ = json.NewEncoder(rw).Encode(test.wantConfig)
			})

			srv := httptest.NewServer(mux)

			t.Cleanup(srv.Close)

			c := NewClient(srv.URL, testToken)
			c.httpClient = srv.Client()

			agentCfg, err := c.GetConfig(context.Background())
			test.wantErr(t, err)

			require.Equal(t, 1, callCount)

			assert.Equal(t, test.wantConfig, agentCfg)
		})
	}
}

func TestClient_Ping(t *testing.T) {
	tests := []struct {
		desc             string
		returnStatusCode int
		wantErr          assert.ErrorAssertionFunc
	}{
		{
			desc:             "ping successfully sent",
			returnStatusCode: http.StatusOK,
			wantErr:          assert.NoError,
		},
		{
			desc:             "ping sent for an unknown cluster",
			returnStatusCode: http.StatusNotFound,
			wantErr:          assert.Error,
		},
		{
			desc:             "error on ping",
			returnStatusCode: http.StatusInternalServerError,
			wantErr:          assert.Error,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			var callCount int

			mux := http.NewServeMux()
			mux.HandleFunc("/ping", func(rw http.ResponseWriter, req *http.Request) {
				callCount++

				if req.Method != http.MethodPost {
					http.Error(rw, fmt.Sprintf("unsupported to method: %s", req.Method), http.StatusMethodNotAllowed)
					return
				}

				if req.Header.Get("Authorization") != "Bearer "+testToken {
					http.Error(rw, "Invalid token", http.StatusUnauthorized)
					return
				}

				rw.WriteHeader(test.returnStatusCode)
			})

			srv := httptest.NewServer(mux)

			t.Cleanup(srv.Close)

			c := NewClient(srv.URL, testToken)
			c.httpClient = srv.Client()

			err := c.Ping(context.Background())
			test.wantErr(t, err)

			require.Equal(t, 1, callCount)
		})
	}
}

func TestClient_ListVerifiedDomains(t *testing.T) {
	tests := []struct {
		desc             string
		returnStatusCode int
		domains          []string
		wantErr          assert.ErrorAssertionFunc
		wantDomains      []string
	}{
		{
			desc:             "get domains",
			returnStatusCode: http.StatusOK,
			domains:          []string{"domain.com"},
			wantErr:          assert.NoError,
			wantDomains:      []string{"domain.com"},
		},
		{
			desc:             "unable to get domains",
			returnStatusCode: http.StatusInternalServerError,
			wantErr:          assert.Error,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			var callCount int

			mux := http.NewServeMux()
			mux.HandleFunc("/verified-domains", func(rw http.ResponseWriter, req *http.Request) {
				callCount++

				if req.Method != http.MethodGet {
					http.Error(rw, fmt.Sprintf("unsupported to method: %s", req.Method), http.StatusMethodNotAllowed)
					return
				}

				if req.Header.Get("Authorization") != "Bearer "+testToken {
					http.Error(rw, "Invalid token", http.StatusUnauthorized)
					return
				}

				rw.WriteHeader(test.returnStatusCode)
				err := json.NewEncoder(rw).Encode(test.domains)
				require.NoError(t, err)
			})

			srv := httptest.NewServer(mux)

			t.Cleanup(srv.Close)

			c := NewClient(srv.URL, testToken)
			c.httpClient = srv.Client()

			domains, err := c.ListVerifiedDomains(context.Background())
			test.wantErr(t, err)

			require.Equal(t, 1, callCount)
			assert.Equal(t, test.wantDomains, domains)
		})
	}
}

func TestClient_CreateEdgeIngress(t *testing.T) {
	tests := []struct {
		desc             string
		createReq        *CreateEdgeIngressReq
		edgeIngress      *edgeingress.EdgeIngress
		returnStatusCode int
		wantErr          assert.ErrorAssertionFunc
	}{
		{
			desc: "create edge ingress",
			createReq: &CreateEdgeIngressReq{
				Name:         "name",
				Namespace:    "namespace",
				ServiceName:  "service-name",
				ServicePort:  8080,
				ACPName:      "acp-name",
				ACPNamespace: "acp-namespace",
			},
			returnStatusCode: http.StatusCreated,
			wantErr:          assert.NoError,
			edgeIngress: &edgeingress.EdgeIngress{
				WorkspaceID:  "workspace-id",
				ClusterID:    "cluster-id",
				Namespace:    "namespace",
				Name:         "name",
				Domain:       "majestic-beaver-123.hub-traefik.io",
				Version:      "version-1",
				ServiceName:  "service-name",
				ServicePort:  8080,
				ACPName:      "acp-name",
				ACPNamespace: "acp-namespace",
				CreatedAt:    time.Now().UTC().Truncate(time.Millisecond),
				UpdatedAt:    time.Now().UTC().Truncate(time.Millisecond),
			},
		},
		{
			desc: "conflict",
			createReq: &CreateEdgeIngressReq{
				Name:         "name",
				Namespace:    "namespace",
				ServiceName:  "service-name",
				ServicePort:  8080,
				ACPName:      "acp-name",
				ACPNamespace: "acp-namespace",
			},
			returnStatusCode: http.StatusConflict,
			wantErr:          assertErrorIs(ErrVersionConflict),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			var (
				callCount int
				callWith  hubv1alpha1.EdgeIngress
			)

			mux := http.NewServeMux()
			mux.HandleFunc("/edge-ingresses", func(rw http.ResponseWriter, req *http.Request) {
				callCount++

				if req.Method != http.MethodPost {
					http.Error(rw, fmt.Sprintf("unsupported to method: %s", req.Method), http.StatusMethodNotAllowed)
					return
				}

				if req.Header.Get("Authorization") != "Bearer "+testToken {
					http.Error(rw, "Invalid token", http.StatusUnauthorized)
					return
				}

				err := json.NewDecoder(req.Body).Decode(&callWith)
				require.NoError(t, err)

				rw.WriteHeader(test.returnStatusCode)
				err = json.NewEncoder(rw).Encode(test.edgeIngress)
				require.NoError(t, err)
			})

			srv := httptest.NewServer(mux)

			t.Cleanup(srv.Close)

			c := NewClient(srv.URL, testToken)
			c.httpClient = srv.Client()

			createdEdgeIngress, err := c.CreateEdgeIngress(context.Background(), test.createReq)
			test.wantErr(t, err)

			require.Equal(t, 1, callCount)
			assert.Equal(t, test.edgeIngress, createdEdgeIngress)
		})
	}
}

func TestClient_UpdateEdgeIngress(t *testing.T) {
	edgeIngress := hubv1alpha1.EdgeIngress{
		TypeMeta: metav1.TypeMeta{Kind: "EdgeIngress"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "name",
			Namespace: "namespace",
		},
		Spec: hubv1alpha1.EdgeIngressSpec{
			Service: hubv1alpha1.EdgeIngressService{
				Name: "service-name",
				Port: 8080,
			},
			ACP: &hubv1alpha1.EdgeIngressACP{
				Name:      "acp-name",
				Namespace: "acp-namespace",
			},
		},
	}
	edgeIngressWithStatus := edgeIngress
	edgeIngressWithStatus.Status.Version = "version-2"
	edgeIngressWithStatus.Status.Domain = "majestic-beaver-123.hub-traefik.io"

	tests := []struct {
		desc             string
		name             string
		namespace        string
		version          string
		updateReq        *UpdateEdgeIngressReq
		edgeIngress      *edgeingress.EdgeIngress
		returnStatusCode int
		wantErr          assert.ErrorAssertionFunc
	}{
		{
			desc:      "update edge ingress",
			name:      "name",
			namespace: "namespace",
			version:   "version-1",
			updateReq: &UpdateEdgeIngressReq{
				ServiceName:  "service-name",
				ServicePort:  8080,
				ACPName:      "acp-name",
				ACPNamespace: "acp-namespace",
			},
			returnStatusCode: http.StatusOK,
			wantErr:          assert.NoError,
			edgeIngress: &edgeingress.EdgeIngress{
				WorkspaceID:  "workspace-id",
				ClusterID:    "cluster-id",
				Namespace:    "namespace",
				Name:         "name",
				Domain:       "majestic-beaver-123.hub-traefik.io",
				Version:      "version-2",
				ServiceName:  "service-name",
				ServicePort:  8080,
				ACPName:      "acp-name",
				ACPNamespace: "acp-namespace",
				CreatedAt:    time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond),
				UpdatedAt:    time.Now().UTC().Truncate(time.Millisecond),
			},
		},
		{
			desc:    "conflict",
			version: "version-1",
			updateReq: &UpdateEdgeIngressReq{
				ServiceName:  "service-name",
				ServicePort:  8080,
				ACPName:      "acp-name",
				ACPNamespace: "acp-namespace",
			},
			returnStatusCode: http.StatusConflict,
			wantErr:          assertErrorIs(ErrVersionConflict),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			var (
				callCount int
				callWith  hubv1alpha1.EdgeIngress
			)

			id := test.name + "@" + test.namespace
			mux := http.NewServeMux()
			mux.HandleFunc("/edge-ingresses/"+id, func(rw http.ResponseWriter, req *http.Request) {
				callCount++

				if req.Method != http.MethodPut {
					http.Error(rw, fmt.Sprintf("unsupported to method: %s", req.Method), http.StatusMethodNotAllowed)
					return
				}

				if req.Header.Get("Authorization") != "Bearer "+testToken {
					http.Error(rw, "Invalid token", http.StatusUnauthorized)
					return
				}
				if req.Header.Get("Last-Known-Version") != test.version {
					http.Error(rw, "Invalid token", http.StatusInternalServerError)
					return
				}

				err := json.NewDecoder(req.Body).Decode(&callWith)
				require.NoError(t, err)

				rw.WriteHeader(test.returnStatusCode)
				err = json.NewEncoder(rw).Encode(test.edgeIngress)
				require.NoError(t, err)
			})

			srv := httptest.NewServer(mux)

			t.Cleanup(srv.Close)

			c := NewClient(srv.URL, testToken)
			c.httpClient = srv.Client()

			updatedEdgeIngress, err := c.UpdateEdgeIngress(context.Background(), test.namespace, test.name, test.version, test.updateReq)
			test.wantErr(t, err)

			require.Equal(t, 1, callCount)
			assert.Equal(t, test.edgeIngress, updatedEdgeIngress)
		})
	}
}

func TestClient_DeleteEdgeIngress(t *testing.T) {
	tests := []struct {
		desc             string
		version          string
		name             string
		namespace        string
		returnStatusCode int
		wantErr          assert.ErrorAssertionFunc
		edgeIngress      *hubv1alpha1.EdgeIngress
	}{
		{
			desc:             "delete edge ingress",
			version:          "version-1",
			name:             "name",
			namespace:        "namespace",
			returnStatusCode: http.StatusNoContent,
			wantErr:          assert.NoError,
		},
		{
			desc:             "conflict",
			version:          "version-1",
			name:             "name",
			namespace:        "namespace",
			returnStatusCode: http.StatusConflict,
			wantErr:          assertErrorIs(ErrVersionConflict),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			var callCount int

			id := test.name + "@" + test.namespace
			mux := http.NewServeMux()
			mux.HandleFunc("/edge-ingresses/"+id, func(rw http.ResponseWriter, req *http.Request) {
				callCount++

				if req.Method != http.MethodDelete {
					http.Error(rw, fmt.Sprintf("unsupported to method: %s", req.Method), http.StatusMethodNotAllowed)
					return
				}

				if req.Header.Get("Authorization") != "Bearer "+testToken {
					http.Error(rw, "Invalid token", http.StatusUnauthorized)
					return
				}
				if req.Header.Get("Last-Known-Version") != test.version {
					http.Error(rw, "Invalid token", http.StatusInternalServerError)
					return
				}

				rw.WriteHeader(test.returnStatusCode)
			})

			srv := httptest.NewServer(mux)

			t.Cleanup(srv.Close)

			c := NewClient(srv.URL, testToken)
			c.httpClient = srv.Client()

			err := c.DeleteEdgeIngress(context.Background(), test.version, test.namespace, test.name)
			test.wantErr(t, err)

			require.Equal(t, 1, callCount)
		})
	}
}

func TestClient_CreateACP(t *testing.T) {
	tests := []struct {
		desc             string
		policy           *hubv1alpha1.AccessControlPolicy
		acp              *acp.ACP
		returnStatusCode int
		wantErr          assert.ErrorAssertionFunc
	}{
		{
			desc: "create access control policy",
			policy: &hubv1alpha1.AccessControlPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "namespace",
				},
				Spec: hubv1alpha1.AccessControlPolicySpec{
					JWT: &hubv1alpha1.AccessControlPolicyJWT{
						PublicKey: "key",
					},
				},
			},
			returnStatusCode: http.StatusCreated,
			wantErr:          assert.NoError,
			acp: &acp.ACP{
				Namespace: "namespace",
				Name:      "name",
				Version:   "version-1",
				Config: acp.Config{
					JWT: &jwt.Config{
						PublicKey: "key",
					},
				},
			},
		},
		{
			desc: "conflict",
			policy: &hubv1alpha1.AccessControlPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "namespace",
				},
				Spec: hubv1alpha1.AccessControlPolicySpec{
					JWT: &hubv1alpha1.AccessControlPolicyJWT{
						PublicKey: "key",
					},
				},
			},
			returnStatusCode: http.StatusConflict,
			wantErr:          assertErrorIs(ErrVersionConflict),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			var (
				callCount int
				callWith  acp.ACP
			)

			mux := http.NewServeMux()
			mux.HandleFunc("/acps", func(rw http.ResponseWriter, req *http.Request) {
				callCount++

				if req.Method != http.MethodPost {
					http.Error(rw, fmt.Sprintf("unsupported to method: %s", req.Method), http.StatusMethodNotAllowed)
					return
				}

				if req.Header.Get("Authorization") != "Bearer "+testToken {
					http.Error(rw, "Invalid token", http.StatusUnauthorized)
					return
				}

				err := json.NewDecoder(req.Body).Decode(&callWith)
				require.NoError(t, err)

				rw.WriteHeader(test.returnStatusCode)
				if test.returnStatusCode == http.StatusConflict {
					return
				}

				callWith.Version = "version-1"
				assert.Equal(t, test.acp, &callWith)

				err = json.NewEncoder(rw).Encode(callWith)
				require.NoError(t, err)
			})

			srv := httptest.NewServer(mux)

			t.Cleanup(srv.Close)

			c := NewClient(srv.URL, testToken)
			c.httpClient = srv.Client()

			createdACP, err := c.CreateACP(context.Background(), test.policy)
			test.wantErr(t, err)

			require.Equal(t, 1, callCount)
			assert.Equal(t, test.acp, createdACP)
		})
	}
}

func TestClient_UpdateACP(t *testing.T) {
	tests := []struct {
		desc             string
		policy           *hubv1alpha1.AccessControlPolicy
		acp              *acp.ACP
		returnStatusCode int
		wantErr          assert.ErrorAssertionFunc
	}{
		{
			desc: "update access control policy",
			policy: &hubv1alpha1.AccessControlPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "namespace",
				},
				Spec: hubv1alpha1.AccessControlPolicySpec{
					JWT: &hubv1alpha1.AccessControlPolicyJWT{
						PublicKey: "key",
					},
				},
			},
			returnStatusCode: http.StatusOK,
			wantErr:          assert.NoError,
			acp: &acp.ACP{
				Namespace: "namespace",
				Name:      "name",
				Version:   "version-1",
				Config: acp.Config{
					JWT: &jwt.Config{
						PublicKey: "key",
					},
				},
			},
		},
		{
			desc: "conflict",
			policy: &hubv1alpha1.AccessControlPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "name",
					Namespace: "namespace",
				},
				Spec: hubv1alpha1.AccessControlPolicySpec{
					JWT: &hubv1alpha1.AccessControlPolicyJWT{
						PublicKey: "key",
					},
				},
			},
			returnStatusCode: http.StatusConflict,
			wantErr:          assertErrorIs(ErrVersionConflict),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			var (
				callCount int
				callWith  acp.ACP
			)

			id := test.policy.Name + "@" + test.policy.Namespace
			mux := http.NewServeMux()
			mux.HandleFunc("/acps/"+id, func(rw http.ResponseWriter, req *http.Request) {
				callCount++

				if req.Method != http.MethodPut {
					http.Error(rw, fmt.Sprintf("unsupported to method: %s", req.Method), http.StatusMethodNotAllowed)
					return
				}

				if req.Header.Get("Authorization") != "Bearer "+testToken {
					http.Error(rw, "Invalid token", http.StatusUnauthorized)
					return
				}

				if req.Header.Get("Last-Known-Version") != "oldVersion" {
					http.Error(rw, "Invalid token", http.StatusUnauthorized)
					return
				}

				err := json.NewDecoder(req.Body).Decode(&callWith)
				require.NoError(t, err)

				rw.WriteHeader(test.returnStatusCode)
				if test.returnStatusCode == http.StatusConflict {
					return
				}

				callWith.Version = "version-1"
				assert.Equal(t, test.acp, &callWith)

				err = json.NewEncoder(rw).Encode(callWith)
				require.NoError(t, err)
			})

			srv := httptest.NewServer(mux)

			t.Cleanup(srv.Close)

			c := NewClient(srv.URL, testToken)
			c.httpClient = srv.Client()

			updatedACP, err := c.UpdateACP(context.Background(), "oldVersion", test.policy)
			test.wantErr(t, err)

			require.Equal(t, 1, callCount)
			assert.Equal(t, test.acp, updatedACP)
		})
	}
}

func TestClient_DeleteACP(t *testing.T) {
	tests := []struct {
		desc             string
		name             string
		namespace        string
		returnStatusCode int
		wantErr          assert.ErrorAssertionFunc
	}{
		{
			desc:             "update access control policy",
			name:             "name",
			namespace:        "namespace",
			returnStatusCode: http.StatusNoContent,
			wantErr:          assert.NoError,
		},
		{
			desc:             "conflict",
			name:             "name",
			namespace:        "namespace",
			returnStatusCode: http.StatusConflict,
			wantErr:          assertErrorIs(ErrVersionConflict),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			var callCount int
			id := test.name + "@" + test.namespace
			mux := http.NewServeMux()
			mux.HandleFunc("/acps/"+id, func(rw http.ResponseWriter, req *http.Request) {
				callCount++

				if req.Method != http.MethodDelete {
					http.Error(rw, fmt.Sprintf("unsupported to method: %s", req.Method), http.StatusMethodNotAllowed)
					return
				}

				if req.Header.Get("Authorization") != "Bearer "+testToken {
					http.Error(rw, "Invalid token", http.StatusUnauthorized)
					return
				}
				if req.Header.Get("Last-Known-Version") != "oldVersion" {
					http.Error(rw, "Invalid token", http.StatusInternalServerError)
					return
				}

				rw.WriteHeader(test.returnStatusCode)
			})

			srv := httptest.NewServer(mux)

			t.Cleanup(srv.Close)

			c := NewClient(srv.URL, testToken)
			c.httpClient = srv.Client()

			err := c.DeleteACP(context.Background(), "oldVersion", test.name, test.namespace)
			test.wantErr(t, err)

			require.Equal(t, 1, callCount)
		})
	}
}

func TestClient_GetEdgeIngress(t *testing.T) {
	wantEdgeIngresses := []edgeingress.EdgeIngress{
		{
			WorkspaceID:  "workspace-id",
			ClusterID:    "cluster-id",
			Namespace:    "namespace",
			Name:         "name",
			Domain:       "https://majestic-beaver-123.traefik-hub.io",
			Version:      "version",
			ServiceName:  "service-name",
			ServicePort:  8080,
			ACPName:      "acp-name",
			ACPNamespace: "acp-namespace",
			CreatedAt:    time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond),
			UpdatedAt:    time.Now().UTC().Truncate(time.Millisecond),
		},
	}

	var callCount int

	mux := http.NewServeMux()
	mux.HandleFunc("/edge-ingresses", func(rw http.ResponseWriter, req *http.Request) {
		callCount++

		if req.Method != http.MethodGet {
			http.Error(rw, fmt.Sprintf("unsupported to method: %s", req.Method), http.StatusMethodNotAllowed)
			return
		}

		if req.Header.Get("Authorization") != "Bearer "+testToken {
			http.Error(rw, "Invalid token", http.StatusUnauthorized)
			return
		}

		rw.WriteHeader(http.StatusOK)
		err := json.NewEncoder(rw).Encode(wantEdgeIngresses)
		require.NoError(t, err)
	})

	srv := httptest.NewServer(mux)

	t.Cleanup(srv.Close)

	c := NewClient(srv.URL, testToken)
	c.httpClient = srv.Client()

	gotEdgeIngresses, err := c.GetEdgeIngresses(context.Background())
	require.NoError(t, err)

	require.Equal(t, 1, callCount)
	assert.Equal(t, wantEdgeIngresses, gotEdgeIngresses)
}

func assertErrorIs(wantErr error) assert.ErrorAssertionFunc {
	return func(t assert.TestingT, err error, i ...interface{}) bool {
		return assert.ErrorIs(t, err, wantErr, i...)
	}
}
