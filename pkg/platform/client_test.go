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

func TestClient_ReportSecuredRoutesInUse(t *testing.T) {
	tests := []struct {
		desc string

		securedRoute     int
		returnStatusCode int
		wantErr          assert.ErrorAssertionFunc
	}{
		{
			desc:             "reports secured routes in use",
			securedRoute:     3,
			returnStatusCode: http.StatusOK,
			wantErr:          assert.NoError,
		},
		{
			desc:             "returns error when status code is not 200",
			returnStatusCode: http.StatusBadRequest,
			wantErr:          assert.Error,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			var callCount int
			var gotCurrent int

			mux := http.NewServeMux()
			mux.HandleFunc("/quotas", func(rw http.ResponseWriter, req *http.Request) {
				callCount++

				if test.returnStatusCode != http.StatusOK {
					rw.WriteHeader(test.returnStatusCode)
					return
				}

				if req.Method != http.MethodPut {
					http.Error(rw, fmt.Sprintf("unsupported to method: %s", req.Method), http.StatusMethodNotAllowed)
					return
				}

				if req.Header.Get("Authorization") != "Bearer "+testToken {
					http.Error(rw, "Invalid token", http.StatusUnauthorized)
					return
				}

				payload := struct {
					Name    string `json:"name"`
					Current int    `json:"current"`
				}{}

				err := json.NewDecoder(req.Body).Decode(&payload)
				require.NoError(t, err)
				gotCurrent = payload.Current

				rw.WriteHeader(test.returnStatusCode)
			})

			srv := httptest.NewServer(mux)

			t.Cleanup(srv.Close)

			c := NewClient(srv.URL, testToken)
			c.httpClient = srv.Client()

			err := c.ReportSecuredRoutesInUse(context.Background(), 3)
			test.wantErr(t, err)

			assert.Equal(t, 1, callCount)
			if test.returnStatusCode == http.StatusOK {
				assert.Equal(t, test.securedRoute, gotCurrent)
			}
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
