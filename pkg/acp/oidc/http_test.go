package oidc

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_newHTTPClient_WithProxyEnvVars(t *testing.T) {
	testProxyServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_, err := rw.Write([]byte(`PROXIED`))
		require.NoError(t, err)
	}))
	defer testProxyServer.Close()

	os.Clearenv()

	err := os.Setenv("HTTP_PROXY", testProxyServer.URL)
	require.NoError(t, err)

	defer os.Unsetenv("HTTP_PROXY")

	client := newHTTPClient()
	require.NoError(t, err)

	resp, err := client.Get("http://foo.bar")
	require.NoError(t, err)

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, []byte(`PROXIED`), body)
}
