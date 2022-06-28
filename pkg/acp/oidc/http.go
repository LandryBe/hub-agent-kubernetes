package oidc

import (
	"net"
	"net/http"
	"time"
)

//TODO add TLS configuration.
func newHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			Proxy:               http.ProxyFromEnvironment,
		},
		Timeout: 5 * time.Second,
	}
}
