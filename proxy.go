package main

import (
	"net"
	"net/http"
	"time"
)
import "net/http/httputil"
import "net/url"

func createProxyRoutes(routes map[string]routeProxy) map[string]proxyWrapper {
	proxies := make(map[string]proxyWrapper, len(routes))
	for route, detail := range routes {
		wrapper := proxyWrapper{standard: newProxy(detail.host, false)}
		if detail.sse {
			wrapper.sse = newProxy(detail.host, true)
		}
		proxies[route] = wrapper
	}
	return proxies
}

type proxyWrapper struct {
	standard *httputil.ReverseProxy
	sse      *httputil.ReverseProxy
}

// Create a new sse proxy
func newProxy(proxyUrl string, isSse bool) *httputil.ReverseProxy {
	u, err := url.Parse(proxyUrl)
	if err != nil {
		return nil
	}
	r := httputil.NewSingleHostReverseProxy(u)
	if isSse {
		r.FlushInterval = 100 * time.Millisecond

		//Prolong timeouts
		r.Transport = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   24 * time.Hour,
				KeepAlive: 24 * time.Hour,
			}).Dial,
			TLSHandshakeTimeout: 60 * time.Second,
		}
	}
	return r
}
