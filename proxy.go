package main

import (
	"net"
	"net/http"
	"time"
)
import "net/http/httputil"
import "net/url"

func createProxyRoutes(routes []routeProxy) map[string]proxyWrapper {
	proxies := make(map[string]proxyWrapper, len(routes))
	for _, route := range routes {
		proxies[route.Name] = createProxy(route)
	}
	return proxies
}

func createProxyRoutesByOrigin(originsConfig map[string]OriginConfig) map[string]map[string]proxyWrapper {
	origins := make(map[string]map[string]proxyWrapper, len(originsConfig))
	for name, origin := range originsConfig {
		origins[name] = make(map[string]proxyWrapper, len(origin.Routes))
		for _, route := range origin.Routes {
			origins[name][route.Name] = createProxy(route)
		}
	}
	return origins
}

func getListAsSet(data []string) set {
	m := make(map[string]struct{}, len(data))
	for _, d := range data {
		m[d] = struct{}{}
	}
	return m
}

func createProxy(detail routeProxy) proxyWrapper {
	wrapper := proxyWrapper{standard: newProxy(detail.Host, false), security: detail.Security, guest: detail.Guest, admins: getListAsSet(detail.AdminAuthorizedEmails)}
	if detail.Sse {
		wrapper.sse = newProxy(detail.Host, true)
	}
	return wrapper
}

// proxyWrapper wrap the proxy by giving standard implement and version which accept SSE connexion
type proxyWrapper struct {
	standard *httputil.ReverseProxy
	sse      *httputil.ReverseProxy
	security bool
	guest    bool
	admins   set
}

// Create a new Sse proxy
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
			DialContext: (&net.Dialer{
				Timeout:   24 * time.Hour,
				KeepAlive: 24 * time.Hour,
			}).DialContext,
			TLSHandshakeTimeout: 60 * time.Second,
		}
	}
	return r
}
