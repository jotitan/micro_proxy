package proxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"time"
)
import "net/http/httputil"
import "net/url"

func GetHost(r *http.Request) string {
	reg := regexp.MustCompile("(:?https?://)?([^:]+)(:?:[0-9]+)?")
	results := reg.FindAllStringSubmatch(r.Host, 1)
	if len(results) == 0 {
		return r.Host
	}
	return results[0][2]
}

// CreateProxyRoutes create routes for a single domain
func CreateProxyRoutes(routes []routeProxy) map[string]ProxyWrapper {
	proxies := make(map[string]ProxyWrapper, len(routes))
	for _, route := range routes {
		proxies[route.Name] = createProxy(route)
	}
	return proxies
}

// CreateProxyRoutesByOrigin manage multiple origins with many routes for each
func CreateProxyRoutesByOrigin(originsConfig map[string]OriginConfig) map[string]map[string]ProxyWrapper {
	origins := make(map[string]map[string]ProxyWrapper, len(originsConfig))
	for name, origin := range originsConfig {
		origins[name] = make(map[string]ProxyWrapper, len(origin.Routes))
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

func createProxy(detail routeProxy) ProxyWrapper {
	if detail.IsServeFolder {
		return ProxyWrapper{ServeFile: newProxyServeFile(detail), IsServeFile: true, security: detail.Security, guest: detail.Guest, Admins: getListAsSet(detail.AdminAuthorizedEmails)}
	}
	wrapper := ProxyWrapper{Standard: newProxy(detail.Host, false), security: detail.Security, guest: detail.Guest, Admins: getListAsSet(detail.AdminAuthorizedEmails)}
	if detail.Sse {
		wrapper.Sse = newProxy(detail.Host, true)
	}
	return wrapper
}

// ProxyWrapper wrap the proxy by giving standard implement and version which accept SSE connexion
type ProxyWrapper struct {
	Standard    *httputil.ReverseProxy
	Sse         *httputil.ReverseProxy
	ServeFile   http.HandlerFunc
	IsServeFile bool
	security    bool
	guest       bool
	Admins      set
}

func newProxyServeFile(detail routeProxy) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(detail.ServeFolder, r.URL.Path))
	}
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
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			Proxy:           http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   24 * time.Hour,
				KeepAlive: 24 * time.Hour,
			}).DialContext,
			TLSHandshakeTimeout: 60 * time.Second,
		}
	}
	return r
}
