package main

import (
	"net/http"
	"path/filepath"
	"regexp"
)
import "strings"
import "os"
import "log"

var proxyRoutes map[string]proxyWrapper
var originsRoutes map[string]map[string]proxyWrapper
var challengesFolder string

var security SecurityAccess2

var monitoring Monitoring

func main() {
	if len(os.Args) < 3 {
		log.Println("Need parameters <port> <conf>")
		os.Exit(1)
	}

	config, err := extractConfig(os.Args[2])
	if err != nil {
		log.Fatal("Impossible to extract config", err)
	}
	if config.ProxyByRoute {
		proxyRoutes = createProxyRoutes(config.Routes)
	} else {
		originsRoutes = createProxyRoutesByOrigin(config.Origins)
	}
	challengesFolder = config.ChallengesFolder
	security = NewSecurityAccess(config)
	monitoring = NewMonitoring(config.Monitoring)

	server := http.NewServeMux()
	server.HandleFunc("/callback", callback)
	server.HandleFunc("/", routing)
	port := os.Args[1]

	if !strings.EqualFold("", config.Certificate.PathKey) {
		log.Println("Start secured proxy on port", port, "with", len(proxyRoutes), "routes")
		log.Fatal(http.ListenAndServeTLS(":"+port, config.Certificate.PathCrt, config.Certificate.PathKey, server))
	} else {
		log.Println("Start proxy on port", port, "with", len(proxyRoutes), "routes")
		log.Fatal(http.ListenAndServe(":"+port, server))
	}
}

func acme(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Path[len("/.well-known/acme-challenge")+1:]
	log.Println("Run acme challenge", file)
	reg := regexp.MustCompile("[0-9a-zA-Z_-]+")
	if !reg.MatchString(file) {
		log.Println("Error, bad file", file)
		http.Error(w, "bad request", 400)
	} else {
		log.Println("Challenge", r.URL.Path, file)
		http.ServeFile(w, r, filepath.Join(challengesFolder, file))
	}
}

// callback is used by security
func callback(w http.ResponseWriter, r *http.Request) {
	// Check if token already exist
	if security.isConnected(r) {
		redirect(w, r)
		return
	}
	scope := r.FormValue("state")
	if r.FormValue("kind") == "guest" {
		// Connect as guest
		if proxy, exist := searchRoute(scope, getHost(r)); exist {
			if security.checkAndConnectAsGuest(w, proxy, scope) {
				redirect(w, r)
				return
			}
		}
		errorNoGuest(w)
	} else {
		if email, err := security.provider.GetEmailFromAuthent(r); err == nil {
			security.setJWT(w, email, scope, security.provider.IsEmailAdmin(email), false)
			redirect(w, r)
		} else {
			errorNoLogin(w, err.Error())
		}
	}
}

func redirect(w http.ResponseWriter, r *http.Request) {
	state := r.FormValue("state")
	w.Header().Set("Location", "/"+state)
	w.WriteHeader(http.StatusTemporaryRedirect)
}

func routing(w http.ResponseWriter, r *http.Request) {
	log.Println("Receive request", r.URL.Path)

	if manageAcme(w, r) || manageLongPath(w, r) || manageRoot(w, r) || manageReferee(w, r) {
		return
	}

	log.Println("Unknown route =>", r.URL.Path)

	errorNoRoute(w)
}

// manageAcme is used to provides challenges file from certbot
func manageAcme(w http.ResponseWriter, r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge") {
		acme(w, r)
		return true
	}
	return false
}

func getRoutes(host string) map[string]proxyWrapper {
	if len(proxyRoutes) > 0 {
		return proxyRoutes
	}
	if routes, exist := originsRoutes[host]; !exist {
		return map[string]proxyWrapper{}
	} else {
		return routes
	}
}

func searchRoute(route, host string) (proxyWrapper, bool) {
	routes := getRoutes(host)
	proxy, exist := routes[route]
	return proxy, exist
}

func getHost(r *http.Request) string {
	reg := regexp.MustCompile("(:?https?://)?([^:]+)(:?:[0-9]+)?")
	results := reg.FindAllStringSubmatch(r.Host, 1)
	if len(results) == 0 {
		return r.Host
	}
	return results[0][2]
}

// manageLongPath manage a complete path by extracting the beginning to find the route
func manageLongPath(w http.ResponseWriter, r *http.Request) bool {
	if pos := strings.Index(r.URL.Path[1:], "/"); pos != -1 {
		subPath := r.URL.Path[1 : pos+1]
		if route, exist := searchRoute(subPath, getHost(r)); exist {
			// Redirect
			serve(w, r, subPath, r.URL.Path[1+pos:], route)
			return true
		}
	}
	return false
}

// manageRoot test if route exist and serve request
func manageRoot(w http.ResponseWriter, r *http.Request) bool {
	if route, exist := searchRoute(r.URL.Path[1:], getHost(r)); exist {
		if !strings.HasSuffix(r.URL.Path[1:], "/") {
			w.Header().Set("Location", "/"+r.URL.Path[1:]+"/")
			w.WriteHeader(308)
			return true
		}
		serve(w, r, r.URL.Path[1:], "/", route)
		return true
	}
	return false
}

// Check if referee contains route, if true, redirect to also, range over routes
func manageReferee(w http.ResponseWriter, r *http.Request) bool {
	routes := getRoutes(getHost(r))
	for route, gateway := range routes {
		if strings.Index(r.Referer(), route) != -1 {
			serve(w, r, route, r.URL.Path[1:], gateway)
			return true
		}
	}
	return false
}

func serve(w http.ResponseWriter, r *http.Request, routeName, path string, wrapper proxyWrapper) {
	// If security, check token exists
	doContinue, err := security.check(w, r, wrapper, routeName)
	if err != nil {
		errorNoRight(w)
	}
	if err != nil || !doContinue {
		return
	}
	r.URL.Path = path
	r.Header.Set("proxy-redirect", routeName+"/")
	// SSE case
	if strings.EqualFold("text/event-stream", r.Header.Get("Accept")) {
		log.Println("Serve SSE on ", routeName)
		wrapper.sse.ServeHTTP(w, r)
	} else {
		logRoute(routeName, path)
		wrapper.standard.ServeHTTP(w, r)
	}
}

func logRoute(route, path string) {
	monitoring.addMetric("success")
	monitoring.addMetric(route)
	isRequest := !strings.Contains(path, ".") || strings.Contains(path, "?")
	if isRequest {
		monitoring.addMetric("request")
	} else {
		monitoring.addMetric("file")
	}
}

func errorNoRight(w http.ResponseWriter) {
	http.Error(w, "No rights, get out", http.StatusUnauthorized)
	monitoring.addMetric("no-right")
}

func errorNoLogin(w http.ResponseWriter, err string) {
	http.Error(w, err, http.StatusUnauthorized)
	monitoring.addMetric("no-log")
}

func errorNoRoute(w http.ResponseWriter) {
	http.Error(w, "no route", http.StatusNotFound)
	monitoring.addMetric("no-route")
}
func errorNoGuest(w http.ResponseWriter) {
	http.Error(w, "Impossible to connect as guest, get out", http.StatusUnauthorized)
	monitoring.addMetric("no-guest")
}
