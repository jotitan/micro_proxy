package main

import (
	"crypto/tls"
	"fmt"
	"github.com/jotitan/proxy_server/proxy"

	"net/http"
	"path/filepath"
	"regexp"
	"time"
)
import "strings"
import "os"
import "log"

var proxyRoutes map[string]proxy.ProxyWrapper
var originsRoutes map[string]map[string]proxy.ProxyWrapper
var challengesFolder string

var security proxy.SecurityAccess

var monitoring proxy.Monitoring

const (
	logLevelAll   = 0
	logLevelError = 1
)

var logLevel = logLevelAll

func main() {
	if len(os.Args) < 3 {
		logError("Need parameters <port> <conf>")
		os.Exit(1)
	}

	config, err := proxy.ExtractConfig(os.Args[2])
	if err != nil {
		log.Fatal("Impossible to extract config", err)
	}
	if config.ProxyByRoute {
		proxyRoutes = proxy.CreateProxyRoutes(config.Routes)
	} else {
		originsRoutes = proxy.CreateProxyRoutesByOrigin(config.Origins)
	}
	challengesFolder = config.ChallengesFolder
	security = proxy.NewSecurityAccess(config)
	monitoring = proxy.NewMonitoring(config.Monitoring)

	port := os.Args[1]
	serverMux := http.NewServeMux()
	server := http.Server{
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		Addr:    ":" + port,
		Handler: serverMux,
	}

	serverMux.HandleFunc("/signature/public-key", getPublicKey)
	serverMux.HandleFunc("/callback", callback)
	serverMux.HandleFunc("/loglevel", setLogLevel)
	serverMux.HandleFunc("/", routing)

	if !strings.EqualFold("", config.Certificate.PathKey) {
		logInfo(fmt.Sprintf("Start secured proxy on port %s with %d / %d routes", port, len(proxyRoutes), len(originsRoutes)))
		log.Fatal(server.ListenAndServeTLS(config.Certificate.PathCrt, config.Certificate.PathKey))
	} else {
		logInfo(fmt.Sprintf("Start proxy on port %s with %d / %d routes", port, len(proxyRoutes), len(originsRoutes)))
		log.Fatal(server.ListenAndServe())
	}
}

func acme(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Path[len("/.well-known/acme-challenge")+1:]
	logInfo("Run acme challenge", file)
	reg := regexp.MustCompile("[0-9a-zA-Z_-]+")
	if !reg.MatchString(file) {
		logError("Error, bad file", file)
		http.Error(w, "bad request", 400)
	} else {
		logInfo("Challenge", r.URL.Path, file)
		http.ServeFile(w, r, filepath.Join(challengesFolder, file))
	}
}

// callback is used by security
func getPublicKey(w http.ResponseWriter, r *http.Request) {
	if data, err := security.SignatureTool.GetPublicKey(r.FormValue("kid")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else {
		w.Write(data)
	}
}

func callback(w http.ResponseWriter, r *http.Request) {
	// Check if token already exist
	if security.IsConnected(r) {
		redirect(w, r)
		return
	}
	scope := r.FormValue("state")
	if r.FormValue("kind") == "guest" {
		// Connect as guest
		// If / exists, cut after the first (cause full path)
		if pos := strings.Index(scope, "/"); pos != -1 {
			scope = scope[0:pos]
		}
		if proxy, exist := searchRoute(scope, proxy.GetHost(r)); exist {
			if security.CheckAndConnectAsGuest(w, proxy, scope) {
				redirect(w, r)
				return
			}
		}
		errorNoGuest(w)
	} else {
		if email, err := security.Provider.GetEmailFromAuthent(r); err == nil {
			security.SetJWT(w, email, scope, getAdminByScope(email, proxy.GetHost(r)), false)
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
	logInfo("Receive request", r.URL.Path, r.Referer())

	if manageAcme(w, r) || manageLongPath(w, r) || manageRoot(w, r) || manageReferee(w, r) {
		return
	}

	logError("Unknown route =>", r.URL.Path, r.Referer(), r.URL.RequestURI())
	errorNoRoute(w)
	timeout()
}

// manageAcme is used to provides challenges file from certbot
func manageAcme(w http.ResponseWriter, r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge") {
		acme(w, r)
		return true
	}
	return false
}

func getRoutes(host string) map[string]proxy.ProxyWrapper {
	if len(proxyRoutes) > 0 {
		return proxyRoutes
	}
	if routes, exist := originsRoutes[host]; !exist {
		return map[string]proxy.ProxyWrapper{}
	} else {
		return routes
	}
}

func searchRoute(route, host string) (proxy.ProxyWrapper, bool) {
	routes := getRoutes(host)
	p, exist := routes[route]
	return p, exist
}

func getAdminByScope(email, host string) map[string]bool {
	m := make(map[string]bool)
	for name, route := range getRoutes(host) {
		m[name] = route.Admins.Has(email)
	}
	return m
}

// manageLongPath manage a complete path by extracting the beginning to find the route
func manageLongPath(w http.ResponseWriter, r *http.Request) bool {
	if pos := strings.Index(r.URL.Path[1:], "/"); pos != -1 {
		subPath := r.URL.Path[1 : pos+1]
		if route, exist := searchRoute(subPath, proxy.GetHost(r)); exist {
			// Redirect
			serve(w, r, subPath, r.URL.Path[1+pos:], route)
			return true
		}
	}
	return false
}

// manageRoot test if route exist and serve request
func manageRoot(w http.ResponseWriter, r *http.Request) bool {
	if route, exist := searchRoute(r.URL.Path[1:], proxy.GetHost(r)); exist {
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
	routes := getRoutes(proxy.GetHost(r))
	for route, gateway := range routes {
		if strings.Index(r.Referer(), route) != -1 {
			serve(w, r, route, r.URL.Path[1:], gateway)
			return true
		}
	}
	return false
}

func serve(w http.ResponseWriter, r *http.Request, routeName, path string, wrapper proxy.ProxyWrapper) {
	// If security, check token exists
	doContinue, err := security.Check(w, r, wrapper, routeName)
	if err != nil {
		errorNoRight(w)
	}
	if err != nil || !doContinue {
		return
	}
	r.URL.Path = path

	switch {
	case wrapper.IsServeFile:
		wrapper.ServeFile(w, r)
	case strings.EqualFold("text/event-stream", r.Header.Get("Accept")):
		r.Header.Set("proxy-redirect", routeName+"/")
		logInfo("Serve SSE on ", routeName)
		wrapper.Sse.ServeHTTP(w, r)
	default:
		r.Header.Set("proxy-redirect", routeName+"/")
		logRoute(routeName, path)
		wrapper.Standard.ServeHTTP(w, r)
	}
}

func logRoute(route, path string) {
	monitoring.AddMetric("success")
	monitoring.AddMetric(route)
	isRequest := !strings.Contains(path, ".") || strings.Contains(path, "?")
	if isRequest {
		monitoring.AddMetric("request")
	} else {
		monitoring.AddMetric("file")
	}
}

func errorNoRight(w http.ResponseWriter) {
	http.Error(w, "No rights, get out", http.StatusUnauthorized)
	monitoring.AddMetric("no-right")
}

func errorNoLogin(w http.ResponseWriter, err string) {
	http.Error(w, err, http.StatusUnauthorized)
	monitoring.AddMetric("no-log")
}

func errorNoRoute(w http.ResponseWriter) {
	http.Error(w, "no route", http.StatusNotFound)
	monitoring.AddMetric("no-route")
}
func errorNoGuest(w http.ResponseWriter) {
	http.Error(w, "Impossible to connect as guest, get out", http.StatusUnauthorized)
	monitoring.AddMetric("no-guest")
}

func setLogLevel(w http.ResponseWriter, r *http.Request) {
	level := r.FormValue("level")
	if level == "ERROR" {
		logLevel = logLevelError
	} else {
		logLevel = logLevelAll
	}
}

func logInfo(args ...string) {
	if logLevel == logLevelError {
		return
	}
	if excludeCase(args...) {
		return
	}
	log.Println(strings.Join(args, " "))
}

func logError(args ...string) {
	if excludeCase(args...) {
		return
	}
	log.Println(strings.Join(args, " "))
}

func excludeCase(args ...string) bool {
	return strings.HasSuffix(args[len(args)-1], ".map")
}

func timeout() {
	time.Sleep(time.Second * 100)
}
