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
var challengesFolder string

func main() {
	if len(os.Args) != 3 {
		log.Println("Need parameters <port> <conf>")
		os.Exit(1)
	}
	var routes map[string]routeProxy
	var certificate certificateConfig
	routes, certificate, challengesFolder = extractConfig(os.Args[2])
	proxyRoutes = createProxyRoutes(routes)

	server := http.NewServeMux()
	server.HandleFunc("/", routing)
	port := os.Args[1]

	if !strings.EqualFold("", certificate.pathKey) {
		log.Println("Start secured proxy on port", port, "with", len(routes), "routes")
		err := http.ListenAndServeTLS(":"+port, certificate.pathCrt, certificate.pathKey, server)
		log.Println("Error", err)
	} else {
		log.Println("Start proxy on port", port, "with", len(routes), "routes")
		err := http.ListenAndServe(":"+port, server)
		log.Println("Error", err)
	}
}

func acme(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Path[len("/.well-known/acme-challenge")+1:]
	reg := regexp.MustCompile("[0-9a-zA-Z_-]+")
	if !reg.MatchString(file) {
		log.Println("Error, bad file", file)
		http.Error(w, "bad request", 400)
	} else {
		log.Println("Challenge", r.URL.Path, file)
		http.ServeFile(w, r, filepath.Join(challengesFolder, file))
	}
}

func routing(w http.ResponseWriter, r *http.Request) {
	// Acme challenge
	if strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge") {
		acme(w, r)
		return
	}

	// Case redirection
	if pos := strings.Index(r.URL.Path[1:], "/"); pos != -1 {
		subPath := r.URL.Path[1 : pos+1]
		if route, exist := proxyRoutes[subPath]; exist {
			// Redirect
			log.Println(r.URL, r.Header.Get("Accept"))
			serve(w, r, subPath, r.URL.Path[1+pos:], route)
			return
		}
	}
	// Case root
	if route, exist := proxyRoutes[r.URL.Path[1:]]; exist {
		log.Println(r.URL, r.Header.Get("Accept"))
		serve(w, r, r.URL.Path[1:], "/", route)
		return
	}

	// Check if referee contains route, if true, redirect to also, range over routes
	for route, gateway := range proxyRoutes {
		if strings.Index(r.Referer(), route) != -1 {
			log.Println(r.URL, r.Header.Get("Accept"))
			serve(w, r, route, r.URL.Path[1:], gateway)
			return
		}
	}
	log.Println("Unknown route =>", r.URL.Path)
	http.Error(w, "Unknown route", 404)
}

func serve(w http.ResponseWriter, r *http.Request, routeName, path string, wrapper proxyWrapper) {
	r.URL.Path = path
	r.Header.Set("proxy-redirect", routeName+"/")
	// SSE case
	if strings.EqualFold("text/event-stream", r.Header.Get("Accept")) {
		log.Println("Serve SSE on ", routeName)
		wrapper.sse.ServeHTTP(w, r)
	} else {
		wrapper.standard.ServeHTTP(w, r)
	}
}
