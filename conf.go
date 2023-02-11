package main

import (
	"encoding/json"
	"os"
)

type certificateConfig struct {
	pathKey string
	pathCrt string
}

type routeProxy struct {
	name string
	host string
	// if true, create a special proxy to manage sse request
	sse bool
}

// Structure of conf file : Json like {[{route:,host:},{route:,host:}]}
func extractConfig(path string) (map[string]routeProxy, certificateConfig) {
	routes := make(map[string]routeProxy, 0)
	certif := certificateConfig{}
	if data, err := os.ReadFile(path); err == nil {
		config := make(map[string]interface{}, 0)
		json.Unmarshal(data, &config)
		for _, route := range config["routes"].([]interface{}) {
			useSse := false
			routeDetail := route.(map[string]interface{})
			if _, exist := routeDetail["sse"]; exist {
				useSse = true
			}
			routes[routeDetail["route"].(string)] = routeProxy{name: routeDetail["route"].(string), host: routeDetail["host"].(string), sse: useSse}
		}
		if certificate, ok := config["certificate"]; ok {
			if value, exist := certificate.(map[string]interface{})["key"]; exist {
				certif.pathKey = value.(string)
				certif.pathCrt = certificate.(map[string]interface{})["crt"].(string)
			}
		}
	}
	return routes, certif
}
