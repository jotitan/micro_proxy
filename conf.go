package main

import (
	"encoding/json"
	"os"
)

const (
	basicSecurity  = SecurityType("basic")
	oauth2Security = SecurityType("oauth2")
)

type SecurityType string

type certificateConfig struct {
	PathKey string `json:"key"`
	PathCrt string `json:"crt"`
}

type BasicConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type OAuth2Config struct {
	Provider              string   `json:"provider"`
	ClientId              string   `json:"client_id"`
	ClientSecret          string   `json:"client_secret"`
	RedirectUrl           string   `json:"redirect_url"`
	AuthorizedEmails      []string `json:"emails"`
	AdminAuthorizedEmails []string `json:"admin_emails"`
}

type Security struct {
	Type      SecurityType `json:"type"`
	JWTSecret string       `json:"secret"`
	Basic     BasicConfig  `json:"basic"`
	OAuth2    OAuth2Config `json:"oauth2"`
}

type routeProxy struct {
	Name string `json:"route"`
	Host string `json:"host"`
	// if true, create a special proxy to manage Sse request
	Sse      bool `json:"sse"`
	Security bool `json:"security"`
	// Guest connection is possible, only if security is true
	Guest bool `json:"guest"`
}

type Config struct {
	ChallengesFolder string            `json:"challenges-folder"`
	Certificate      certificateConfig `json:"certificate"`
	Routes           []routeProxy      `json:"routes"`
	Security         Security          `json:"security"`
	Monitoring       string            `json:"monitoring_url"`
}

func extractConfig(path string) (Config, error) {
	if data, err := os.ReadFile(path); err == nil {
		var config Config
		err = json.Unmarshal(data, &config)
		if err != nil {
			return Config{}, err
		}

		routes := make(map[string]routeProxy, 0)
		for _, route := range config.Routes {
			routes[route.Name] = routeProxy{Name: route.Name, Host: route.Host, Sse: route.Sse}
		}
		return config, nil
	} else {
		return Config{}, err
	}
}
