package proxy

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
	Provider            string            `json:"Provider"`
	ClientId            string            `json:"client_id"`
	ClientSecret        string            `json:"client_secret"`
	RedirectUrl         string            `json:"redirect_url"`
	RedirectUrlByDomain map[string]string `json:"redirect_url_by_domain"`
	//AuthorizedEmails []string `json:"emails"`
}

type Security struct {
	Type              SecurityType     `json:"type"`
	SymetricSignature bool             `json:"symetric_signature"`
	JWTSecret         string           `json:"secret"`
	KeysFolder        string           `json:"folder_keys"`
	Basic             BasicConfig      `json:"basic"`
	OAuth2            OAuth2Config     `json:"oauth2"`
	Providers         []ProviderConfig `json:"providers"`
}

type ProviderConfig struct {
	Name   string       `json:"name"`
	Config OAuth2Config `json:"config"`
}

type routeProxy struct {
	Name          string `json:"route"`
	Host          string `json:"host"`
	IsServeFolder bool   `json:"serve_folder"` // To serve static file in folder
	ServeFolder   string `json:"folder"`       // Folder to serve
	// if true, create a special proxy to manage Sse request
	Sse      bool `json:"sse"`
	Security bool `json:"security"`
	// Guest connection is possible, only if security is true
	Guest bool `json:"guest"`
	// List of authorized providers
	SecurityProviders     []string `json:"security-providers"`
	AdminAuthorizedEmails []string `json:"admin_emails"`
}

type OriginConfig struct {
	Routes   []routeProxy         `json:"routes"`
	Security OriginSecurityConfig `json:"security"`
}

type OriginSecurityConfig struct {
	Emails []string `json:"emails"`
}

type Config struct {
	ChallengesFolder string                  `json:"challenges-folder"`
	Certificate      certificateConfig       `json:"certificate"`
	ProxyByRoute     bool                    `json:"by_route"`
	Routes           []routeProxy            `json:"routes"`
	Origins          map[string]OriginConfig `json:"origins"`
	Security         Security                `json:"security"`
	Monitoring       string                  `json:"monitoring_url"`
}

func ExtractConfig(path string) (Config, error) {
	if data, err := os.ReadFile(path); err == nil {
		var config Config
		err = json.Unmarshal(data, &config)
		if err != nil {
			return Config{}, err
		}
		return config, nil
	} else {
		return Config{}, err
	}
}
