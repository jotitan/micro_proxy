package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Give oauth2 provider to let acccess to application

// Differents provider could be implemented (google, azure...)
type OAuth2Provider interface {
	//GenerateUrlConnection generate an url to access application from oauth2 access
	GenerateUrlConnection(context string) string
	// GetTokenFromCode Get a valid jwt token from oauth2 provider from code
	GetTokenFromCode(code string) (string, error)
	// CheckAndExtractData extract data from jwt token
	CheckAndExtractData(token string) (string, error)
}

type OAuth2SecurityProvider struct {
	provider         OAuth2Provider
	emailsAuthorized []string
	emailsAdmin      []string
}

func (O OAuth2SecurityProvider) GenerateConnectionButton(context string) string {
	return O.provider.GenerateUrlConnection(context)
}

func (O OAuth2SecurityProvider) InitConnect(w http.ResponseWriter, context string) {
	// Redirect user
	w.Header().Set("Location", O.provider.GenerateUrlConnection(context))
	w.WriteHeader(http.StatusTemporaryRedirect)
}

func (O OAuth2SecurityProvider) GetEmailFromAuthent(r *http.Request) (string, error) {
	token, err := O.provider.GetTokenFromCode(r.FormValue("code"))
	if err != nil {
		return "", err
	}
	email, err := O.provider.CheckAndExtractData(token)
	if err != nil {
		return "", err
	}
	if !O.IsEmailAuthorized(email) {
		return "", errors.New("unauthorized email")
	}
	return email, nil
}

func (O OAuth2SecurityProvider) IsEmailAuthorized(userEmail string) bool {
	for _, email := range O.emailsAuthorized {
		if email == userEmail {
			return true
		}
	}
	return false
}

func (O OAuth2SecurityProvider) IsEmailAdmin(userEmail string) bool {
	for _, email := range O.emailsAdmin {
		if email == userEmail {
			return true
		}
	}
	return false
}

func NewOAuth2Provider(conf OAuth2Config) OAuth2SecurityProvider {
	return OAuth2SecurityProvider{
		provider:         newProvider(conf),
		emailsAuthorized: conf.AuthorizedEmails,
		emailsAdmin:      conf.AdminAuthorizedEmails,
	}
}

func newProvider(conf OAuth2Config) OAuth2Provider {
	switch conf.Provider {
	case "google":
		return NewGoogleProvider(conf.ClientId, conf.ClientSecret, conf.RedirectUrl)
	default:
		return nil
	}
}

type GoogleProvider struct {
	clientID        string
	clientSecret    string
	urlGenerateCode string
	redirectUrl     string
	urlToken        string
}

func NewGoogleProvider(clientID, clientSecret, redirectUrl string) GoogleProvider {
	return GoogleProvider{
		clientID:        clientID,
		clientSecret:    clientSecret,
		redirectUrl:     redirectUrl,
		urlGenerateCode: "https://accounts.google.com/o/oauth2/v2/auth",
		urlToken:        "https://oauth2.googleapis.com/token",
	}
}

func (gp GoogleProvider) GenerateUrlConnection(context string) string {
	return fmt.Sprintf("%s?scope=%s&client_id=%s&redirect_uri=%s&response_type=code&flowName=GeneralOAuthFlow&state=%s",
		gp.urlGenerateCode, "https://www.googleapis.com/auth/userinfo.email", gp.clientID, url.PathEscape(gp.redirectUrl), context)
}

func (gp GoogleProvider) CheckAndExtractData(token string) (string, error) {
	// No need to use a valid signature (token send by google, must be trust
	if token, _ := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) { return nil, nil }); token == nil {
		//error
		return "", errors.New("impossible to get informations from google jwt token")
	} else {
		claims := token.Claims.(jwt.MapClaims)
		if !strings.EqualFold(gp.clientID, claims["aud"].(string)) {
			return "", errors.New("bad jwt token")
		}
		if !claims["email_verified"].(bool) {
			return "", errors.New("email not verified")
		}
		return claims["email"].(string), nil
	}
}

// Get a JWT token on google oauth2 from code
func (gp GoogleProvider) GetTokenFromCode(code string) (string, error) {
	urlGetToken := fmt.Sprintf("%s?client_id=%s&client_secret=%s&code=%s&redirect_uri=%s&grant_type=authorization_code", gp.urlToken, gp.clientID, gp.clientSecret, code, gp.redirectUrl)

	if resp, err := http.PostForm(urlGetToken, url.Values{}); err == nil && resp.StatusCode == 200 {
		if data, err := io.ReadAll(resp.Body); err == nil {
			m := make(map[string]interface{})
			if err := json.Unmarshal(data, &m); err == nil {
				return m["id_token"].(string), nil
			} else {
				return "", err
			}
		} else {
			return "", err
		}
	} else {
		if err == nil {
			return "", errors.New("no token send by google provider")
		}
		return "", err
	}
}
