package proxy

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"net/http"
)

const jwtCookieName = "token"

type SecurityProvider interface {
	InitConnect(w http.ResponseWriter, context, domain string)
	GenerateConnectionButton(context, domain string) string
	GetEmailFromAuthent(r *http.Request) (string, error)
	IsEmailAuthorized(email, domain string) bool
}

type SecurityAccess struct {
	enable        bool
	SignatureTool JwtSignatureTool
	Provider      SecurityProvider
	// List of security Provider
	providers map[string]SecurityProvider
}

func NewSecurityAccess(conf Config) SecurityAccess {
	if conf.Security.Type == "" {
		return SecurityAccess{enable: false}
	}
	s := SecurityAccess{
		SignatureTool: NewSignatureTool(conf),
		enable:        true,
	}
	switch conf.Security.Type {
	case basicSecurity:

	case oauth2Security:
		s.Provider = NewOAuth2Provider(conf.Security.OAuth2, buildAuthorizedEmailByOrigins(conf))
	}
	return s
}

func buildAuthorizedEmailByOrigins(conf Config) map[string]set {
	emails := make(map[string]set)
	for name, config := range conf.Origins {
		emails[name] = convertListToSet(config.Security.Emails)
	}
	return emails
}

func loadProviders(conf Config) map[string]SecurityProvider {
	providers := make(map[string]SecurityProvider)
	for _, p := range conf.Security.Providers {
		providers[p.Name] = NewOAuth2Provider(p.Config, buildAuthorizedEmailByOrigins(conf))
	}
	return providers
}

// Check return true if process can continue or false if not needed. Error is returned when bad access
func (sa SecurityAccess) Check(w http.ResponseWriter, r *http.Request, wrapper ProxyWrapper, path string) (bool, error) {
	if !wrapper.security {
		return true, nil
	}
	token, err := sa.getJWT(r)
	if err != nil {
		sa.initConnect(w, wrapper, path, GetHost(r), buildContextURL(r))
		return false, nil
	}
	return sa.checkRights(token, wrapper, path, GetHost(r))
}

func buildContextURL(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return r.URL.Path[1:]
	}
	return r.URL.Path[1:] + "?" + r.URL.RawQuery
}

func (sa SecurityAccess) checkRights(token *jwt.Token, wrapper ProxyWrapper, path, domain string) (bool, error) {
	// If token is guest, Check wrapper enable guest and path is the good
	claims := token.Claims.(jwt.MapClaims)
	isGuest, existGuest := claims["guest"].(bool)
	scope, existScope := claims["scope"].(string)
	if existGuest && isGuest {
		if !wrapper.guest || !existScope || scope != path {
			return false, errors.New("no access here")
		}
	} else {
		// Check user email exist in listExistingKeys
		email, existEmail := claims["email"].(string)
		if !existEmail || !sa.Provider.IsEmailAuthorized(email, domain) {
			return false, errors.New("no access here")
		}
	}
	return true, nil
}

func (sa SecurityAccess) initConnect(w http.ResponseWriter, wrapper ProxyWrapper, path, domain, fullPath string) {
	if wrapper.guest {
		sa.showGuestSSOOptions(w, fullPath, domain)
	} else {
		sa.Provider.InitConnect(w, fullPath, domain)
	}
}

func (sa SecurityAccess) showGuestSSOOptions(w http.ResponseWriter, path, domain string) {
	w.Header().Set("Content-Type", "text/html")
	html := createTemplate(links{LinkGuest: fmt.Sprintf("/callback?kind=guest&state=%s", path), LinkSSO: sa.Provider.GenerateConnectionButton(path, domain)})
	w.Write(html)
}

func (sa SecurityAccess) getJWTCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(jwtCookieName)
	if err == nil {
		return cookie.Value, nil
	}
	return "", err
}

func (sa SecurityAccess) createJWT(email, scope string, isAdminByScope map[string]bool, isGuest bool) (string, error) {
	claims := jwt.MapClaims{
		"email": email,
		"guest": isGuest,
		"scope": scope,
	}
	// Create admin lists for origins
	for route, isAdmin := range isAdminByScope {
		claims[fmt.Sprintf("admin_%s", route)] = isAdmin
	}
	return sa.SignatureTool.SignToken(claims)
}

func (sa SecurityAccess) CheckAndConnectAsGuest(w http.ResponseWriter, wrapper ProxyWrapper, context string) bool {
	if !wrapper.security || !wrapper.guest {
		return false
	}
	return sa.SetJWT(w, "guest", context, map[string]bool{}, true) == nil
}

func (sa SecurityAccess) createJWTCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     jwtCookieName,
		Value:    value,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Path:     "/",
	})
}

func (sa SecurityAccess) SetJWT(w http.ResponseWriter, email, scope string, isAdminByScope map[string]bool, isGuest bool) error {
	token, err := sa.createJWT(email, scope, isAdminByScope, isGuest)
	if err != nil {
		return err
	}
	sa.createJWTCookie(w, token)
	return nil
}

func (sa SecurityAccess) IsConnected(r *http.Request) bool {
	_, err := sa.getJWT(r)
	return err == nil
}

func (sa SecurityAccess) getJWT(r *http.Request) (*jwt.Token, error) {
	// Check if jwt token exist in a cookie and is valid. Create by server during first connexion
	if token, err := sa.getJWTCookie(r); err == nil {
		return sa.SignatureTool.GetJWT(token)
	}
	return nil, errors.New("impossible to get jwt")
}
