package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"html/template"
	"net/http"
)

const jwtCookieName = "token"

var htmlTemplate = `
<html>
<head>
<title>Connexion page</title>
<style>
button > a {
	margin:20px;
	padding:10px;
	font-size:24px;
}
div {
	text-align:center;
	margin:10px;
}
body {
	margin-top:100px;
}
</style>
</head>
<body>
<div><button><a href="{{.LinkGuest}}">Connect as guest</a></button></div>
<div><button><a href="{{.LinkSSO}}">Connect as admin</a></button></div>
</body>
</html>
`

type SecurityProvider interface {
	InitConnect(w http.ResponseWriter, context string)
	GenerateConnectionButton(context string) string
	GetEmailFromAuthent(r *http.Request) (string, error)
	IsEmailAuthorized(email string) bool
	IsEmailAdmin(email string) bool
}

type SecurityAccess2 struct {
	enable           bool
	hs256SecretKey   string
	provider         SecurityProvider
	authorizedEmails []string
	adminEmails      []string
}

func NewSecurityAccess(conf Config) SecurityAccess2 {
	if conf.Security.Type == "" {
		return SecurityAccess2{enable: false}
	}
	s := SecurityAccess2{
		hs256SecretKey: conf.Security.JWTSecret,
		enable:         true,
	}
	switch conf.Security.Type {
	case basicSecurity:
	case oauth2Security:
		s.provider = NewOAuth2Provider(conf.Security.OAuth2)
	}
	return s
}

// check return true if process can continue or false if not needed. Error is returned when bad access
func (sa SecurityAccess2) check(w http.ResponseWriter, r *http.Request, wrapper proxyWrapper, path string) (bool, error) {
	if !wrapper.security {
		return true, nil
	}
	token, err := sa.getJWT(r)
	if err != nil {
		sa.initConnect(w, wrapper, path)
		return false, nil
	}
	return sa.checkRights(token, wrapper, path)
}

func (sa SecurityAccess2) checkRights(token *jwt.Token, wrapper proxyWrapper, path string) (bool, error) {
	// If token is guest, check wrapper enable guest and path is the good
	isGuest, existGuest := token.Claims.(jwt.MapClaims)["guest"].(bool)
	scope, existScope := token.Claims.(jwt.MapClaims)["scope"].(string)
	if existGuest && isGuest {
		if !wrapper.guest || !existScope || scope != path {
			return false, errors.New("no access here")
		}
	}
	return true, nil
}

func (sa SecurityAccess2) initConnect(w http.ResponseWriter, wrapper proxyWrapper, path string) {
	if wrapper.guest {
		sa.showGuestSSOOptions(w, path)
	} else {
		sa.provider.InitConnect(w, path)
	}
}

func (sa SecurityAccess2) showGuestSSOOptions(w http.ResponseWriter, path string) {
	w.Header().Set("Content-Type", "text/html")
	html := createTemplate(links{LinkGuest: fmt.Sprintf("/callback?kind=guest&state=%s", path), LinkSSO: sa.provider.GenerateConnectionButton(path)})
	w.Write(html)
}

type links struct {
	LinkGuest string
	LinkSSO   string
}

func createTemplate(links links) []byte {
	t, _ := template.New("buttons-tmpl").Parse(htmlTemplate)
	buf := bytes.NewBufferString("")
	if t.Execute(buf, links) != nil {
		return []byte{}
	}
	return buf.Bytes()
}

func (sa SecurityAccess2) getJWTCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(jwtCookieName)
	if err == nil {
		return cookie.Value, nil
	}
	return "", err
}

func (sa SecurityAccess2) createJWT(email, scope string, isAdmin, isGuest bool) (string, error) {
	claims := jwt.MapClaims{
		"email":    email,
		"is_admin": isAdmin,
		"guest":    isGuest,
		"scope":    scope,
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString([]byte(sa.hs256SecretKey))
}

func (sa SecurityAccess2) checkAndConnectAsGuest(w http.ResponseWriter, wrapper proxyWrapper, context string) bool {
	if !wrapper.security || !wrapper.guest {
		return false
	}
	return sa.setJWT(w, "guest", context, false, true) == nil
}

func (sa SecurityAccess2) createJWTCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     jwtCookieName,
		Value:    value,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
		Path:     "/",
	})
}

func (sa SecurityAccess2) setJWT(w http.ResponseWriter, email, scope string, isAdmin, isGuest bool) error {
	token, err := sa.createJWT(email, scope, isAdmin, isGuest)
	if err != nil {
		return err
	}
	sa.createJWTCookie(w, token)
	return nil
}

func (sa SecurityAccess2) isConnected(r *http.Request) bool {
	_, err := sa.getJWT(r)
	return err == nil
}

func (sa SecurityAccess2) getJWT(r *http.Request) (*jwt.Token, error) {
	// Check if jwt token exist in a cookie and is valid. Create by server during first connexion
	if token, err := sa.getJWTCookie(r); err == nil {
		return jwt.Parse(token, func(token *jwt.Token) (interface{}, error) { return []byte(sa.hs256SecretKey), nil })
	}
	return nil, errors.New("impossible to get jwt")
}
