package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jmespath/go-jmespath"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	prefix            = "/auth"
	SessionCookieName = "oidc_auth"
	headerPrefix      = "HEADER_"
)

var (
	provider        *oidc.Provider
	config          oauth2.Config
	verifier        *oidc.IDTokenVerifier
	sameSite        http.SameSite
	jmespathHeaders map[string]*jmespath.JMESPath
	defaultHeaders  string
)

func getEnvOrDie(key string) string {
	val := os.Getenv(key)
	if val == "" {
		log.Fatalf("missing environemnt variable '%s'", key)
	}
	return val
}

func getEnvOrDefault(key, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	return val
}

func main() {
	var err error
	issuer := getEnvOrDie("ISSUER")

	if getEnvOrDefault("INSECURE_SKIP_VERIFY", "false") == "true" {
		t := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		http.DefaultClient = &http.Client{Transport: t}
	}

	ss := getEnvOrDefault("SAMESITE", "lax")
	if strings.EqualFold(ss, "lax") {
		sameSite = http.SameSiteLaxMode
	} else if strings.EqualFold(ss, "strict") {
		sameSite = http.SameSiteStrictMode
	} else if strings.EqualFold(ss, "none") {
		sameSite = http.SameSiteNoneMode
	} else {
		log.Fatalf("SAMESITE '%s' not supported\n", ss)
	}

	defaultHeaders = getEnvOrDefault("DEFAULT_HEADERS", "")

	jmespathHeaders, err = loadHeaderExprs()
	if err != nil {
		log.Fatalln("unable to load JMESPATH expressions", err)
	}

	scopes := getEnvOrDefault("SCOPES", "openid profile email groups")

	provider, err = oidc.NewProvider(context.Background(), issuer)
	if err != nil {
		log.Fatalln("unable to create OIDC provider", err)
	}

	config = oauth2.Config{
		ClientID:     getEnvOrDie("CLIENT_ID"),
		ClientSecret: getEnvOrDie("CLIENT_SECRET"),
		Endpoint:     provider.Endpoint(),
		Scopes:       strings.Split(scopes, " "),
	}

	verifier = provider.Verifier(&oidc.Config{ClientID: config.ClientID})

	http.HandleFunc(prefix+"/login", login)
	http.HandleFunc(prefix+"/logout", logout)
	http.HandleFunc(prefix+"/callback", callback)
	http.HandleFunc(prefix+"/decisions", decide)
	http.HandleFunc("/", http.NotFound)
	err = http.ListenAndServe(":"+getEnvOrDefault("PORT", "80"), nil)
	if err != nil {
		log.Fatalln("unable to listen", err)
	}
}

func loadHeaderExprs() (map[string]*jmespath.JMESPath, error) {
	result := map[string]*jmespath.JMESPath{}

	for _, pair := range os.Environ() {
		prefixedName, value, _ := strings.Cut(pair, "=")

		if strings.HasPrefix(prefixedName, headerPrefix) {
			name := prefixedName[len(headerPrefix):]
			compiled, err := jmespath.Compile(value)
			if err != nil {
				log.Printf("unable to parse JMESTPATH expression '%s'\n", value)
				return nil, err
			} else {
				result[name] = compiled
				log.Printf("header '%s' is avalible\n", name)
			}
		}
	}

	return result, nil
}

func logout(rw http.ResponseWriter, req *http.Request) {
	clearCookie(rw, SessionCookieName)
	infoS(req, "clearing session", http.StatusFound)
	http.Redirect(rw, req, "/", http.StatusFound)
}

func infoS(req *http.Request, message string, status int) {
	log.Printf("%s - %s %s %s - %s\n", req.Host, req.Method, req.URL.Path, message, http.StatusText(status))
}

func decide(rw http.ResponseWriter, req *http.Request) {
	sessionCookie, err := req.Cookie(SessionCookieName)
	if err != nil {
		infoS(req, "no session cookie", http.StatusUnauthorized)
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	rawIdToken := sessionCookie.Value
	idToken, err := verifier.Verify(req.Context(), rawIdToken)
	if err != nil {
		infoS(req, "verify failed : "+err.Error(), http.StatusUnauthorized)
		clearCookie(rw, SessionCookieName)
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	var claims map[string]interface{}
	if err = idToken.Claims(&claims); err != nil {
		infoS(req, "no claims in token", http.StatusInternalServerError)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	emailClaim := claims["email"]
	groupsClaim := claims["groups"]

	userEmail := ""
	if email, ok := emailClaim.(string); ok {
		userEmail = email
	}

	var userGroups []string
	if groups, ok := groupsClaim.([]interface{}); ok {
		for _, group := range groups {
			if g, ok := group.(string); ok {
				userGroups = append(userGroups, g)
			}
		}
	}

	queryParams := req.URL.Query()
	headers := queryParams.Get("headers")
	allowedGroups := queryParams.Get("allowed_groups")
	allowedEmails := queryParams.Get("allowed_emails")

	if headers == "" {
		headers = defaultHeaders
	}

	if allowedGroups != "" {
		allowed := false
		for _, group := range strings.Split(allowedGroups, ",") {
			if contains(group, userGroups) {
				allowed = true
				break
			}
		}
		if !allowed {
			infoS(req, fmt.Sprintf("user '%s' not in allowed groups", userEmail), http.StatusForbidden)
			rw.WriteHeader(http.StatusForbidden)
			return
		}
	}

	if allowedEmails != "" {
		if !contains(userEmail, strings.Split(allowedEmails, ",")) {
			infoS(req, fmt.Sprintf("user '%s' not in allowed emails", userEmail), http.StatusForbidden)
			rw.WriteHeader(http.StatusForbidden)
			return
		}
	}

	idTokenJson, err := base64.RawURLEncoding.DecodeString(strings.Split(rawIdToken, ".")[1])
	if err != nil {
		infoS(req, "token payload", http.StatusInternalServerError)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	var data map[string]interface{}
	if json.Unmarshal(idTokenJson, &data) != nil {
		infoS(req, "unmarshal", http.StatusInternalServerError)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	data["raw"] = rawIdToken

	for _, header := range strings.Split(headers, ",") {
		expr := jmespathHeaders[header]
		if expr == nil {
			continue
		}

		search, err := expr.Search(data)
		if err != nil {
			continue
		}
		if result, ok := search.(string); ok {
			rw.Header().Set(header, result)
		}
	}

	rw.WriteHeader(http.StatusOK)
	infoS(req, userEmail, http.StatusOK)
}

func callback(rw http.ResponseWriter, req *http.Request) {
	state, err := req.Cookie("state")
	if err != nil {
		infoS(req, "no state cookie", http.StatusBadRequest)
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	rd, err := req.Cookie("rd")
	if err != nil {
		infoS(req, "no rd cookie", http.StatusBadRequest)
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	clearCookie(rw, "state")
	clearCookie(rw, "rd")

	queryParams := req.URL.Query()

	if state.Value != queryParams.Get("state") {
		infoS(req, "state mismatch", http.StatusBadRequest)
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	code := queryParams.Get("code")
	if code == "" {
		infoS(req, "no code", http.StatusBadRequest)
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	rdUrl, err := url.Parse(rd.Value)
	if err != nil {
		infoS(req, "invalid rd url : "+err.Error(), http.StatusBadRequest)
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	redirectUrl := fmt.Sprintf("%s://%s%s/callback", rdUrl.Scheme, rdUrl.Host, prefix)

	token, err := config.Exchange(req.Context(), code, oauth2.SetAuthURLParam("redirect_uri", redirectUrl))
	if err != nil {
		infoS(req, "code exchange error : "+err.Error(), http.StatusUnauthorized)
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	rawIdToken, ok := token.Extra("id_token").(string)
	if !ok {
		infoS(req, "no id_token", http.StatusInternalServerError)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, err = verifier.Verify(req.Context(), rawIdToken)
	if err != nil {
		infoS(req, "invalid token : "+err.Error(), http.StatusUnauthorized)
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	http.SetCookie(rw, &http.Cookie{
		Name:     SessionCookieName,
		Value:    rawIdToken,
		Expires:  time.Now().Add(time.Hour * 24),
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: sameSite,
	})

	infoS(req, "redirecting to '"+rd.Value+"'", http.StatusFound)
	http.Redirect(rw, req, rd.Value, http.StatusFound)
}

func login(rw http.ResponseWriter, req *http.Request) {
	queryParams := req.URL.Query()
	rd := queryParams.Get("rd")
	if rd == "" {
		host := req.Header.Get("X-Forwarded-Host")
		proto := req.Header.Get("X-Forwarded-Proto")
		port := req.Header.Get("X-Forwarded-Port")

		if host != "" {
			builder := strings.Builder{}
			if proto == "https" || proto == "http" {
				builder.WriteString(proto)
			} else {
				builder.WriteString("https")
			}

			builder.WriteString("://")
			builder.WriteString(host)

			if p, err := strconv.Atoi(port); err != nil && p > 1 && p < 65535 {
				builder.WriteString(":")
				builder.WriteString(port)
			}
			rd = builder.String()
		} else {
			host = req.Host
			if host == "" {
				infoS(req, "could not determine the redirect URL", http.StatusBadRequest)
				rw.WriteHeader(http.StatusBadRequest)
				return
			}
			rd = "https://" + host
		}
	}

	stateCookie, err := req.Cookie("state")
	if err != nil && stateCookie != nil {
		left := stateCookie.Expires.Sub(time.Now())
		if left > (time.Minute*9)+time.Second*50 {
			infoS(req, "consecutive logins too soon", http.StatusBadRequest)
			rw.WriteHeader(http.StatusBadGateway)
			return
		}
	}

	state, err := generateRandomState()
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	rdUrl, err := url.Parse(rd)
	if err != nil {
		infoS(req, "invalid rd url : "+err.Error(), http.StatusBadRequest)
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	redirectUrl := fmt.Sprintf("%s://%s%s/callback", rdUrl.Scheme, rdUrl.Host, prefix)

	http.SetCookie(rw, &http.Cookie{
		Name:     "state",
		Value:    state,
		Path:     "/",
		Expires:  time.Now().Add(time.Minute * 10),
		Secure:   true,
		HttpOnly: true,
		SameSite: sameSite,
	})
	http.SetCookie(rw, &http.Cookie{
		Name:     "rd",
		Value:    rd,
		Path:     "/",
		Expires:  time.Now().Add(time.Minute * 10),
		Secure:   true,
		HttpOnly: true,
		SameSite: sameSite,
	})

	clearCookie(rw, SessionCookieName)

	infoS(req, "redirecting to authorization server", http.StatusFound)
	http.Redirect(rw, req, config.AuthCodeURL(state, oauth2.SetAuthURLParam("redirect_uri", redirectUrl)), http.StatusFound)
}

func clearCookie(rw http.ResponseWriter, name string) {
	http.SetCookie(rw, &http.Cookie{
		Name:     name,
		Path:     "/",
		Value:    "",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	})
}

func generateRandomState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	state := base64.URLEncoding.EncodeToString(b)

	return state, nil
}

func contains(s string, slice []string) bool {
	for _, item := range slice {
		if s == item {
			return true
		}
	}
	return false

}
