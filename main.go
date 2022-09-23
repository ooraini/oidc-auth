package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const prefix = "/auth"
const SessionCookieName = "oidc_auth"

var (
	provider *oidc.Provider
	config   oauth2.Config
	verifier *oidc.IDTokenVerifier
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
	var x interface{} = nil
	s, ok := x.(string)
	if ok {
		println(s)
	}
	var err error
	issuer := getEnvOrDie("ISSUER")

	if getEnvOrDefault("INSECURE_SKIP_VERIFY", "false") == "true" {
		t := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		http.DefaultClient = &http.Client{Transport: t}
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
		RedirectURL:  getEnvOrDie("REDIRECT_URL"),
		Scopes:       strings.Split(scopes, " "),
	}

	verifier = provider.Verifier(&oidc.Config{ClientID: config.ClientID})

	http.HandleFunc(prefix+"/login", login)
	http.HandleFunc(prefix+"/logout", logout)
	http.HandleFunc(prefix+"/callback", callback)
	http.HandleFunc(prefix+"/decisions", decide)
	http.HandleFunc("/", http.NotFound)
	err = http.ListenAndServe(":"+getEnvOrDefault("PORT", "8080"), nil)
	if err != nil {
		log.Fatalln("unable to listen", err)
	}
}

func logout(rw http.ResponseWriter, req *http.Request) {
	clearCookie(rw, SessionCookieName)
	infoS(req, "clearing session", http.StatusFound)
	http.Redirect(rw, req, "/", http.StatusFound)
}

func info(req *http.Request, message string) {
	log.Printf("%s - %s %s %s\n", req.Host, req.Method, req.URL.Path, message)
	log.Printf("%s - %s %s %s\n", req.RemoteAddr, req.Method, req.URL.Path, message)
}

func infoS(req *http.Request, message string, status int) {
	log.Printf("%s - %s %s %s - %s\n", req.Host, req.Method, req.URL.Path, message, http.StatusText(status))
	log.Printf("%s - %s %s %s - %s\n", req.RemoteAddr, req.Method, req.URL.Path, message, http.StatusText(status))
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

	subClaim := claims["sub"]
	nameClaim := claims["name"]
	emailClaim := claims["email"]
	preferredUsernameClaim := claims["preferred_username"]
	groupsClaim := claims["groups"]

	rw.Header().Set("X-Auth-Request-Subject", subClaim.(string))

	if name, ok := nameClaim.(string); ok {
		rw.Header().Set("X-Auth-Request-User", name)
	}

	userEmail := ""
	if email, ok := emailClaim.(string); ok {
		userEmail = email
		rw.Header().Set("X-Auth-Request-Email", email)
	}

	if preferredUsername, ok := preferredUsernameClaim.(string); ok {
		rw.Header().Set("X-Auth-Request-Preferred-Username", preferredUsername)
	}

	var userGroups []string
	if groups, ok := groupsClaim.([]interface{}); ok {
		for _, group := range groups {
			if g, ok := group.(string); ok {
				userGroups = append(userGroups, g)
			}
		}
		rw.Header().Set("X-Auth-Request-Groups", strings.Join(userGroups, ","))
	}

	rw.Header().Set("Authorization", "Bearer "+rawIdToken)

	allow := true

	queryParams := req.URL.Query()
	allowedGroups := queryParams.Get("allowed_groups")
	allowedEmails := queryParams.Get("allowed_emails")

	if allowedGroups != "" {
		allow = false
		for _, group := range strings.Split(allowedGroups, ",") {
			if contains(group, userGroups) {
				allow = true
				info(req, "user in allowed group '"+group+"'")
			}
		}
	}

	if allowedEmails != "" {
		allow = false
		for _, email := range strings.Split(allowedEmails, ",") {
			if userEmail == email {
				allow = true
				info(req, "user email in allowed emails")
				break
			}
		}
	}

	var status int
	if allow {
		status = http.StatusOK
	} else {
		status = http.StatusForbidden
	}

	rw.WriteHeader(status)
	info(req, http.StatusText(status))
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

	token, err := config.Exchange(req.Context(), code)
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
		SameSite: http.SameSiteStrictMode,
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

	http.SetCookie(rw, &http.Cookie{
		Name:     "state",
		Value:    state,
		Path:     "/",
		Expires:  time.Now().Add(time.Minute * 10),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(rw, &http.Cookie{
		Name:     "rd",
		Value:    rd,
		Path:     "/",
		Expires:  time.Now().Add(time.Minute * 10),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	clearCookie(rw, SessionCookieName)

	infoS(req, "redirecting to authorization server", http.StatusFound)
	http.Redirect(rw, req, config.AuthCodeURL(state), http.StatusFound)
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
