package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/oauth2"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const prefix = "/auth"

var (
	provider *oidc.Provider
	config   oauth2.Config
	verifier *oidc.IDTokenVerifier
	secret   [32]byte
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

	secretBytes, err := hex.DecodeString(getEnvOrDie("COOKIE_SECRET"))
	copy(secret[:], secretBytes)

	if err != nil {
		log.Fatalln("unable to decode cookie secret", err)
	}

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
	http.HandleFunc(prefix+"/decide", decide)
	http.HandleFunc("/", http.NotFound)
	err = http.ListenAndServe(":"+getEnvOrDefault("PORT", "8080"), nil)
	if err != nil {
		log.Fatalln("unable to listen", err)
	}
}

func logout(rw http.ResponseWriter, req *http.Request) {
	clearCookie(rw, "oidc-auth")
	http.Redirect(rw, req, "/", http.StatusFound)
}

func decide(rw http.ResponseWriter, req *http.Request) {
	sessionCookie, err := req.Cookie("oidc-auth")

	if err != nil {
		log.Println("decide: no session cookie")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	encoded := []byte(sessionCookie.Value)

	encrypted := make([]byte, base64.URLEncoding.DecodedLen(len(encoded)))
	_, err = base64.URLEncoding.Decode(encrypted, encoded)

	if err != nil {
		log.Println("decide: invalid session cookie", err)
		clearCookie(rw, "oidc-auth")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	var decryptNonce [24]byte
	copy(decryptNonce[:], encrypted[:24])
	decrypted, ok := secretbox.Open(nil, encrypted[24:], &decryptNonce, &secret)
	if !ok {
		log.Println("decide: unable to decrypt session cookie")
		clearCookie(rw, "oidc-auth")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	rawIdToken := string(decrypted)
	idToken, err := verifier.Verify(req.Context(), rawIdToken)
	if err != nil {
		log.Println("decide: invalid token", err)
		clearCookie(rw, "oidc-auth")
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	var claims map[string]interface{}
	if err = idToken.Claims(&claims); err != nil {
		log.Println("decide: no claims", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	subClaim := claims["sub"]
	nameClaim := claims["name"]
	emailClaim := claims["email"]
	preferredUsernameClaim := claims["preferred_username"]
	groupsClaim := claims["groups"]

	rw.Header().Set("X-Forwarded-Subject", subClaim.(string))

	if name, ok := nameClaim.(string); ok {
		rw.Header().Set("X-Forwarded-User", name)
	}

	if email, ok := emailClaim.(string); ok {
		rw.Header().Set("X-Forwarded-Email", email)
	}

	if preferredUsername, ok := preferredUsernameClaim.(string); ok {
		rw.Header().Set("X-Forwarded-Preferred-Username", preferredUsername)
	}

	if groups, ok := groupsClaim.([]interface{}); ok {
		var stringGroups []string
		for _, group := range groups {
			if g, ok := group.(string); ok {
				stringGroups = append(stringGroups, g)
			}
		}
		rw.Header().Set("X-Forwarded-Groups", strings.Join(stringGroups, ","))
	}

	rw.Header().Set("Authorization", "Bearer "+rawIdToken)

	log.Println("decide: allow " + subClaim.(string))
	rw.WriteHeader(http.StatusOK)
}

func callback(rw http.ResponseWriter, req *http.Request) {
	_, err := req.Cookie("oidc-auth")
	if err != nil {
		log.Println("callback: called with an existing session. 403")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	state, err := req.Cookie("state")
	if err != nil {
		log.Println("callback: no state cookie")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	rd, err := req.Cookie("rd")
	if err != nil {
		log.Println("callback: no rd cookie")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	clearCookie(rw, "state")
	clearCookie(rw, "rd")

	queryParams := req.URL.Query()

	if state.Value != queryParams.Get("state") {
		log.Println("callback: state mismatch")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	code := queryParams.Get("code")
	if code == "" {
		log.Println("callback: no code")
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	token, err := config.Exchange(req.Context(), code)
	if err != nil {
		log.Println("callback: code exchange failed", err)
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	rawIdToken, ok := token.Extra("id_token").(string)
	if !ok {
		log.Println("callback: no id_token", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, err = verifier.Verify(req.Context(), rawIdToken)
	if err != nil {
		log.Println("callback: invalid token", err)
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		log.Println("callback: rand", err)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	encrypted := secretbox.Seal(nonce[:], []byte(rawIdToken), &nonce, &secret)
	encoded := make([]byte, base64.URLEncoding.EncodedLen(len(encrypted)))
	base64.URLEncoding.Encode(encoded, encrypted)

	http.SetCookie(rw, &http.Cookie{
		Name:     "oidc-auth",
		Value:    string(encoded),
		Path:     prefix,
		Expires:  time.Now().Add(time.Hour * 24),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	http.Redirect(rw, req, rd.Value, http.StatusFound)
}

func login(rw http.ResponseWriter, req *http.Request) {
	_, err := req.Cookie("oidc-auth")
	if err != nil {
		log.Println("login: called with an existing session. 403")
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	queryParams := req.URL.Query()
	rd := queryParams.Get("rd")
	if rd == "" {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	stateCookie, err := req.Cookie("state")
	if err != nil {
		left := stateCookie.Expires.Sub(time.Now())
		if left > (time.Minute*9)+time.Second*50 {
			log.Println("login: another attempt too soon. 401")
			rw.WriteHeader(http.StatusUnauthorized)
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
		Path:     prefix,
		Expires:  time.Now().Add(time.Minute * 10),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.SetCookie(rw, &http.Cookie{
		Name:     "rd",
		Value:    rd,
		Path:     prefix,
		Expires:  time.Now().Add(time.Minute * 10),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	clearCookie(rw, "oidc-auth")

	http.Redirect(rw, req, config.AuthCodeURL(state), http.StatusFound)
}

func clearCookie(rw http.ResponseWriter, name string) {
	http.SetCookie(rw, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     prefix,
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
