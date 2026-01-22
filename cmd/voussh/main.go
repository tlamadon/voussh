package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Addr         string              `yaml:"addr"`
	CAKey        string              `yaml:"ca_key"`
	CertValidity string              `yaml:"cert_validity"`
	ClientID     string              `yaml:"client_id"`
	ClientSecret string              `yaml:"client_secret"`
	RedirectURL  string              `yaml:"redirect_url"`
	Groups       map[string]Group    `yaml:"groups"`
	Users        map[string][]string `yaml:"users"`
}

type Group struct {
	Principals []string `yaml:"principals"`
}

type SignRequest struct {
	PublicKey string `json:"public_key"`
}

var (
	config      Config
	caSigner    ssh.Signer
	oauth2Config *oauth2.Config
	oidcVerifier *oidc.IDTokenVerifier
)

func main() {
	configData, err := os.ReadFile("config.yaml")
	if err != nil {
		log.Fatal("Failed to read config.yaml:", err)
	}

	if err := yaml.Unmarshal(configData, &config); err != nil {
		log.Fatal("Failed to parse config:", err)
	}

	caKeyData, err := os.ReadFile(config.CAKey)
	if err != nil {
		log.Fatal("Failed to read CA key:", err)
	}

	caSigner, err = ssh.ParsePrivateKey(caKeyData)
	if err != nil {
		log.Fatal("Failed to parse CA key:", err)
	}

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		log.Fatal("Failed to create OIDC provider:", err)
	}

	oauth2Config = &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  config.RedirectURL,
		Endpoint:     google.Endpoint,
		Scopes:       []string{oidc.ScopeOpenID, "email"},
	}

	oidcVerifier = provider.Verifier(&oidc.Config{
		ClientID: config.ClientID,
	})

	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/sign", handleSign)
	http.HandleFunc("/pubkey", handlePubkey)
	http.HandleFunc("/userinfo", handleUserInfo)

	log.Printf("Server starting on %s", config.Addr)
	log.Fatal(http.ListenAndServe(config.Addr, nil))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	state := generateState()
	url := oauth2Config.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing code", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Failed to exchange code", http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprint(w, rawIDToken)
}

func handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Missing or invalid authorization", http.StatusUnauthorized)
		return
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	idToken, err := oidcVerifier.Verify(r.Context(), tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	var claims struct {
		Email string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Failed to parse claims", http.StatusInternalServerError)
		return
	}

	groups, ok := config.Users[claims.Email]
	if !ok {
		http.Error(w, "User not authorized", http.StatusForbidden)
		return
	}

	var principals []string
	for _, group := range groups {
		if g, exists := config.Groups[group]; exists {
			principals = append(principals, g.Principals...)
		}
	}

	if len(principals) == 0 {
		http.Error(w, "No principals for user", http.StatusForbidden)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var req SignRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		http.Error(w, "Invalid public key", http.StatusBadRequest)
		return
	}

	duration, err := time.ParseDuration(config.CertValidity)
	if err != nil {
		duration = 8 * time.Hour
	}

	now := time.Now()
	cert := &ssh.Certificate{
		Key:             pubKey,
		Serial:          0,
		CertType:        ssh.UserCert,
		KeyId:           claims.Email,
		ValidPrincipals: principals,
		ValidAfter:      uint64(now.Add(-5 * time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(duration).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-pty":              "",
				"permit-agent-forwarding": "",
				"permit-user-rc":          "",
			},
		},
	}

	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		http.Error(w, "Failed to sign certificate", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "%s", ssh.MarshalAuthorizedKey(cert))
}

func handlePubkey(w http.ResponseWriter, r *http.Request) {
	pubKey := caSigner.PublicKey()
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "%s", ssh.MarshalAuthorizedKey(pubKey))
}

func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func handleUserInfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Missing or invalid authorization", http.StatusUnauthorized)
		return
	}
	tokenString := strings.TrimPrefix(authHeader, "Bearer ")

	idToken, err := oidcVerifier.Verify(r.Context(), tokenString)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	var claims struct {
		Email string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Failed to parse claims", http.StatusInternalServerError)
		return
	}

	groups, ok := config.Users[claims.Email]
	if !ok {
		http.Error(w, "User not authorized", http.StatusForbidden)
		return
	}

	userInfo := map[string]interface{}{
		"email":  claims.Email,
		"groups": groups,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}