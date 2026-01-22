package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/url"
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
	Addr         string                         `yaml:"addr"`
	CAKey        string                         `yaml:"ca_key"`
	CertValidity string                         `yaml:"cert_validity"`
	ClientID     string                         `yaml:"client_id"`
	ClientSecret string                         `yaml:"client_secret"`
	RedirectURL  string                         `yaml:"redirect_url"`
	Users        map[string]map[string][]string `yaml:"users"` // email -> role -> principals
	TLS          *TLSConfig                     `yaml:"tls,omitempty"`
}

type TLSConfig struct {
	CertFile string `yaml:"cert"`
	KeyFile  string `yaml:"key"`
}

var (
	config       Config
	caSigner     ssh.Signer
	oauth2Config *oauth2.Config
	oidcVerifier *oidc.IDTokenVerifier
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "init":
			cmdInit(os.Args[2:])
			return
		}
	}

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
	http.HandleFunc("/pubkey", handlePubkey)
	http.HandleFunc("/health", handleHealth)

	if config.TLS != nil && config.TLS.CertFile != "" && config.TLS.KeyFile != "" {
		log.Printf("Server starting on https://%s", config.Addr)
		log.Fatal(http.ListenAndServeTLS(config.Addr, config.TLS.CertFile, config.TLS.KeyFile, nil))
	} else {
		log.Printf("Server starting on http://%s", config.Addr)
		log.Fatal(http.ListenAndServe(config.Addr, nil))
	}
}

func cmdInit(args []string) {
	keyPath := "ca_key"
	if len(args) > 0 {
		keyPath = args[0]
	}
	pubKeyPath := keyPath + ".pub"

	if _, err := os.Stat(keyPath); err == nil {
		fmt.Printf("Error: %s already exists\n", keyPath)
		os.Exit(1)
	}
	if _, err := os.Stat(pubKeyPath); err == nil {
		fmt.Printf("Error: %s already exists\n", pubKeyPath)
		os.Exit(1)
	}

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Error generating key pair: %v\n", err)
		os.Exit(1)
	}

	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		fmt.Printf("Error creating SSH public key: %v\n", err)
		os.Exit(1)
	}

	pemBlock, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		fmt.Printf("Error marshaling private key: %v\n", err)
		os.Exit(1)
	}
	privKeyBytes := pem.EncodeToMemory(pemBlock)

	if err := os.WriteFile(keyPath, privKeyBytes, 0600); err != nil {
		fmt.Printf("Error writing private key: %v\n", err)
		os.Exit(1)
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(sshPubKey)
	if err := os.WriteFile(pubKeyPath, pubKeyBytes, 0644); err != nil {
		fmt.Printf("Error writing public key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("CA key pair generated:\n")
	fmt.Printf("  Private key: %s\n", keyPath)
	fmt.Printf("  Public key:  %s\n", pubKeyPath)
}

// State encodes: randomBytes_cliPort_role_pubkey
func handleLogin(w http.ResponseWriter, r *http.Request) {
	cliPort := r.URL.Query().Get("cli_port")
	role := r.URL.Query().Get("role")
	pubkey := r.URL.Query().Get("pubkey")

	// Build state: random_port_role_pubkey
	state := generateState()
	if cliPort != "" {
		state += "_" + cliPort
	} else {
		state += "_"
	}
	state += "_" + role
	state += "_" + pubkey

	authURL := oauth2Config.AuthCodeURL(state)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing code", http.StatusBadRequest)
		return
	}

	// Parse state: random_port_role_pubkey
	state := r.URL.Query().Get("state")
	parts := strings.SplitN(state, "_", 4)
	var cliPort, role, pubkeyB64 string
	if len(parts) >= 2 {
		cliPort = parts[1]
	}
	if len(parts) >= 3 {
		role = parts[2]
	}
	if len(parts) >= 4 {
		pubkeyB64 = parts[3]
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

	// Verify token and get email
	idToken, err := oidcVerifier.Verify(ctx, rawIDToken)
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

	// Check user authorization
	userRoles, ok := config.Users[claims.Email]
	if !ok {
		http.Error(w, "User not authorized", http.StatusForbidden)
		return
	}

	// Use "default" role if none specified
	if role == "" {
		role = "default"
	}

	// Get principals for the requested role
	principals, ok := userRoles[role]
	if !ok {
		// List available roles for the user
		var availableRoles []string
		for r := range userRoles {
			availableRoles = append(availableRoles, r)
		}
		http.Error(w, fmt.Sprintf("Role '%s' not available. Available roles: %s", role, strings.Join(availableRoles, ", ")), http.StatusForbidden)
		return
	}

	if len(principals) == 0 {
		http.Error(w, "No principals for role", http.StatusForbidden)
		return
	}

	// Sign certificate if public key provided
	var certB64 string
	if pubkeyB64 != "" {
		pubkeyBytes, err := base64.RawURLEncoding.DecodeString(pubkeyB64)
		if err != nil {
			http.Error(w, "Invalid public key encoding", http.StatusBadRequest)
			return
		}

		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubkeyBytes)
		if err != nil {
			http.Error(w, "Invalid public key", http.StatusBadRequest)
			return
		}

		cert, err := signCertificate(pubKey, claims.Email, role, principals)
		if err != nil {
			http.Error(w, "Failed to sign certificate", http.StatusInternalServerError)
			return
		}
		certB64 = base64.RawURLEncoding.EncodeToString(ssh.MarshalAuthorizedKey(cert))
	}

	// Redirect to CLI or show token
	if cliPort != "" {
		redirectURL := fmt.Sprintf("http://localhost:%s/callback?token=%s&role=%s&cert=%s",
			cliPort, url.QueryEscape(rawIDToken), url.QueryEscape(role), certB64)
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		return
	}

	// Device flow: display info
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>VSH Login</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px;">
<h2>Login Successful</h2>
<p>Logged in as: %s</p>
<p>Role: %s</p>
<p>Principals: %s</p>
<p style="color: #666;">You can close this window.</p>
</body>
</html>`, claims.Email, role, strings.Join(principals, ", "))
}

func signCertificate(pubKey ssh.PublicKey, email, role string, principals []string) (*ssh.Certificate, error) {
	duration, err := time.ParseDuration(config.CertValidity)
	if err != nil {
		duration = 8 * time.Hour
	}

	now := time.Now()
	cert := &ssh.Certificate{
		Key:             pubKey,
		Serial:          uint64(now.UnixNano()),
		CertType:        ssh.UserCert,
		KeyId:           fmt.Sprintf("%s@%s", email, role),
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
		return nil, err
	}

	return cert, nil
}

func handlePubkey(w http.ResponseWriter, r *http.Request) {
	pubKey := caSigner.PublicKey()
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "%s", ssh.MarshalAuthorizedKey(pubKey))
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok","service":"voussh"}`)
}

func generateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
