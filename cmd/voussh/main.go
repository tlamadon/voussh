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
	"sync"
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

type sessionData struct {
	cliPort string
	role    string
	pubkey  string
}

var (
	config       Config
	caSigner     ssh.Signer
	oauth2Config *oauth2.Config
	oidcVerifier *oidc.IDTokenVerifier
	sessions     = make(map[string]*sessionData)
	sessionsMu   sync.RWMutex
)

func main() {
	configFile := "config.yaml"

	// Parse command-line arguments
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch arg {
		case "init":
			cmdInit(os.Args[i+1:])
			return
		case "--config", "-c":
			if i+1 < len(os.Args) {
				configFile = os.Args[i+1]
				i++ // Skip next arg as it's the config file path
			} else {
				log.Fatal("--config requires a file path")
			}
		case "--help", "-h":
			fmt.Println("Usage: voussh [options]")
			fmt.Println("       voussh init [keyfile]")
			fmt.Println()
			fmt.Println("Options:")
			fmt.Println("  --config, -c <file>  Path to config file (default: config.yaml)")
			fmt.Println("  --help, -h           Show this help message")
			fmt.Println()
			fmt.Println("Commands:")
			fmt.Println("  init [keyfile]       Generate a new CA key pair")
			os.Exit(0)
		}
	}

	configData, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Failed to read config file %s: %v", configFile, err)
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

	// Use the redirect URL as configured (no automatic adjustment)
	redirectURL := config.RedirectURL
	if config.TLS != nil && config.TLS.CertFile != "" && config.TLS.KeyFile != "" {
		// Just log a warning if there's a potential mismatch
		if strings.HasPrefix(redirectURL, "http://") {
			log.Printf("WARNING: TLS enabled but redirect URL uses http://. Make sure this is registered in Google OAuth.")
		}
	}

	oauth2Config = &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     google.Endpoint,
		Scopes:       []string{oidc.ScopeOpenID, "email"},
	}

	clientIDPreview := config.ClientID
	if len(clientIDPreview) > 20 {
		clientIDPreview = clientIDPreview[:20] + "..."
	}
	log.Printf("OAuth configured with ClientID: %s (length: %d)", clientIDPreview, len(config.ClientID))
	log.Printf("Using redirect URL: %s", redirectURL)

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

func handleLogin(w http.ResponseWriter, r *http.Request) {
	// Log the full request URL for debugging
	log.Printf("Login request URL: %s", r.URL.String())
	log.Printf("Login request query params: %v", r.URL.Query())

	cliPort := r.URL.Query().Get("cli_port")
	role := r.URL.Query().Get("role")
	pubkey := r.URL.Query().Get("pubkey")

	log.Printf("Extracted params - cliPort: '%s', role: '%s', pubkey length: %d", cliPort, role, len(pubkey))

	// Generate a short state token and store session data server-side
	state := generateState()

	sessionsMu.Lock()
	sessions[state] = &sessionData{
		cliPort: cliPort,
		role:    role,
		pubkey:  pubkey,
	}
	sessionCount := len(sessions)
	sessionsMu.Unlock()

	// Clean up old sessions after 10 minutes
	go func() {
		time.Sleep(10 * time.Minute)
		sessionsMu.Lock()
		delete(sessions, state)
		sessionsMu.Unlock()
	}()

	log.Printf("Stored session with state: %s (total sessions: %d)", state, sessionCount)
	log.Printf("Session data stored - cliPort: '%s', role: '%s', pubkey length: %d", cliPort, role, len(pubkey))

	authURL := oauth2Config.AuthCodeURL(state)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing code", http.StatusBadRequest)
		return
	}

	// Retrieve session data from state
	state := r.URL.Query().Get("state")
	log.Printf("Callback state received: %s", state)

	// Debug: List all current sessions
	sessionsMu.RLock()
	log.Printf("Current sessions count: %d", len(sessions))
	for k := range sessions {
		log.Printf("  Session state: %s", k)
	}
	session, ok := sessions[state]
	sessionsMu.RUnlock()

	if !ok {
		http.Error(w, "Invalid or expired state", http.StatusBadRequest)
		log.Printf("Session not found for state: %s (looking in %d sessions)", state, len(sessions))
		return
	}

	// Clean up session
	sessionsMu.Lock()
	delete(sessions, state)
	sessionsMu.Unlock()

	cliPort := session.cliPort
	role := session.role
	pubkeyB64 := session.pubkey

	log.Printf("Retrieved from session - cliPort: %s, role: %s, pubkey length: %d", cliPort, role, len(pubkeyB64))

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
		log.Printf("Redirecting to CLI at: %s", redirectURL)
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		return
	}
	log.Printf("No CLI port provided, showing device flow")

	// Device flow: display certificate for manual copy
	w.Header().Set("Content-Type", "text/html")
	certDisplay := ""
	if certB64 != "" {
		if certData, err := base64.RawURLEncoding.DecodeString(certB64); err == nil {
			certDisplay = fmt.Sprintf(`
<div style="margin-top: 20px; padding: 15px; background: #f5f5f5; border-radius: 5px;">
<h3>Certificate (for manual setup if callback failed):</h3>
<p style="font-size: 12px; color: #666;">If the CLI didn't receive the certificate automatically, save this to ~/.ssh/id_ed25519-cert.pub:</p>
<textarea readonly style="width: 100%%; height: 200px; font-family: monospace; font-size: 12px;" onclick="this.select()">%s</textarea>
</div>`, string(certData))
		}
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>VSH Login</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px;">
<h2>Login Successful</h2>
<p>Logged in as: %s</p>
<p>Role: %s</p>
<p>Principals: %s</p>
%s
<p style="color: #666; margin-top: 20px;">You can close this window.</p>
</body>
</html>`, claims.Email, role, strings.Join(principals, ", "), certDisplay)
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
