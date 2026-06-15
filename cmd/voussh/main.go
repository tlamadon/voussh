package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/voussh/voussh/internal/version"
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
	Users        map[string]map[string][]string `yaml:"users"`                // email -> role -> principals
	Extensions   []string                       `yaml:"extensions,omitempty"` // global SSH cert extensions; defaults to defaultExtensions when unset
	Roles        map[string]Role                `yaml:"roles,omitempty"`      // role -> per-role policy (validity, extensions)
	TLS          *TLSConfig                     `yaml:"tls,omitempty"`
}

// Role holds per-role certificate policy. Empty fields fall back to the
// top-level Config defaults.
type Role struct {
	Validity   string   `yaml:"validity,omitempty"`   // overrides CertValidity for this role
	Extensions []string `yaml:"extensions,omitempty"` // overrides Extensions for this role
}

// defaultExtensions are the certificate extensions used when none are
// configured. This preserves prior behaviour.
var defaultExtensions = []string{
	"permit-pty",
	"permit-agent-forwarding",
	"permit-user-rc",
}

type TLSConfig struct {
	CertFile string `yaml:"cert"`
	KeyFile  string `yaml:"key"`
}

type StateData struct {
	Port   string `json:"p,omitempty"`
	Role   string `json:"r,omitempty"`
	Pubkey string `json:"k,omitempty"`
}

var (
	configPtr    atomic.Pointer[Config] // hot-reloadable config; read via currentConfig()
	caSigner     ssh.Signer
	oauth2Config *oauth2.Config
	oidcVerifier *oidc.IDTokenVerifier
)

// currentConfig returns the active configuration. The returned pointer is
// immutable — a reload swaps in a brand-new *Config rather than mutating it,
// so callers can read its fields without locking.
func currentConfig() *Config {
	return configPtr.Load()
}

// loadConfig reads and parses the config file.
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// watchConfig polls the config file and hot-reloads policy fields (users,
// roles, cert_validity, extensions) when it changes. Polling (rather than
// fsnotify) keeps things dependency-free and robust to editors that replace
// the file via rename.
func watchConfig(path string) {
	var lastMod time.Time
	var lastSize int64
	if fi, err := os.Stat(path); err == nil {
		lastMod, lastSize = fi.ModTime(), fi.Size()
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		fi, err := os.Stat(path)
		if err != nil {
			continue // file briefly missing (e.g. mid-rename); try again later
		}
		if fi.ModTime().Equal(lastMod) && fi.Size() == lastSize {
			continue
		}
		lastMod, lastSize = fi.ModTime(), fi.Size()
		reloadConfig(path)
	}
}

// reloadConfig re-reads the config file and atomically swaps in the new
// policy. Fields that require rebuilding the listener or OAuth client cannot
// be applied without a restart and are logged as warnings.
func reloadConfig(path string) {
	newCfg, err := loadConfig(path)
	if err != nil {
		log.Printf("Config reload failed, keeping previous config: %v", err)
		return
	}

	old := currentConfig()
	if newCfg.Addr != old.Addr {
		log.Printf("Config reload: 'addr' changed (%q -> %q) — restart required to take effect", old.Addr, newCfg.Addr)
	}
	if newCfg.CAKey != old.CAKey {
		log.Printf("Config reload: 'ca_key' changed — restart required to take effect")
	}
	if newCfg.ClientID != old.ClientID || newCfg.ClientSecret != old.ClientSecret || newCfg.RedirectURL != old.RedirectURL {
		log.Printf("Config reload: OAuth settings changed — restart required to take effect")
	}
	if tlsString(newCfg.TLS) != tlsString(old.TLS) {
		log.Printf("Config reload: 'tls' changed — restart required to take effect")
	}

	configPtr.Store(newCfg)
	log.Printf("Config reloaded from %s (%d users, %d roles)", path, len(newCfg.Users), len(newCfg.Roles))
}

func tlsString(t *TLSConfig) string {
	if t == nil {
		return ""
	}
	return t.CertFile + "|" + t.KeyFile
}

func main() {
	configFile := "config.yaml"

	// Parse command-line arguments
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch arg {
		case "init":
			cmdInit(os.Args[i+1:])
			return
		case "--version", "-v":
			fmt.Printf("voussh %s\n", version.String())
			os.Exit(0)
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
			fmt.Println("  --version, -v        Show version")
			fmt.Println("  --help, -h           Show this help message")
			fmt.Println()
			fmt.Println("Commands:")
			fmt.Println("  init [keyfile]       Generate a new CA key pair")
			os.Exit(0)
		}
	}

	cfg, err := loadConfig(configFile)
	if err != nil {
		log.Fatalf("Failed to load config file %s: %v", configFile, err)
	}
	configPtr.Store(cfg)

	caKeyData, err := os.ReadFile(cfg.CAKey)
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
	redirectURL := cfg.RedirectURL
	if cfg.TLS != nil && cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
		// Just log a warning if there's a potential mismatch
		if strings.HasPrefix(redirectURL, "http://") {
			log.Printf("WARNING: TLS enabled but redirect URL uses http://. Make sure this is registered in Google OAuth.")
		}
	}

	oauth2Config = &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     google.Endpoint,
		Scopes:       []string{oidc.ScopeOpenID, "email"},
	}

	oidcVerifier = provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	// Reload policy fields (users, roles, cert_validity, extensions) when the
	// config file changes on disk.
	go watchConfig(configFile)

	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/pubkey", handlePubkey)
	http.HandleFunc("/health", handleHealth)

	log.Printf("voussh %s", version.String())

	if cfg.TLS != nil && cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "" {
		log.Printf("Server starting on https://%s", cfg.Addr)
		log.Fatal(http.ListenAndServeTLS(cfg.Addr, cfg.TLS.CertFile, cfg.TLS.KeyFile, nil))
	} else {
		log.Printf("Server starting on http://%s", cfg.Addr)
		log.Fatal(http.ListenAndServe(cfg.Addr, nil))
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
	cliPort := r.URL.Query().Get("cli_port")
	role := r.URL.Query().Get("role")
	pubkey := r.URL.Query().Get("pubkey")

	// Encode state data as compact JSON, then base64
	stateData := StateData{
		Port:   cliPort,
		Role:   role,
		Pubkey: pubkey,
	}

	stateJSON, err := json.Marshal(stateData)
	if err != nil {
		http.Error(w, "Failed to encode state", http.StatusInternalServerError)
		return
	}

	// Use base64 URL encoding for the state
	state := base64.RawURLEncoding.EncodeToString(stateJSON)

	authURL := oauth2Config.AuthCodeURL(state)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing code", http.StatusBadRequest)
		return
	}

	// Decode state from base64 JSON
	state := r.URL.Query().Get("state")

	stateJSON, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		http.Error(w, "Invalid state encoding", http.StatusBadRequest)
		return
	}

	var stateData StateData
	if err := json.Unmarshal(stateJSON, &stateData); err != nil {
		http.Error(w, "Invalid state format", http.StatusBadRequest)
		return
	}

	cliPort := stateData.Port
	role := stateData.Role
	pubkeyB64 := stateData.Pubkey

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
	userRoles, ok := currentConfig().Users[claims.Email]
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

		// Log certificate issuance
		validUntil := time.Unix(int64(cert.ValidBefore), 0)
		exts := make([]string, 0, len(cert.Permissions.Extensions))
		for name := range cert.Permissions.Extensions {
			exts = append(exts, name)
		}
		sort.Strings(exts)
		log.Printf("Certificate issued: user=%s, role=%s, principals=[%s], validity=%s (until %s), extensions=[%s]",
			claims.Email, role, strings.Join(principals, ", "),
			time.Until(validUntil).Round(time.Second), validUntil.Format(time.RFC3339),
			strings.Join(exts, ", "))
	}

	// Redirect to CLI or show token
	if cliPort != "" {
		redirectURL := fmt.Sprintf("http://localhost:%s/callback?token=%s&role=%s&cert=%s",
			cliPort, url.QueryEscape(rawIDToken), url.QueryEscape(role), certB64)
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		return
	}

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
	cfg := currentConfig()
	roleCfg := cfg.Roles[role]

	// Validity: per-role override, then global, then 8h default.
	validity := cfg.CertValidity
	if roleCfg.Validity != "" {
		validity = roleCfg.Validity
	}
	duration, err := time.ParseDuration(validity)
	if err != nil {
		duration = 8 * time.Hour
	}

	// Extensions: per-role override, then global, then built-in default.
	extNames := roleCfg.Extensions
	if len(extNames) == 0 {
		extNames = cfg.Extensions
	}
	if len(extNames) == 0 {
		extNames = defaultExtensions
	}
	extensions := make(map[string]string, len(extNames))
	for _, name := range extNames {
		extensions[name] = ""
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
			Extensions: extensions,
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
