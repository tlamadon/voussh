package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
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
	Addr           string                         `yaml:"addr"`
	CAKey          string                         `yaml:"ca_key"`
	CertValidity   string                         `yaml:"cert_validity"`
	TrustedProxies []string                       `yaml:"trusted_proxies,omitempty"` // peers whose X-Forwarded-* headers are believed
	ClientID       string                         `yaml:"client_id"`
	ClientSecret   string                         `yaml:"client_secret"`
	RedirectURL    string                         `yaml:"redirect_url"`
	BaseURL        string                         `yaml:"base_url,omitempty"`    // externally reachable origin; derived from redirect_url when unset
	Users          map[string]map[string][]string `yaml:"users"`                 // email -> role -> principals
	Extensions     []string                       `yaml:"extensions,omitempty"`  // global SSH cert extensions; defaults to defaultExtensions when unset
	Roles          map[string]Role                `yaml:"roles,omitempty"`       // role -> per-role policy (validity, extensions)
	Services       map[string]ServiceConfig       `yaml:"services,omitempty"`    // service name -> machine credentials for POST /sign
	DeviceFlow     *DeviceFlowConfig              `yaml:"device_flow,omitempty"` // device authorization flow settings
	Admin          *AdminConfig                   `yaml:"admin,omitempty"`       // web admin panel at /admin
	TLS            *TLSConfig                     `yaml:"tls,omitempty"`

	// trustedProxies is TrustedProxies compiled to prefixes, prepared once
	// per load so per-request checks never re-parse strings. It travels with
	// the Config so a reload swaps policy and prefixes atomically.
	trustedProxies []netip.Prefix
}

// validate rejects configs that must not be served. It runs on every load, so
// a bad edit is refused at startup and skipped on reload rather than swapped
// into a running server.
func (c *Config) validate() error {
	for name, svc := range c.Services {
		if err := svc.validate(); err != nil {
			return fmt.Errorf("service %q: %w", name, err)
		}
	}
	for name, role := range c.Roles {
		if err := validateSourceAddress(role.SourceAddress); err != nil {
			return fmt.Errorf("role %q: %w", name, err)
		}
	}
	if c.Admin != nil && len(c.Admin.Emails) == 0 {
		return fmt.Errorf("admin: emails must not be empty")
	}
	// trusted_proxies is compiled here, not merely checked, so startup and
	// reload both get the prepared form; a malformed entry rejects the whole
	// config the same way any other bad field does.
	for _, entry := range c.TrustedProxies {
		prefix, err := parseProxyPrefix(entry)
		if err != nil {
			return err
		}
		c.trustedProxies = append(c.trustedProxies, prefix)
	}
	return nil
}

// DeviceFlowConfig tunes the device authorization flow. A nil *DeviceFlowConfig
// behaves as an enabled flow with default timings, so existing configs pick the
// feature up without edits.
type DeviceFlowConfig struct {
	// Enabled is a pointer so that an absent key means "on" while an explicit
	// `enabled: false` switches the flow off.
	Enabled      *bool  `yaml:"enabled,omitempty"`
	CodeValidity string `yaml:"code_validity,omitempty"` // how long a code stays usable; default 10m
	PollInterval string `yaml:"poll_interval,omitempty"` // minimum client poll spacing; default 5s
	MaxPending   int    `yaml:"max_pending,omitempty"`   // cap on concurrent requests; default 1024
}

func (d *DeviceFlowConfig) enabled() bool {
	if d == nil || d.Enabled == nil {
		return true
	}
	return *d.Enabled
}

func (d *DeviceFlowConfig) codeValidity() time.Duration {
	return d.duration(func() string { return d.CodeValidity }, 10*time.Minute, "code_validity")
}

func (d *DeviceFlowConfig) pollInterval() time.Duration {
	return d.duration(func() string { return d.PollInterval }, 5*time.Second, "poll_interval")
}

func (d *DeviceFlowConfig) maxPending() int {
	if d == nil || d.MaxPending <= 0 {
		return 1024
	}
	return d.MaxPending
}

func (d *DeviceFlowConfig) duration(get func() string, fallback time.Duration, name string) time.Duration {
	if d == nil || get() == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(get())
	if err != nil {
		log.Printf("Config: device_flow.%s is not a valid duration (%q), using %s", name, get(), fallback)
		return fallback
	}
	return parsed
}

// Role holds per-role certificate policy. Empty fields fall back to the
// top-level Config defaults.
type Role struct {
	Validity      string   `yaml:"validity,omitempty"`       // overrides CertValidity for this role
	Extensions    []string `yaml:"extensions,omitempty"`     // overrides Extensions for this role
	SourceAddress string   `yaml:"source_address,omitempty"` // source-address critical option: CIDRs the cert may be used from
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
	// Device carries the user code when the login was started from the device
	// page. Only the user code travels through the browser — never the device
	// code, which is the CLI's secret.
	Device string `json:"d,omitempty"`
	// Admin marks a login started from the admin panel; the callback sets a
	// session cookie instead of issuing a certificate.
	Admin string `json:"a,omitempty"`
}

// encodeState packs state for the OAuth round trip as compact JSON in base64url.
func encodeState(data StateData) (string, error) {
	stateJSON, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(stateJSON), nil
}

// decodeState reverses encodeState.
func decodeState(state string) (StateData, error) {
	stateJSON, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return StateData{}, err
	}
	var data StateData
	if err := json.Unmarshal(stateJSON, &data); err != nil {
		return StateData{}, err
	}
	return data, nil
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
	if err := cfg.validate(); err != nil {
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
	// device_flow.enabled is read per request, so it reloads; the timing knobs
	// are baked into the store at startup and cannot be.
	if newCfg.DeviceFlow.codeValidity() != old.DeviceFlow.codeValidity() ||
		newCfg.DeviceFlow.pollInterval() != old.DeviceFlow.pollInterval() ||
		newCfg.DeviceFlow.maxPending() != old.DeviceFlow.maxPending() {
		log.Printf("Config reload: device_flow timings changed — restart required to take effect")
	}
	if newCfg.DeviceFlow.enabled() != old.DeviceFlow.enabled() {
		log.Printf("Config reload: device flow %s", map[bool]string{true: "enabled", false: "disabled"}[newCfg.DeviceFlow.enabled()])
	}
	// admin.emails is read per request, so it reloads; the ring buffer
	// capacity is baked in at startup and cannot be.
	if newCfg.Admin.logLines() != old.Admin.logLines() {
		log.Printf("Config reload: admin.log_lines changed — restart required to take effect")
	}
	if newCfg.Admin.enabled() != old.Admin.enabled() {
		log.Printf("Config reload: admin panel %s", map[bool]string{true: "enabled", false: "disabled"}[newCfg.Admin.enabled()])
	}

	configPtr.Store(newCfg)
	log.Printf("Config reloaded from %s (%d users, %d roles, %d services)", path, len(newCfg.Users), len(newCfg.Roles), len(newCfg.Services))
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

	// Tee every log line into the ring buffer the admin panel reads. Done
	// before any other startup logging so the panel sees it all.
	initAdmin(cfg)
	log.SetOutput(io.MultiWriter(os.Stderr, logBuffer))

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

	initDeviceFlow(cfg)

	// Reload policy fields (users, roles, cert_validity, extensions) when the
	// config file changes on disk.
	go watchConfig(configFile)

	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/pubkey", handlePubkey)
	http.HandleFunc("/sign", handleSign)
	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/device", handleDeviceVerify)
	http.HandleFunc("/device/code", handleDeviceCode)
	http.HandleFunc("/device/approve", handleDeviceApprove)
	http.HandleFunc("/device/token", handleDeviceToken)
	http.HandleFunc("/admin", handleAdmin)
	http.HandleFunc("/admin/logs", handleAdminLogs)

	log.Printf("voussh %s", version.String())

	if cfg.DeviceFlow.enabled() {
		base := deviceBaseURL(cfg)
		if base == "" {
			log.Printf("WARNING: device flow is enabled but no verification URL can be derived from redirect_url. Set base_url in the config.")
		} else {
			log.Printf("Device flow enabled: %s/device (codes valid %s, poll interval %s)",
				base, cfg.DeviceFlow.codeValidity(), cfg.DeviceFlow.pollInterval())
		}
	} else {
		log.Printf("Device flow disabled")
	}

	if cfg.Admin.enabled() {
		log.Printf("Admin panel enabled at /admin (%d admins, last %d log lines)", len(cfg.Admin.Emails), cfg.Admin.logLines())
		if cfg.TLS == nil || cfg.TLS.CertFile == "" || cfg.TLS.KeyFile == "" {
			log.Printf("WARNING: admin panel enabled without TLS; session cookies travel in cleartext")
		}
	}

	tlsOff := cfg.TLS == nil || cfg.TLS.CertFile == "" || cfg.TLS.KeyFile == ""
	if n := len(cfg.trustedProxies); n > 0 {
		log.Printf("Trusting X-Forwarded-* headers from %d proxy prefix(es)", n)
	} else if tlsOff && listensBeyondLoopback(cfg.Addr) {
		// Either a plaintext service exposed on a network, or a proxy
		// deployment with the header handling left unconfigured.
		log.Printf("WARNING: serving plain HTTP on %s with no trusted_proxies — if a reverse proxy fronts voussh, list it in trusted_proxies; if not, consider enabling tls", cfg.Addr)
	}

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
	state, err := encodeState(StateData{
		Port:   r.URL.Query().Get("cli_port"),
		Role:   r.URL.Query().Get("role"),
		Pubkey: r.URL.Query().Get("pubkey"),
	})
	if err != nil {
		http.Error(w, "Failed to encode state", http.StatusInternalServerError)
		return
	}

	authURL := oauth2Config.AuthCodeURL(state)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// resolvePrincipals applies the users/roles policy: it maps a verified email
// and a requested role onto the principals the certificate may carry. An empty
// role selects "default". The returned role is the one actually used.
func resolvePrincipals(email, role string) (string, []string, error) {
	userRoles, ok := currentConfig().Users[email]
	if !ok {
		return "", nil, fmt.Errorf("user %s is not authorized", email)
	}

	if role == "" {
		role = "default"
	}

	principals, ok := userRoles[role]
	if !ok {
		available := make([]string, 0, len(userRoles))
		for name := range userRoles {
			available = append(available, name)
		}
		sort.Strings(available)
		return "", nil, fmt.Errorf("role %q not available. Available roles: %s",
			role, strings.Join(available, ", "))
	}
	if len(principals) == 0 {
		return "", nil, fmt.Errorf("no principals configured for role %q", role)
	}

	return role, principals, nil
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing code", http.StatusBadRequest)
		return
	}

	stateData, err := decodeState(r.URL.Query().Get("state"))
	if err != nil {
		http.Error(w, "Invalid state", http.StatusBadRequest)
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

	// A login started from the admin panel returns there, carrying a signed
	// session cookie instead of a certificate.
	if stateData.Admin != "" {
		handleAdminCallback(w, r, claims.Email)
		return
	}

	// A login started from the device page continues there: the approval step
	// happens in this browser, and the certificate goes to the polling CLI.
	if stateData.Device != "" {
		if !deviceFlowEnabled() {
			http.Error(w, "Device flow is disabled", http.StatusNotFound)
			return
		}
		handleDeviceCallback(w, stateData.Device, claims.Email)
		return
	}

	role, principals, err := resolvePrincipals(claims.Email, role)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
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

		pubKey, _, err := parseUserPublicKey(pubkeyBytes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		cert, err := signCertificate(pubKey, claims.Email, role, principals)
		if err != nil {
			http.Error(w, "Failed to sign certificate", http.StatusInternalServerError)
			return
		}
		certB64 = base64.RawURLEncoding.EncodeToString(ssh.MarshalAuthorizedKey(cert))

		logCertificateIssued(cert, claims.Email, role, principals, "browser")
	}

	// Redirect to CLI or show token
	if cliPort != "" {
		redirectURL := fmt.Sprintf("http://localhost:%s/callback?token=%s&role=%s&cert=%s",
			cliPort, url.QueryEscape(rawIDToken), url.QueryEscape(role), certB64)
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
		return
	}

	// No CLI listener to redirect to: fall back to showing the certificate for
	// manual copying. For a machine with no usable browser, prefer the device
	// flow (`vsh login --device`) over this page.
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

	keyID := fmt.Sprintf("%s@%s", email, role)
	return signPolicyCertificate(pubKey, keyID, principals, duration, extensions, criticalOptions(roleCfg.SourceAddress))
}

// criticalOptions builds the critical-options map for a certificate. A nil map
// (no source restriction) keeps the wire format identical to what voussh
// issued before source_address existed.
func criticalOptions(sourceAddress string) map[string]string {
	if sourceAddress == "" {
		return nil
	}
	return map[string]string{"source-address": sourceAddress}
}

// signPolicyCertificate builds and signs a certificate from fully resolved
// policy. The five-minute ValidAfter backdate absorbs clock skew between the
// CA and the servers checking the certificate.
func signPolicyCertificate(pubKey ssh.PublicKey, keyID string, principals []string, duration time.Duration, extensions, critical map[string]string) (*ssh.Certificate, error) {
	now := time.Now()
	cert := &ssh.Certificate{
		Key:             pubKey,
		Serial:          uint64(now.UnixNano()),
		CertType:        ssh.UserCert,
		KeyId:           keyID,
		ValidPrincipals: principals,
		ValidAfter:      uint64(now.Add(-5 * time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(duration).Unix()),
		Permissions: ssh.Permissions{
			Extensions:      extensions,
			CriticalOptions: critical,
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
