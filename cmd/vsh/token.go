package main

// vsh token obtains and manages HTTP credentials: short-lived access tokens
// bound to a private key that never leaves this machine. Authentication is
// the same as for `vsh login` — the browser flow, the device flow, or a
// service token — only the thing issued at the end differs.
//
// Everything a human reads goes to stderr. Stdout carries data and nothing
// else, so `vsh token print` and `vsh http` are safe inside $(...).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/voussh/voussh/httpcred"
	"github.com/voussh/voussh/internal/keyfile"
	"golang.org/x/crypto/ssh"
)

// Login modes, recorded with a credential so `vsh token renew` can repeat the
// workflow that produced it.
const (
	tokenModeBrowser = "browser"
	tokenModeDevice  = "device"
	tokenModeService = "service"
)

// tokenRecord is one stored credential. There is one per audience; a new
// login for the same audience replaces it.
type tokenRecord struct {
	Server        string    `json:"server"`
	Audience      string    `json:"audience"`
	Role          string    `json:"role"`
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	ExpiresAt     time.Time `json:"expires_at"`
	KeyPath       string    `json:"key"`
	KeyThumbprint string    `json:"key_thumbprint"`
	Mode          string    `json:"mode"`
	// ServiceTokenFile is the path of the service token used in service
	// mode. Only the path is stored, never its contents.
	ServiceTokenFile string `json:"service_token_file,omitempty"`
	AccessToken      string `json:"access_token"`
}

func (r *tokenRecord) expired(margin time.Duration) bool {
	return !time.Now().Add(margin).Before(r.ExpiresAt)
}

// fatalf reports an error on stderr and exits.
func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func cmdToken(args []string) {
	if len(args) == 0 {
		printTokenUsage()
		os.Exit(1)
	}
	switch args[0] {
	case "login":
		cmdTokenLogin(args[1:])
	case "renew":
		cmdTokenRenew(args[1:])
	case "status":
		cmdTokenStatus(args[1:])
	case "print":
		cmdTokenPrint(args[1:])
	case "proof":
		cmdTokenProof(args[1:])
	case "logout":
		cmdTokenLogout(args[1:])
	case "help", "--help", "-h":
		printTokenUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown token command: %s\n", args[0])
		printTokenUsage()
		os.Exit(1)
	}
}

func printTokenUsage() {
	fmt.Fprintln(os.Stderr, "Usage: vsh token <command> [options]")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  login   Obtain an HTTP credential: --audience <name> [--role <role>] [--device]")
	fmt.Fprintln(os.Stderr, "  renew   Repeat the login that produced a stored credential")
	fmt.Fprintln(os.Stderr, "  status  Show stored credentials: audience, role, identity and expiry")
	fmt.Fprintln(os.Stderr, "  print   Write the raw access token to stdout (for scripting)")
	fmt.Fprintln(os.Stderr, "  proof   Write a DPoP proof for one request to stdout (for scripting)")
	fmt.Fprintln(os.Stderr, "  logout  Remove stored credentials")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "To use a credential, see: vsh http --help")
}

// ---------------------------------------------------------------------------
// Storage. Tokens live under the vsh config directory, one file per audience,
// readable only by the owner. They never pass through argv or the environment.
// ---------------------------------------------------------------------------

func tokenDir() string { return filepath.Join(vshDir, "tokens") }

// defaultHTTPKeyPath is the proof-of-possession key used when --key is not
// given. It is dedicated to HTTP credentials rather than shared with SSH.
func defaultHTTPKeyPath() string { return filepath.Join(vshDir, "http_ed25519") }

// tokenFileName maps an audience onto a file name. Audiences may be URLs, so
// anything outside a conservative character set is replaced, with a short
// hash appended to keep distinct audiences from colliding. Upper case counts
// as "replaced": on a case-insensitive filesystem "API" and "api" would
// otherwise be one file.
func tokenFileName(audience string) string {
	var b strings.Builder
	for _, r := range audience {
		switch {
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == '.' && b.Len() > 0:
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	name := b.String()
	if name != audience || len(name) > 64 {
		if len(name) > 64 {
			name = name[:64]
		}
		sum := sha256.Sum256([]byte(audience))
		name += "-" + hex.EncodeToString(sum[:4])
	}
	return name + ".json"
}

func saveToken(rec *tokenRecord) error {
	if err := os.MkdirAll(tokenDir(), 0700); err != nil {
		return err
	}
	// MkdirAll leaves an existing directory's mode alone; tighten it.
	if err := os.Chmod(tokenDir(), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(tokenDir(), tokenFileName(rec.Audience)), append(data, '\n'), 0600)
}

func loadToken(audience string) (*tokenRecord, error) {
	data, err := os.ReadFile(filepath.Join(tokenDir(), tokenFileName(audience)))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no credential stored for audience %q. Run: vsh token login --audience %s", audience, audience)
		}
		return nil, err
	}
	var rec tokenRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("stored credential for audience %q is unreadable: %w", audience, err)
	}
	// The file name is derived from the audience, but the record is what
	// says whose credential this is. Never hand back one for another audience.
	if rec.Audience != audience {
		return nil, fmt.Errorf("stored credential is for audience %q, not %q. Run: vsh token login --audience %s", rec.Audience, audience, audience)
	}
	return &rec, nil
}

// listTokens returns every stored credential, sorted by audience.
func listTokens() []*tokenRecord {
	entries, err := os.ReadDir(tokenDir())
	if err != nil {
		return nil
	}
	var out []*tokenRecord
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(tokenDir(), entry.Name()))
		if err != nil {
			continue
		}
		var rec tokenRecord
		if json.Unmarshal(data, &rec) == nil && rec.Audience != "" {
			out = append(out, &rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Audience < out[j].Audience })
	return out
}

// selectToken resolves --audience. It may be omitted when exactly one
// credential is stored, which is the common case.
func selectToken(audience string) (*tokenRecord, error) {
	if audience != "" {
		return loadToken(audience)
	}
	all := listTokens()
	switch len(all) {
	case 0:
		return nil, errors.New("no credentials stored. Run: vsh token login --audience <name>")
	case 1:
		return all[0], nil
	}
	names := make([]string, len(all))
	for i, rec := range all {
		names[i] = rec.Audience
	}
	return nil, fmt.Errorf("several credentials are stored; choose one with --audience (%s)", strings.Join(names, ", "))
}

// ensureHTTPKey loads the proof-of-possession key, generating it on first
// use. The key is written once, in OpenSSH format, mode 0600; only its public
// half is ever sent anywhere.
func ensureHTTPKey(path string) (ed25519.PrivateKey, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key: %w", err)
		}
		block, err := ssh.MarshalPrivateKey(priv, "vsh http credential key")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal key: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
		if err := writeFileAtomic(path, pem.EncodeToMemory(block), 0600); err != nil {
			return nil, fmt.Errorf("failed to write key: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Generated a new key for HTTP credentials at %s\n", path)
		return priv, nil
	}
	key, err := keyfile.LoadPrivate(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}
	return key, nil
}

// ---------------------------------------------------------------------------
// vsh token login / renew
// ---------------------------------------------------------------------------

type tokenLoginOptions struct {
	Server           string
	Audience         string
	Role             string
	Mode             string
	KeyPath          string
	ServiceTokenFile string
	// ExpectSubject, when set, is the identity the new token must be for.
	// Renewal sets it: a renewed credential that silently belongs to someone
	// else is the signature of a login completed by the wrong person.
	ExpectSubject string
}

func cmdTokenLogin(args []string) {
	fs := flag.NewFlagSet("token login", flag.ExitOnError)
	server := fs.String("server", "", "Server URL (default: $VSH_SERVER, the saved server, or a prompt)")
	audience := fs.String("audience", "", "Service the token is for (required)")
	role := fs.String("role", "", "Role to request (default: the server's default role)")
	deviceFlow := fs.Bool("device", false, "Approve from another device instead of a local browser")
	serviceTokenFile := fs.String("service-token-file", "", "Authenticate as a machine identity with this voussh service token (non-interactive)")
	keyPath := fs.String("key", "", "Ed25519 private key to bind the token to (default: generated on first use)")
	fs.Parse(args)

	if *audience == "" {
		fatalf("--audience is required")
	}
	if *deviceFlow && *serviceTokenFile != "" {
		fatalf("--device and --service-token-file are mutually exclusive")
	}

	opts := tokenLoginOptions{
		Server:           *server,
		Audience:         *audience,
		Role:             *role,
		Mode:             tokenModeBrowser,
		KeyPath:          *keyPath,
		ServiceTokenFile: *serviceTokenFile,
	}
	switch {
	case *serviceTokenFile != "":
		opts.Mode = tokenModeService
	case *deviceFlow:
		opts.Mode = tokenModeDevice
	}

	if opts.Mode == tokenModeService {
		// A machine identity never prompts, and its server is not a choice
		// to remember on a human's behalf.
		if opts.Server == "" {
			opts.Server = serverURL
		}
		if opts.Server == "" {
			fatalf("No server configured. Use --server or set VSH_SERVER.")
		}
	} else {
		resolved, err := resolveServer(opts.Server, true)
		if err != nil {
			fatalf("Error: %v", err)
		}
		opts.Server = resolved
		addServerToHistory(opts.Server)
	}

	rec, err := tokenLogin(opts)
	if err != nil {
		fatalf("%v", err)
	}
	reportToken(rec)
}

func cmdTokenRenew(args []string) {
	fs := flag.NewFlagSet("token renew", flag.ExitOnError)
	audience := fs.String("audience", "", "Audience to renew (optional when only one credential is stored)")
	fs.Parse(args)

	old, err := selectToken(*audience)
	if err != nil {
		fatalf("%v", err)
	}
	rec, err := tokenLogin(renewOptions(old))
	if err != nil {
		fatalf("%v", err)
	}
	reportToken(rec)
}

// renewOptions rebuilds the login that produced a stored credential.
func renewOptions(rec *tokenRecord) tokenLoginOptions {
	return tokenLoginOptions{
		Server:           rec.Server,
		Audience:         rec.Audience,
		Role:             rec.Role,
		Mode:             rec.Mode,
		KeyPath:          rec.KeyPath,
		ServiceTokenFile: rec.ServiceTokenFile,
		ExpectSubject:    rec.Subject,
	}
}

func reportToken(rec *tokenRecord) {
	fmt.Fprintf(os.Stderr, "Token saved for audience %s\n", rec.Audience)
	fmt.Fprintf(os.Stderr, "  Identity: %s\n", rec.Subject)
	fmt.Fprintf(os.Stderr, "  Role:     %s\n", rec.Role)
	fmt.Fprintf(os.Stderr, "  Expires:  %s (in %s)\n",
		rec.ExpiresAt.Local().Format("15:04:05 on Jan 2"), time.Until(rec.ExpiresAt).Round(time.Second))
}

// tokenLogin runs one of the three authentication workflows, checks what came
// back, and stores it.
func tokenLogin(opts tokenLoginOptions) (*tokenRecord, error) {
	serverURL = strings.TrimRight(opts.Server, "/")
	if opts.KeyPath == "" {
		opts.KeyPath = defaultHTTPKeyPath()
	}
	key, err := ensureHTTPKey(opts.KeyPath)
	if err != nil {
		return nil, err
	}
	pub := key.Public().(ed25519.PublicKey)

	// Fetch the server's verification keys before anything else. This doubles
	// as the check that the server issues tokens at all — one that does not
	// (no jwt block, or an older voussh) would treat a browser login as an
	// ordinary certificate login and leave this command waiting for a token
	// that is never coming.
	issuerKeys, err := fetchIssuerKeys()
	if err != nil {
		return nil, err
	}

	var token string
	switch opts.Mode {
	case tokenModeService:
		token, err = tokenViaService(opts, pub)
	case tokenModeDevice:
		token, err = tokenViaDevice(opts, pub)
	default:
		opts.Mode = tokenModeBrowser
		token, err = tokenViaBrowser(opts, pub)
	}
	if err != nil {
		return nil, err
	}

	claims, err := checkIssuedToken(token, issuerKeys, pub, opts.Audience)
	if err != nil {
		return nil, err
	}
	if opts.ExpectSubject != "" && claims.Subject != opts.ExpectSubject {
		return nil, fmt.Errorf("the new token is for %s, but the stored credential belongs to %s; refusing to replace it. "+
			"To switch identity deliberately, run: vsh token login --audience %s", claims.Subject, opts.ExpectSubject, opts.Audience)
	}
	rec := &tokenRecord{
		Server:           serverURL,
		Audience:         opts.Audience,
		Role:             claims.Role,
		Subject:          claims.Subject,
		Issuer:           claims.Issuer,
		ExpiresAt:        claims.Expiry,
		KeyPath:          opts.KeyPath,
		KeyThumbprint:    claims.KeyThumbprint,
		Mode:             opts.Mode,
		ServiceTokenFile: opts.ServiceTokenFile,
		AccessToken:      token,
	}
	if err := saveToken(rec); err != nil {
		return nil, fmt.Errorf("failed to save token: %w", err)
	}
	return rec, nil
}

// checkIssuedToken confirms that a token is the one that was asked for: signed
// by the server it was requested from, bound to this machine's key, for the
// requested audience, and not already expired.
//
// The signature check matters most in the browser flow, where the token
// arrives through a request to a loopback port rather than in the response to
// a request vsh made: it stops anything other than the server from handing
// vsh a "token". Relying services still verify for themselves, against keys
// they pin; this check is about what vsh is willing to store and display.
func checkIssuedToken(token string, issuerKeys []httpcred.VerificationKey, pub ed25519.PublicKey, audience string) (httpcred.Claims, error) {
	claims, err := httpcred.VerifySignature(token, issuerKeys)
	if err != nil {
		return httpcred.Claims{}, fmt.Errorf("received a token that was not signed by %s; refusing to store it (%v)", serverURL, err)
	}
	if subtle.ConstantTimeCompare([]byte(claims.KeyThumbprint), []byte(httpcred.Thumbprint(pub))) != 1 {
		return httpcred.Claims{}, errors.New("server returned a token bound to a different key; refusing to store it")
	}
	if !slices.Contains(claims.Audience, audience) {
		return httpcred.Claims{}, fmt.Errorf("server returned a token for audience %q, not %q; refusing to store it",
			strings.Join(claims.Audience, " "), audience)
	}
	if !time.Now().Before(claims.Expiry) {
		return httpcred.Claims{}, errors.New("server returned a token that has already expired (check this machine's clock)")
	}
	return claims, nil
}

// fetchIssuerKeys downloads the server's published verification keys, which
// exist exactly when HTTP credentials are enabled.
func fetchIssuerKeys() ([]httpcred.VerificationKey, error) {
	resp, err := deviceHTTPClient.Get(serverURL + "/.well-known/jwks.json")
	if err != nil {
		return nil, fmt.Errorf("failed to contact %s: %w", serverURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s does not issue HTTP credentials (no jwt configuration, or an older voussh)", serverURL)
	}
	keys, err := httpcred.ParseJWKS(body)
	if err != nil {
		return nil, fmt.Errorf("%s published an unusable key set: %w", serverURL, err)
	}
	return keys, nil
}

// jwkParam encodes the public key the way the interactive flows carry it.
func jwkParam(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(httpcred.MarshalPublicJWK(pub))
}

// tokenResponse mirrors the server's JSON token response.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Audience    string `json:"audience"`
	Role        string `json:"role"`
	Subject     string `json:"subject"`
}

func parseTokenResponse(body []byte) (string, error) {
	var resp tokenResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("unexpected response from server: %w", err)
	}
	if resp.AccessToken == "" {
		return "", errors.New("server returned no token (it may be running an older voussh)")
	}
	return resp.AccessToken, nil
}

// tokenViaService is the non-interactive workflow: a voussh service token is
// exchanged for an access token at POST /token.
func tokenViaService(opts tokenLoginOptions, pub ed25519.PublicKey) (string, error) {
	raw, err := os.ReadFile(opts.ServiceTokenFile)
	if err != nil {
		return "", fmt.Errorf("failed to read service token: %w", err)
	}
	serviceToken := strings.TrimSpace(string(raw))
	if serviceToken == "" {
		return "", fmt.Errorf("service token file %s is empty", opts.ServiceTokenFile)
	}

	payload, err := json.Marshal(map[string]any{
		"audience": opts.Audience,
		"role":     opts.Role,
		"jwk":      json.RawMessage(httpcred.MarshalPublicJWK(pub)),
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, serverURL+"/token", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+serviceToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := deviceHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to contact %s: %w", serverURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token request failed: %s", describeDeviceError(body, resp.StatusCode))
	}
	return parseTokenResponse(body)
}

// tokenViaDevice is the headless workflow: the same device flow as
// `vsh login --device`, asking for a token instead of a certificate.
func tokenViaDevice(opts tokenLoginOptions, pub ed25519.PublicKey) (string, error) {
	form := url.Values{}
	form.Set("audience", opts.Audience)
	form.Set("jwk", jwkParam(pub))
	if opts.Role != "" {
		form.Set("role", opts.Role)
	}
	code, err := requestDeviceCodeForm(form)
	if err != nil {
		return "", err
	}

	expiresIn := time.Duration(code.ExpiresIn) * time.Second
	if expiresIn <= 0 {
		expiresIn = 10 * time.Minute
	}
	interval := time.Duration(code.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}

	printDeviceInstructions(os.Stderr, code, expiresIn)
	printApprovalHint(opts.Audience, pub)

	body, err := pollDevice(code.DeviceCode, interval, expiresIn)
	if err != nil {
		return "", err
	}
	return parseTokenResponse(body)
}

// printApprovalHint shows what the approval page should say, so the user can
// tell their own request from one somebody else started.
func printApprovalHint(audience string, pub ed25519.PublicKey) {
	fmt.Fprintf(os.Stderr, "\nThe approval page should show:\n")
	fmt.Fprintf(os.Stderr, "    Audience:    %s\n", audience)
	fmt.Fprintf(os.Stderr, "    Client key:  %s\n\n", httpcred.Thumbprint(pub))
}

// openLoginURL hands the login URL to the user's browser. It is a variable so
// tests can stand in for the browser.
var openLoginURL = openBrowser

type tokenCallbackResult struct {
	token string
	err   error
}

// tokenViaBrowser is the interactive workflow: the same /login round trip as
// `vsh login`, ending in a confirmation page and a redirect to a listener on
// localhost.
func tokenViaBrowser(opts tokenLoginOptions, pub ed25519.PublicKey) (string, error) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return "", fmt.Errorf("failed to start local server: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	// The nonce is how the listener recognises its own login. Without it,
	// anything able to reach this port during the login could hand vsh a
	// token of its choosing.
	var nonceBytes [16]byte
	if _, err := rand.Read(nonceBytes[:]); err != nil {
		listener.Close()
		return "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes[:])

	results := make(chan tokenCallbackResult, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", tokenCallbackHandler(nonce, results))
	srv := &http.Server{Handler: mux}
	go srv.Serve(listener)
	defer shutdownCallbackServer(srv)

	q := url.Values{}
	q.Set("cli_port", fmt.Sprint(port))
	q.Set("cli_state", nonce)
	q.Set("audience", opts.Audience)
	q.Set("jwk", jwkParam(pub))
	if opts.Role != "" {
		q.Set("role", opts.Role)
	}
	loginURL := serverURL + "/login?" + q.Encode()

	fmt.Fprintln(os.Stderr, "Opening browser for authentication...")
	fmt.Fprintf(os.Stderr, "Login URL: %s\n", loginURL)
	printApprovalHint(opts.Audience, pub)
	openLoginURL(loginURL)
	fmt.Fprintf(os.Stderr, "Waiting for approval on localhost:%d...\n", port)
	fmt.Fprintln(os.Stderr, "Note: this only works if the browser is on the same machine. Otherwise use --device.")
	fmt.Fprintln(os.Stderr, "      The login URL above is specific to this login: do not share it or paste it into logs.")

	select {
	case result := <-results:
		return result.token, result.err
	case <-time.After(5 * time.Minute):
		return "", errors.New("login timed out. Please try again")
	}
}

var tokenCallbackTmpl = template.Must(template.New("token").Parse(`<!DOCTYPE html>
<html><head><title>VSH Token</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 520px; margin: 50px auto; padding: 20px;">
{{if .Error}}<h2 style="color: #c00;">Token request failed</h2>
<p>{{.Error}}</p>
{{else}}<h2 style="color: #0a0;">Token issued</h2>
<table style="border-collapse: collapse; margin: 20px 0; width: 100%;">
<tr><td style="padding: 6px 12px 6px 0; color: #666;">Signed in as</td><td><strong>{{.Subject}}</strong></td></tr>
<tr><td style="padding: 6px 12px 6px 0; color: #666;">Audience</td><td>{{.Audience}}</td></tr>
<tr><td style="padding: 6px 12px 6px 0; color: #666;">Role</td><td>{{.Role}}</td></tr>
<tr><td style="padding: 6px 12px 6px 0; color: #666;">Valid until</td><td>{{.Until}}</td></tr>
</table>
<p style="color: #666;">The token has been handed to the CLI. You can close this window and return to your terminal.</p>
{{end}}</body></html>`))

type tokenCallbackPage struct {
	Error    string
	Subject  string
	Audience string
	Role     string
	Until    string
}

// tokenCallbackHandler serves the redirect that ends a browser login. Like
// callbackHandler, it flushes the page before signalling, because the main
// goroutine shuts the server down as soon as it has a result.
func tokenCallbackHandler(nonce string, results chan<- tokenCallbackResult) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		// A request without our nonce is not the end of our login. Answer it
		// and keep waiting, rather than letting it abort or hijack the flow.
		if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(nonce)) != 1 {
			http.Error(w, "Unexpected request", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")

		result := tokenCallbackResult{token: q.Get("jwt")}
		page := tokenCallbackPage{}
		switch {
		case q.Get("error") != "":
			reason := q.Get("error_description")
			if reason == "" {
				reason = q.Get("error")
			}
			result = tokenCallbackResult{err: fmt.Errorf("token request failed: %s", reason)}
			page.Error = reason
		case result.token == "":
			result.err = errors.New("no token received")
			page.Error = "No token received."
		default:
			// Display only; the caller validates the token properly.
			if claims, err := httpcred.ParseUnverified(result.token); err == nil {
				page.Subject = claims.Subject
				page.Audience = strings.Join(claims.Audience, " ")
				page.Role = claims.Role
				page.Until = claims.Expiry.Local().Format("15:04:05 on Jan 2")
			}
		}
		tokenCallbackTmpl.Execute(w, page)
		flushResponse(w)

		// A reload of the page must not block forever on a full channel.
		select {
		case results <- result:
		default:
		}
	}
}

// ---------------------------------------------------------------------------
// vsh token status / print / proof / logout
// ---------------------------------------------------------------------------

func cmdTokenStatus(args []string) {
	fs := flag.NewFlagSet("token status", flag.ExitOnError)
	audience := fs.String("audience", "", "Show only this audience")
	fs.Parse(args)

	var recs []*tokenRecord
	if *audience != "" {
		rec, err := loadToken(*audience)
		if err != nil {
			fatalf("%v", err)
		}
		recs = []*tokenRecord{rec}
	} else {
		recs = listTokens()
	}
	if len(recs) == 0 {
		fmt.Println("No HTTP credentials stored. Run: vsh token login --audience <name>")
		return
	}

	for i, rec := range recs {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("Audience: %s\n", rec.Audience)
		fmt.Printf("Identity: %s\n", rec.Subject)
		fmt.Printf("Role: %s\n", rec.Role)
		fmt.Printf("Issuer: %s (via %s, %s)\n", rec.Issuer, rec.Server, rec.Mode)
		fmt.Printf("Key: %s (%s)\n", rec.KeyThumbprint, rec.KeyPath)
		if rec.expired(0) {
			fmt.Printf("Expired: %s. Run: vsh token renew --audience %s\n",
				rec.ExpiresAt.Local().Format("15:04:05 on Jan 2"), rec.Audience)
		} else {
			fmt.Printf("Expires: %s (%s remaining)\n",
				rec.ExpiresAt.Local().Format("15:04:05 on Jan 2"), time.Until(rec.ExpiresAt).Round(time.Second))
		}
	}
}

// usableToken returns a stored credential that is still valid, renewing it
// first when that needs no human (service mode).
func usableToken(audience string) (*tokenRecord, error) {
	rec, err := selectToken(audience)
	if err != nil {
		return nil, err
	}
	// A token about to expire would be refused by the time it arrives.
	if !rec.expired(10 * time.Second) {
		return rec, nil
	}
	if rec.Mode == tokenModeService {
		renewed, err := tokenLogin(renewOptions(rec))
		if err != nil {
			return nil, fmt.Errorf("token for audience %q expired and renewal failed: %w", rec.Audience, err)
		}
		return renewed, nil
	}
	return nil, fmt.Errorf("token for audience %q expired at %s. Run: vsh token renew --audience %s",
		rec.Audience, rec.ExpiresAt.Local().Format("15:04:05 on Jan 2"), rec.Audience)
}

func cmdTokenPrint(args []string) {
	fs := flag.NewFlagSet("token print", flag.ExitOnError)
	audience := fs.String("audience", "", "Audience (optional when only one credential is stored)")
	fs.Parse(args)

	rec, err := usableToken(*audience)
	if err != nil {
		fatalf("%v", err)
	}
	// The token is bound to a key: on its own it authenticates nothing. A
	// request also needs a proof, from `vsh token proof` or `vsh http`.
	fmt.Println(rec.AccessToken)
}

func cmdTokenProof(args []string) {
	fs := flag.NewFlagSet("token proof", flag.ExitOnError)
	audience := fs.String("audience", "", "Audience (optional when only one credential is stored)")
	method := fs.String("method", "GET", "HTTP method of the request the proof is for")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: vsh token proof [--audience <name>] [--method <method>] <url>")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}

	rec, err := usableToken(*audience)
	if err != nil {
		fatalf("%v", err)
	}
	key, err := keyfile.LoadPrivate(rec.KeyPath)
	if err != nil {
		fatalf("failed to load key: %v", err)
	}
	proof, err := httpcred.NewProof(key, httpcred.ProofParams{
		Method:      strings.ToUpper(*method),
		URL:         fs.Arg(0),
		AccessToken: rec.AccessToken,
	})
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Println(proof)
}

func cmdTokenLogout(args []string) {
	fs := flag.NewFlagSet("token logout", flag.ExitOnError)
	audience := fs.String("audience", "", "Audience to remove")
	all := fs.Bool("all", false, "Remove every stored credential")
	fs.Parse(args)

	var recs []*tokenRecord
	switch {
	case *all:
		recs = listTokens()
	default:
		rec, err := selectToken(*audience)
		if err != nil {
			fatalf("%v", err)
		}
		recs = []*tokenRecord{rec}
	}
	for _, rec := range recs {
		path := filepath.Join(tokenDir(), tokenFileName(rec.Audience))
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			fatalf("failed to remove credential for %s: %v", rec.Audience, err)
		}
		fmt.Fprintf(os.Stderr, "Removed credential for audience %s\n", rec.Audience)
	}
	if len(recs) == 0 {
		fmt.Fprintln(os.Stderr, "No credentials stored")
	}
}
