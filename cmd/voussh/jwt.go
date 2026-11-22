package main

// HTTP credentials: proof-of-possession JWTs for services that authenticate
// requests offline. This file holds everything specific to that credential
// format — policy, keys, the authorization decision and the endpoints that
// exist only for it. The browser and device flows in main.go and device.go
// call into it at the points where they would otherwise sign an SSH
// certificate; identity (who is this?) and role membership (which roles do
// they hold?) are the same code paths for both formats.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/voussh/voussh/httpcred"
	"github.com/voussh/voussh/internal/keyfile"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

const (
	// defaultJWTValidity is the token lifetime when none is configured.
	defaultJWTValidity = 15 * time.Minute
	// maxJWTValidity is the ceiling on any configured lifetime. Tokens are
	// verified offline and cannot be revoked, so their lifetime is the window
	// in which a removed user or a leaked key still works; the config loader
	// refuses anything longer than this.
	maxJWTValidity = 24 * time.Hour
	// jwtApprovalTTL is how long the browser flow's confirmation page stays
	// submittable.
	jwtApprovalTTL = 5 * time.Minute
	// maxTokenRequestBody bounds the bodies of POST /token and
	// POST /login/approve.
	maxTokenRequestBody = 8 << 10
)

// JWTConfig switches on HTTP credential issuance. Absent, voussh is an SSH
// certificate authority and nothing else.
type JWTConfig struct {
	Issuer     string `yaml:"issuer"`             // "iss" claim; relying services require this exact string
	SigningKey string `yaml:"signing_key"`        // Ed25519 private key; deliberately separate from ca_key
	KeyID      string `yaml:"key_id,omitempty"`   // "kid" of the signing key; defaults to its RFC 7638 thumbprint
	Validity   string `yaml:"validity,omitempty"` // token lifetime; default 15m, at most 24h
	// VerificationKeys are further public keys published in the JWKS but
	// never used for signing — the next key during a rotation, or the
	// previous one until its tokens have expired.
	VerificationKeys []JWTVerificationKey `yaml:"verification_keys,omitempty"`
	// Audiences is the complete list of services tokens may be issued for.
	// A request naming anything else is refused.
	Audiences map[string]JWTAudience `yaml:"audiences"`

	// keys is the loaded key material. It travels with the config so a
	// reload swaps policy and keys together.
	keys *jwtKeys
}

// JWTVerificationKey is one additional published key.
type JWTVerificationKey struct {
	Key   string `yaml:"key"`              // public key file: an OpenSSH "ssh-ed25519 ..." line or a JWK
	KeyID string `yaml:"key_id,omitempty"` // defaults to the key's RFC 7638 thumbprint
}

// JWTAudience is the issuance policy for one relying service.
type JWTAudience struct {
	// AllowedRoles lists the roles a user may obtain a token for. The user
	// must also hold the role in the top-level users map.
	AllowedRoles []string `yaml:"allowed_roles,omitempty"`
	// Services grants machine identities (entries of the top-level services
	// map) the roles listed. Being able to request SSH certificates through
	// /sign confers nothing here: a service not named gets no token.
	Services map[string][]string `yaml:"services,omitempty"`
	// Validity overrides the top-level jwt.validity for this audience.
	Validity string `yaml:"validity,omitempty"`
}

// jwtKeys is the key material derived from a JWTConfig.
type jwtKeys struct {
	issuer *httpcred.Issuer
	// approvalKey authenticates the browser flow's confirmation form. It is
	// derived from the signing key rather than generated per process, so the
	// form survives a restart and can be submitted to any replica — the
	// browser flow stays as stateless for tokens as it is for certificates.
	approvalKey []byte
}

// UnmarshalYAML decodes the jwt block strictly: an unknown key is an error.
// The rest of the config tolerates stray keys, but here a misspelt one fails
// open — `valididty: 5m` would silently leave tokens at the longer default,
// and an audience's misspelt `allowed_roles` would be read as "no roles" —
// and tokens cannot be recalled once issued.
func (j *JWTConfig) UnmarshalYAML(node *yaml.Node) error {
	raw, err := yaml.Marshal(node)
	if err != nil {
		return err
	}
	type plain JWTConfig // drops this method, avoiding recursion
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	return dec.Decode((*plain)(j))
}

// parseJWTValidity parses a configured lifetime. An empty value means "not
// set" and yields zero.
func parseJWTValidity(value string) (time.Duration, error) {
	if value == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid validity %q: %w", value, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("invalid validity %q: must be positive", value)
	}
	if d > maxJWTValidity {
		return 0, fmt.Errorf("invalid validity %q: tokens cannot be revoked, so the maximum is %s", value, maxJWTValidity)
	}
	return d, nil
}

// validate checks the policy half of the config. It does no file I/O; keys
// are loaded separately by loadKeys.
func (j *JWTConfig) validate(services map[string]ServiceConfig) error {
	if j.Issuer == "" {
		return errors.New("issuer must not be empty")
	}
	if j.SigningKey == "" {
		return errors.New("signing_key must not be empty")
	}
	if _, err := parseJWTValidity(j.Validity); err != nil {
		return err
	}
	for i, vk := range j.VerificationKeys {
		if vk.Key == "" {
			return fmt.Errorf("verification_keys[%d]: key must not be empty", i)
		}
	}
	for name, aud := range j.Audiences {
		if err := validateAudienceName(name); err != nil {
			return err
		}
		if _, err := parseJWTValidity(aud.Validity); err != nil {
			return fmt.Errorf("audience %q: %w", name, err)
		}
		if len(aud.AllowedRoles) == 0 && len(aud.Services) == 0 {
			return fmt.Errorf("audience %q: needs allowed_roles or services, otherwise no token can ever be issued for it", name)
		}
		if slices.Contains(aud.AllowedRoles, "") {
			return fmt.Errorf("audience %q: allowed_roles contains an empty role", name)
		}
		for svc, roles := range aud.Services {
			// A grant naming an unknown service is far more likely a typo
			// than an intention, and it would fail silently otherwise.
			if _, ok := services[svc]; !ok {
				return fmt.Errorf("audience %q: service %q is not defined under services", name, svc)
			}
			if len(roles) == 0 || slices.Contains(roles, "") {
				return fmt.Errorf("audience %q: service %q needs a non-empty list of roles", name, svc)
			}
		}
	}
	return nil
}

// validateAudienceName keeps audience names printable, so that what an
// approver reads on the confirmation page is exactly what goes into "aud".
func validateAudienceName(name string) error {
	if name == "" || len(name) > 255 {
		return fmt.Errorf("audience %q: name must be 1 to 255 characters", name)
	}
	for _, r := range name {
		if unicode.IsSpace(r) || !unicode.IsPrint(r) {
			return fmt.Errorf("audience %q: name must not contain whitespace or control characters", name)
		}
	}
	return nil
}

// grantsService reports whether any audience names the service. A nil
// receiver (no jwt block) grants nothing.
func (j *JWTConfig) grantsService(service string) bool {
	if j == nil {
		return false
	}
	for _, aud := range j.Audiences {
		if len(aud.Services[service]) > 0 {
			return true
		}
	}
	return false
}

// validityFor resolves the lifetime of a token for one audience.
func (j *JWTConfig) validityFor(aud JWTAudience) time.Duration {
	// Both values were validated at load, so the errors cannot occur here.
	if d, _ := parseJWTValidity(aud.Validity); d > 0 {
		return d
	}
	if d, _ := parseJWTValidity(j.Validity); d > 0 {
		return d
	}
	return defaultJWTValidity
}

// loadKeys reads the signing key and any additional verification keys.
func (j *JWTConfig) loadKeys() error {
	key, err := keyfile.LoadPrivate(j.SigningKey)
	if err != nil {
		return fmt.Errorf("signing_key: %w", err)
	}
	additional := make([]httpcred.VerificationKey, 0, len(j.VerificationKeys))
	for i, vk := range j.VerificationKeys {
		pub, err := keyfile.LoadPublic(vk.Key)
		if err != nil {
			return fmt.Errorf("verification_keys[%d]: %w", i, err)
		}
		additional = append(additional, httpcred.VerificationKey{KeyID: vk.KeyID, Key: pub})
	}
	return j.useKey(key, additional...)
}

// useKey installs already-parsed key material.
func (j *JWTConfig) useKey(key ed25519.PrivateKey, additional ...httpcred.VerificationKey) error {
	issuer, err := httpcred.NewIssuer(j.Issuer, key, j.KeyID, additional...)
	if err != nil {
		return err
	}
	approvalKey, err := hkdf.Key(sha256.New, key.Seed(), nil, "voussh browser approval v1", sha256.Size)
	if err != nil {
		return err
	}
	j.keys = &jwtKeys{issuer: issuer, approvalKey: approvalKey}
	return nil
}

// rejectCAKey refuses a config in which a token key is the SSH CA key. The
// two must be separate: a relying service that pins the token key would
// otherwise be trusting the key that signs SSH certificates, and rotating or
// losing either would take the other with it. An unreadable CA key is not
// this function's concern — startup reports that itself.
func (j *JWTConfig) rejectCAKey(caKeyPath string) error {
	data, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil
	}
	wrapped, ok := signer.PublicKey().(ssh.CryptoPublicKey)
	if !ok {
		return nil
	}
	ca, ok := wrapped.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return nil
	}
	for _, key := range j.keys.issuer.Keys() {
		if bytes.Equal(key.Key, ca) {
			return errors.New("the SSH CA key must not be used as a token key; generate a separate one with `voussh jwt-init`")
		}
	}
	return nil
}

// denyFraming forbids rendering a page inside a frame. The approval pages
// turn one click into a credential, so they must not be embeddable in a page
// that disguises what is being clicked.
func denyFraming(w http.ResponseWriter) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
}

// jwtEnabled reports whether this config can issue tokens.
func (c *Config) jwtEnabled() bool {
	return c.JWT != nil && c.JWT.keys != nil
}

// ---------------------------------------------------------------------------
// Authorization. Two questions, kept apart on purpose: "does this identity
// hold this role?" is answered by the same users map that governs SSH, while
// "may this role be used at this audience?" is answered only by jwt.audiences.
// SSH principals play no part in either.
// ---------------------------------------------------------------------------

// errJWTDisabled means the server has no jwt block.
var errJWTDisabled = errors.New("this server does not issue HTTP credentials")

// jwtDenied is a refusal on policy grounds, as opposed to a malformed request.
type jwtDenied struct{ reason string }

func (e *jwtDenied) Error() string { return e.reason }

func denyJWT(format string, args ...any) error {
	return &jwtDenied{reason: fmt.Sprintf(format, args...)}
}

// jwtErrorStatus maps an authorization error onto an HTTP status.
func jwtErrorStatus(err error) int {
	var denied *jwtDenied
	switch {
	case errors.Is(err, errJWTDisabled):
		return http.StatusNotFound
	case errors.As(err, &denied):
		return http.StatusForbidden
	default:
		return http.StatusBadRequest
	}
}

// jwtGrant is a fully authorized token request. Every field is derived from
// server-side policy and a verified identity; the only things a client
// contributes are which configured audience and which of its own roles it
// wants, and both have been checked by the time a grant exists.
type jwtGrant struct {
	Subject     string
	SubjectType string
	Audience    string
	Role        string
	Validity    time.Duration
}

// jwtAudience looks up a requested audience. Only names present in
// jwt.audiences exist; there is no wildcard and no default.
func (c *Config) jwtAudience(audience string) (JWTAudience, error) {
	if !c.jwtEnabled() {
		return JWTAudience{}, errJWTDisabled
	}
	if audience == "" {
		return JWTAudience{}, denyJWT("an audience is required")
	}
	aud, ok := c.JWT.Audiences[audience]
	if !ok {
		return JWTAudience{}, denyJWT("audience %q is not configured on this server", audience)
	}
	return aud, nil
}

// authorizeUserJWT decides whether a verified user may have a token for an
// audience in a role. An empty role selects "default", as it does for SSH.
func authorizeUserJWT(cfg *Config, email, audience, role string) (jwtGrant, error) {
	aud, err := cfg.jwtAudience(audience)
	if err != nil {
		return jwtGrant{}, err
	}
	// Role membership comes from the users map. The principals attached to
	// the role are SSH's business and are ignored: a role may map to an empty
	// principal list and still be valid here.
	role, _, err = resolveRole(cfg, email, role)
	if err != nil {
		return jwtGrant{}, denyJWT("%s", err.Error())
	}
	if !slices.Contains(aud.AllowedRoles, role) {
		return jwtGrant{}, denyJWT("role %q is not allowed for audience %q", role, audience)
	}
	return jwtGrant{
		Subject:     email,
		SubjectType: httpcred.SubjectUser,
		Audience:    audience,
		Role:        role,
		Validity:    cfg.JWT.validityFor(aud),
	}, nil
}

// authorizeServiceJWT decides whether an authenticated service may have a
// token. The role may be omitted only when the service has exactly one.
func authorizeServiceJWT(cfg *Config, service, audience, role string) (jwtGrant, error) {
	aud, err := cfg.jwtAudience(audience)
	if err != nil {
		return jwtGrant{}, err
	}
	roles := aud.Services[service]
	if len(roles) == 0 {
		return jwtGrant{}, denyJWT("service %q is not authorized for audience %q", service, audience)
	}
	if role == "" {
		if len(roles) != 1 {
			return jwtGrant{}, denyJWT("a role is required; service %q may request: %s", service, strings.Join(roles, ", "))
		}
		role = roles[0]
	}
	if !slices.Contains(roles, role) {
		return jwtGrant{}, denyJWT("role %q is not allowed for service %q at audience %q", role, service, audience)
	}
	return jwtGrant{
		// The prefix keeps a service from ever sharing a subject with a user,
		// whatever it is named.
		Subject:     "service:" + service,
		SubjectType: httpcred.SubjectService,
		Audience:    audience,
		Role:        role,
		Validity:    cfg.JWT.validityFor(aud),
	}, nil
}

// issueJWT signs a token for an authorized grant, bound to the holder's key.
func issueJWT(cfg *Config, grant jwtGrant, key ed25519.PublicKey) (string, httpcred.Claims, error) {
	if !cfg.jwtEnabled() {
		return "", httpcred.Claims{}, errJWTDisabled
	}
	return cfg.JWT.keys.issuer.Issue(httpcred.TokenRequest{
		Subject:     grant.Subject,
		SubjectType: grant.SubjectType,
		Audience:    grant.Audience,
		Role:        grant.Role,
		Key:         key,
		Validity:    grant.Validity,
	})
}

// logTokenIssued records an issuance. It logs the token's identifier, never
// the token.
func logTokenIssued(cfg *Config, claims httpcred.Claims, via, sourceIP string) {
	line := fmt.Sprintf("Token issued: sub=%s, aud=%s, role=%s, jti=%s, jkt=%s, kid=%s, validity=%s (until %s), via=%s",
		claims.Subject, strings.Join(claims.Audience, " "), claims.Role, claims.ID, claims.KeyThumbprint,
		cfg.JWT.keys.issuer.KeyID(), claims.Expiry.Sub(claims.IssuedAt), claims.Expiry.Format(time.RFC3339), via)
	if sourceIP != "" {
		line += ", source_ip=" + sourceIP
	}
	log.Print(line)
}

// tokenResponse is how a token reaches a client over JSON: from POST /token
// and from the device flow's /device/token.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Audience    string `json:"audience"`
	Role        string `json:"role"`
	Subject     string `json:"subject"`
}

func newTokenResponse(token string, claims httpcred.Claims) tokenResponse {
	return tokenResponse{
		AccessToken: token,
		TokenType:   httpcred.AuthScheme,
		ExpiresIn:   int(time.Until(claims.Expiry).Round(time.Second).Seconds()),
		Audience:    strings.Join(claims.Audience, " "),
		Role:        claims.Role,
		Subject:     claims.Subject,
	}
}

// decodeJWKParam decodes a base64url-wrapped public JWK, as carried in a URL
// or form field by the interactive flows.
func decodeJWKParam(value string) (ed25519.PublicKey, error) {
	if value == "" {
		return nil, errors.New("missing jwk")
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, errors.New("jwk is not valid base64url")
	}
	return httpcred.ParsePublicJWK(raw)
}

// ---------------------------------------------------------------------------
// GET /.well-known/jwks.json — the public verification keys.
// ---------------------------------------------------------------------------

func handleJWKS(w http.ResponseWriter, r *http.Request) {
	cfg := currentConfig()
	if !cfg.jwtEnabled() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Write(cfg.JWT.keys.issuer.JWKS())
}

// ---------------------------------------------------------------------------
// POST /token — machine identities. Authentication is the service bearer
// token already used by /sign; authorization is jwt.audiences.<aud>.services
// and nothing else.
// ---------------------------------------------------------------------------

type tokenRequest struct {
	Audience string          `json:"audience"`
	Role     string          `json:"role"`
	JWK      json.RawMessage `json:"jwk"`
}

func handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg := currentConfig()

	// Same rule as /sign: one fixed answer for every authentication failure.
	token, ok := bearerToken(r)
	if !ok {
		log.Printf("Token: request without a bearer token from %s", clientIP(r))
		writeDeviceError(w, http.StatusUnauthorized, "unauthorized", "")
		return
	}
	name, _, ok := authenticateService(cfg, token)
	if !ok {
		log.Printf("Token: rejected unknown token from %s", clientIP(r))
		writeDeviceError(w, http.StatusUnauthorized, "unauthorized", "")
		return
	}
	if !cfg.jwtEnabled() {
		writeDeviceError(w, http.StatusNotFound, "not_found", errJWTDisabled.Error())
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxTokenRequestBody))
	if err != nil {
		writeDeviceError(w, http.StatusBadRequest, "invalid_request", "request body too large or unreadable")
		return
	}
	// Unknown fields are an error rather than ignored: a client that sends
	// "sub" or "exp" should learn at once that it does not get to choose them.
	var req tokenRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		writeDeviceError(w, http.StatusBadRequest, "invalid_request", "body must be a JSON object with audience, jwk and optionally role")
		return
	}
	key, err := httpcred.ParsePublicJWK(req.JWK)
	if err != nil {
		writeDeviceError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	grant, err := authorizeServiceJWT(cfg, name, req.Audience, req.Role)
	if err != nil {
		log.Printf("Token: denied service=%s audience=%q role=%q from %s: %v", name, req.Audience, req.Role, clientIP(r), err)
		writeDeviceError(w, jwtErrorStatus(err), "access_denied", err.Error())
		return
	}
	signed, claims, err := issueJWT(cfg, grant, key)
	if err != nil {
		log.Printf("Token: failed to sign token for service %q: %v", name, err)
		writeDeviceError(w, http.StatusInternalServerError, "server_error", "failed to issue the token")
		return
	}

	logTokenIssued(cfg, claims, "service", clientIP(r))
	writeJSON(w, http.StatusOK, newTokenResponse(signed, claims))
}

// ---------------------------------------------------------------------------
// Browser flow. /login and /callback are shared with SSH; a token request
// adds one step the certificate flow does not have — a confirmation page
// naming the audience — because a silent Google sign-in must not be enough to
// mint a credential for a service the user never saw named.
// ---------------------------------------------------------------------------

// validCLIPort reports whether a client-supplied loopback port is a plain
// port number. The value is spliced into a redirect URL, so anything else
// (for instance "1@evil.example") would send the credential off-host.
func validCLIPort(port string) bool {
	if port == "" || len(port) > 5 {
		return false
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}

// validCLIState bounds the opaque value the CLI uses to recognise its own
// login when the browser returns.
func validCLIState(state string) bool {
	if len(state) > 128 {
		return false
	}
	for _, r := range state {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// cliCallback builds the loopback URL the browser is sent back to.
func cliCallback(port string, params url.Values) string {
	return "http://localhost:" + port + "/callback?" + params.Encode()
}

// handleJWTLogin continues /login when the request is for a token.
func handleJWTLogin(w http.ResponseWriter, r *http.Request) {
	cfg := currentConfig()
	q := r.URL.Query()

	if q.Get("pubkey") != "" {
		http.Error(w, "Request either an SSH certificate (pubkey) or an HTTP credential (audience, jwk), not both", http.StatusBadRequest)
		return
	}
	audience := q.Get("audience")
	if _, err := cfg.jwtAudience(audience); err != nil {
		http.Error(w, err.Error(), jwtErrorStatus(err))
		return
	}
	key, err := decodeJWKParam(q.Get("jwk"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// A token is only ever delivered to a listening CLI; there is no
	// copy-and-paste fallback page as there is for certificates.
	if !validCLIPort(q.Get("cli_port")) {
		http.Error(w, "A valid cli_port is required: start this login with `vsh token login`", http.StatusBadRequest)
		return
	}
	if !validCLIState(q.Get("cli_state")) {
		http.Error(w, "Invalid cli_state", http.StatusBadRequest)
		return
	}

	state, err := encodeState(StateData{
		Port:     q.Get("cli_port"),
		Role:     q.Get("role"),
		Audience: audience,
		JWK:      string(httpcred.MarshalPublicJWK(key)),
		Nonce:    q.Get("cli_state"),
	})
	if err != nil {
		http.Error(w, "Failed to encode state", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusTemporaryRedirect)
}

// jwtApproval is the request a user is asked to confirm, carried through the
// browser inside a MAC so the server needs no session to recognise it again.
type jwtApproval struct {
	Email    string `json:"e"`
	Audience string `json:"a"`
	Role     string `json:"r"`
	JWK      string `json:"k"`
	Port     string `json:"p"`
	Nonce    string `json:"n,omitempty"`
	Expires  int64  `json:"x"`
}

func approvalMAC(key []byte, payload string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("jwt-approval\x00" + payload))
	return mac.Sum(nil)
}

// sealApproval serializes and authenticates an approval.
func sealApproval(key []byte, a jwtApproval) (string, error) {
	raw, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	return payload + "." + base64.RawURLEncoding.EncodeToString(approvalMAC(key, payload)), nil
}

// openApproval verifies and decodes an approval, rejecting expired ones.
func openApproval(key []byte, sealed string, now time.Time) (jwtApproval, bool) {
	payload, sig, ok := strings.Cut(sealed, ".")
	if !ok {
		return jwtApproval{}, false
	}
	mac, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(mac, approvalMAC(key, payload)) {
		return jwtApproval{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return jwtApproval{}, false
	}
	var a jwtApproval
	if err := json.Unmarshal(raw, &a); err != nil || now.Unix() > a.Expires {
		return jwtApproval{}, false
	}
	return a, true
}

// handleJWTCallback continues /callback when the login was for a token. The
// caller has already verified the ID token. Nothing is signed here: the user
// is shown what was asked for and must confirm it.
func handleJWTCallback(w http.ResponseWriter, r *http.Request, state StateData, email string) {
	cfg := currentConfig()
	if !cfg.jwtEnabled() {
		http.Error(w, errJWTDisabled.Error(), http.StatusNotFound)
		return
	}
	// The state parameter is not authenticated, so everything in it is
	// validated again exactly as /login validated the query.
	if !validCLIPort(state.Port) || !validCLIState(state.Nonce) {
		http.Error(w, "Invalid login state", http.StatusBadRequest)
		return
	}
	key, err := httpcred.ParsePublicJWK([]byte(state.JWK))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	grant, err := authorizeUserJWT(cfg, email, state.Audience, state.Role)
	if err != nil {
		log.Printf("Token: denied sub=%s audience=%q role=%q via=browser: %v", email, state.Audience, state.Role, err)
		redirectCLIError(w, r, state.Port, state.Nonce, err.Error())
		return
	}

	sealed, err := sealApproval(cfg.JWT.keys.approvalKey, jwtApproval{
		Email:    email,
		Audience: grant.Audience,
		Role:     grant.Role,
		JWK:      string(httpcred.MarshalPublicJWK(key)),
		Port:     state.Port,
		Nonce:    state.Nonce,
		Expires:  time.Now().Add(jwtApprovalTTL).Unix(),
	})
	if err != nil {
		http.Error(w, "Failed to prepare approval", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	denyFraming(w)
	data := jwtApprovalData{
		Title:      "Issue an HTTP credential",
		Email:      email,
		Audience:   grant.Audience,
		Role:       grant.Role,
		Thumbprint: httpcred.Thumbprint(key),
		Validity:   grant.Validity.String(),
		Approval:   sealed,
	}
	if err := jwtApprovalTmpl.Execute(w, data); err != nil {
		log.Printf("Token: failed to render approval page: %v", err)
	}
}

// redirectCLIError sends the browser back to the waiting CLI with a refusal,
// so the terminal reports it instead of sitting until its timeout.
func redirectCLIError(w http.ResponseWriter, r *http.Request, port, nonce, description string) {
	params := url.Values{"error": {"access_denied"}, "error_description": {description}}
	if nonce != "" {
		params.Set("state", nonce)
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, cliCallback(port, params), http.StatusSeeOther)
}

// handleLoginApprove is POST /login/approve: the user confirmed or rejected
// the token request shown by handleJWTCallback.
func handleLoginApprove(w http.ResponseWriter, r *http.Request) {
	cfg := currentConfig()
	if !cfg.jwtEnabled() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenRequestBody)
	if err := r.ParseForm(); err != nil {
		renderDeviceResult(w, http.StatusBadRequest, "Error", "Malformed request.", false)
		return
	}

	// The MAC is the whole authentication of this request: it was handed only
	// to the browser that completed the Google login, which makes the form
	// unforgeable by a third party (no CSRF) and tamper-proof (the audience,
	// role, key and identity are the ones that were displayed).
	//
	// Keeping no server-side state means the form is not single-use: within
	// jwtApprovalTTL the same browser can submit it again and receive another
	// token. That token is for the same identity, audience, role and key as
	// the first, so resubmitting gains nothing but a later expiry — at most
	// jwtApprovalTTL later.
	approval, ok := openApproval(cfg.JWT.keys.approvalKey, r.PostForm.Get("approval"), time.Now())
	if !ok || !validCLIPort(approval.Port) {
		renderDeviceResult(w, http.StatusForbidden, "Request unavailable",
			"That request has expired or is not valid. Run the login again.", false)
		return
	}

	if r.PostForm.Get("action") != "approve" {
		log.Printf("Token: request for audience %q rejected by %s", approval.Audience, approval.Email)
		redirectCLIError(w, r, approval.Port, approval.Nonce, "the request was rejected")
		return
	}

	key, err := httpcred.ParsePublicJWK([]byte(approval.JWK))
	if err != nil {
		renderDeviceResult(w, http.StatusBadRequest, "Error", "The requested key is not usable.", false)
		return
	}
	// Policy is evaluated again at the moment of signing, against the config
	// in force now: a user or role removed while the page was open gets
	// nothing.
	grant, err := authorizeUserJWT(cfg, approval.Email, approval.Audience, approval.Role)
	if err != nil {
		log.Printf("Token: denied sub=%s audience=%q role=%q via=browser: %v", approval.Email, approval.Audience, approval.Role, err)
		redirectCLIError(w, r, approval.Port, approval.Nonce, err.Error())
		return
	}
	token, claims, err := issueJWT(cfg, grant, key)
	if err != nil {
		log.Printf("Token: failed to sign token for %s: %v", approval.Email, err)
		renderDeviceResult(w, http.StatusInternalServerError, "Error", "Failed to issue the token.", false)
		return
	}
	logTokenIssued(cfg, claims, "browser", clientIP(r))

	params := url.Values{"jwt": {token}}
	if approval.Nonce != "" {
		params.Set("state", approval.Nonce)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, cliCallback(approval.Port, params), http.StatusSeeOther)
}

type jwtApprovalData struct {
	Title      string
	Email      string
	Audience   string
	Role       string
	Thumbprint string
	Validity   string
	Approval   string
}

var jwtApprovalTmpl = template.Must(template.New("layout").Parse(devicePageLayout))

func init() {
	template.Must(jwtApprovalTmpl.New("body").Parse(`
<h2>Issue an HTTP credential?</h2>
<p>Signed in as <strong>{{.Email}}</strong>.</p>
<table style="border-collapse: collapse; margin: 20px 0; width: 100%;">
<tr><td style="padding: 6px 12px 6px 0; color: #666;">Audience</td><td><strong>{{.Audience}}</strong></td></tr>
<tr><td style="padding: 6px 12px 6px 0; color: #666;">Role</td><td><strong>{{.Role}}</strong></td></tr>
<tr><td style="padding: 6px 12px 6px 0; color: #666;">Valid for</td><td>{{.Validity}}</td></tr>
<tr><td style="padding: 6px 12px 6px 0; color: #666;">Client key</td>
    <td style="font-family: monospace; font-size: 13px; word-break: break-all;">{{.Thumbprint}}</td></tr>
</table>
<p style="background: #fff8e1; border-left: 3px solid #f0ad4e; padding: 12px; font-size: 14px;">
Approving issues an access token that lets the holder of that key act as you, in the role shown,
at the service named under Audience. If you did not start this login, or the key thumbprint does
not match the one printed in your terminal, choose Reject.</p>
<form method="POST" action="/login/approve">
<input type="hidden" name="approval" value="{{.Approval}}">
<button type="submit" name="action" value="approve"
 style="padding: 10px 20px; font-size: 16px; margin-right: 10px;">Approve</button>
<button type="submit" name="action" value="deny"
 style="padding: 10px 20px; font-size: 16px;">Reject</button>
</form>`))
}

// ---------------------------------------------------------------------------
// Command line: key generation and offline export of the published key set.
// ---------------------------------------------------------------------------

// cmdJWTInit generates a token signing key pair.
func cmdJWTInit(args []string) {
	keyPath := "jwt_ed25519"
	if len(args) > 0 {
		keyPath = args[0]
	}
	pub, err := generateKeyPair(keyPath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Token signing key pair generated:\n")
	fmt.Printf("  Private key: %s\n", keyPath)
	fmt.Printf("  Public key:  %s.pub\n", keyPath)
	fmt.Printf("  Key ID:      %s\n", httpcred.Thumbprint(pub))
	fmt.Println()
	fmt.Println("Reference the private key as jwt.signing_key in the config, then run")
	fmt.Println("`voussh jwks --config <file>` to print the public key set for relying services to pin.")
}

// cmdJWKS prints the key set exactly as /.well-known/jwks.json would serve
// it, without starting the server or touching the network.
func cmdJWKS(configFile string) {
	cfg, err := loadConfig(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config file %s: %v\n", configFile, err)
		os.Exit(1)
	}
	if !cfg.jwtEnabled() {
		fmt.Fprintf(os.Stderr, "%s has no jwt block\n", configFile)
		os.Exit(1)
	}
	os.Stdout.Write(cfg.JWT.keys.issuer.JWKS())
}

// sortedAudiences lists the configured audience names, for logging.
func (j *JWTConfig) sortedAudiences() []string {
	names := make([]string, 0, len(j.Audiences))
	for name := range j.Audiences {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
