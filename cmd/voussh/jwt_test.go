package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tlamadon/voussh/httpcred"
	"golang.org/x/crypto/ssh"
)

const (
	testJWTIssuer    = "https://auth.example.com"
	testBrokerOrigin = "https://broker.example.com"
	testBrokerURL    = testBrokerOrigin + "/v1/secrets/db-password"
	// A second machine identity, distinct from testServiceToken's.
	testAgentToken = "7d1e9b02c4a84f11-not-a-real-token"
)

// jwtTestConfig returns a config with HTTP credentials enabled:
//
//   - alice holds default (root, admin), deploy (deploy) and reader, a role
//     with no SSH principals at all;
//   - secret-broker admits the roles default, admin and reader — admin being
//     one alice does not hold, deploy being one she holds but is not admitted;
//   - herdr-hq is an SSH-only service; agent is a token-only service.
func jwtTestConfig(t *testing.T) *Config {
	t.Helper()
	cfg := testConfig()
	cfg.Users["alice@example.com"]["reader"] = []string{}
	cfg.Users["bob@example.com"] = map[string][]string{"admin": {"root"}}
	cfg.Services = map[string]ServiceConfig{
		"herdr-hq": {TokenSHA256: sha256Hex(testServiceToken), Principals: []string{"tlamadon"}},
		"agent":    {TokenSHA256: sha256Hex(testAgentToken)},
	}
	cfg.JWT = &JWTConfig{
		Issuer:     testJWTIssuer,
		SigningKey: "unused-in-tests",
		Audiences: map[string]JWTAudience{
			"secret-broker": {
				AllowedRoles: []string{"default", "admin", "reader"},
				Services:     map[string][]string{"agent": {"fetch", "rotate"}},
			},
			"billing-api": {
				AllowedRoles: []string{"default"},
				Validity:     "5m",
			},
		},
	}
	if err := cfg.validate(); err != nil {
		t.Fatalf("test config is invalid: %v", err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.JWT.useKey(key); err != nil {
		t.Fatalf("install signing key: %v", err)
	}
	return cfg
}

// testClient is the holder of a proof-of-possession key.
type testClient struct {
	key ed25519.PrivateKey
}

func newTestClient(t *testing.T) *testClient {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testClient{key: key}
}

func (c *testClient) pub() ed25519.PublicKey { return c.key.Public().(ed25519.PublicKey) }
func (c *testClient) jwk() []byte            { return httpcred.MarshalPublicJWK(c.pub()) }
func (c *testClient) jwkParam() string       { return base64.RawURLEncoding.EncodeToString(c.jwk()) }
func (c *testClient) thumbprint() string     { return httpcred.Thumbprint(c.pub()) }

// publishedKeys fetches the key set through the real endpoint, the way an
// operator would when pinning it.
func publishedKeys(t *testing.T) []httpcred.VerificationKey {
	t.Helper()
	rr := httptest.NewRecorder()
	handleJWKS(rr, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("jwks = %d, body %s", rr.Code, rr.Body.String())
	}
	keys, err := httpcred.ParseJWKS(rr.Body.Bytes())
	if err != nil {
		t.Fatalf("published JWKS does not parse: %v", err)
	}
	return keys
}

// brokerAccepts plays the relying service: it verifies the token offline
// against the published keys, with a DPoP proof made by the client, exactly
// as docs/http-credentials.md prescribes. Every issuance test ends here, so
// "a token was issued" always means "a token a broker would accept".
func brokerAccepts(t *testing.T, client *testClient, token, audience string) httpcred.Claims {
	t.Helper()
	verifier, err := httpcred.NewVerifier(httpcred.VerifierConfig{
		Issuer:   testJWTIssuer,
		Audience: audience,
		Keys:     publishedKeys(t),
		Origin:   testBrokerOrigin,
	})
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}
	proof, err := httpcred.NewProof(client.key, httpcred.ProofParams{Method: "GET", URL: testBrokerURL, AccessToken: token})
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}
	claims, err := verifier.Verify(httpcred.Request{
		Method: "GET", URL: testBrokerURL, Authorization: "DPoP " + token, DPoP: []string{proof},
	})
	if err != nil {
		t.Fatalf("broker rejected the issued token: %v", err)
	}
	return claims
}

func postToken(serviceToken string, body any) *httptest.ResponseRecorder {
	var raw []byte
	switch b := body.(type) {
	case string:
		raw = []byte(b)
	default:
		raw, _ = json.Marshal(b)
	}
	req := httptest.NewRequest(http.MethodPost, "/token", bytes.NewReader(raw))
	if serviceToken != "" {
		req.Header.Set("Authorization", "Bearer "+serviceToken)
	}
	rr := httptest.NewRecorder()
	handleToken(rr, req)
	return rr
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

func tokenBody(client *testClient, audience, role string) map[string]any {
	body := map[string]any{"audience": audience, "jwk": json.RawMessage(client.jwk())}
	if role != "" {
		body["role"] = role
	}
	return body
}

func decodeTokenResponse(t *testing.T, rr *httptest.ResponseRecorder) tokenResponse {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rr.Code, rr.Body.String())
	}
	var resp tokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("response carries no token")
	}
	return resp
}

// ---------------------------------------------------------------------------
// Public verification keys
// ---------------------------------------------------------------------------

func TestJWKSEndpoint(t *testing.T) {
	t.Run("absent without a jwt block", func(t *testing.T) {
		setupDeviceTest(t, nil)
		rr := httptest.NewRecorder()
		handleJWKS(rr, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rr.Code)
		}
	})

	cfg := jwtTestConfig(t)
	setupDeviceTest(t, cfg)

	rr := httptest.NewRecorder()
	handleJWKS(rr, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/jwk-set+json" {
		t.Errorf("Content-Type = %q", ct)
	}
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &set); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(set.Keys))
	}
	key := set.Keys[0]
	for member, want := range map[string]string{"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig"} {
		if key[member] != want {
			t.Errorf("%s = %v, want %s", member, key[member], want)
		}
	}
	if key["kid"] == "" || key["x"] == "" {
		t.Errorf("key is missing kid or x: %v", key)
	}
	if _, leaked := key["d"]; leaked || len(key) != 6 {
		t.Errorf("key has members beyond the public metadata: %v", key)
	}

	rr = httptest.NewRecorder()
	handleJWKS(rr, httptest.NewRequest(http.MethodPost, "/.well-known/jwks.json", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST = %d, want 405", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Authorization policy
// ---------------------------------------------------------------------------

func TestAuthorizeUserJWT(t *testing.T) {
	cfg := jwtTestConfig(t)
	cases := []struct {
		name                  string
		email, audience, role string
		wantRole              string // empty means the request must be refused
		wantValidity          time.Duration
	}{
		{"default role", "alice@example.com", "secret-broker", "", "default", 15 * time.Minute},
		{"explicit role", "alice@example.com", "secret-broker", "default", "default", 15 * time.Minute},
		{"role without ssh principals", "alice@example.com", "secret-broker", "reader", "reader", 15 * time.Minute},
		{"per-audience validity", "alice@example.com", "billing-api", "", "default", 5 * time.Minute},
		{"another user's role", "bob@example.com", "secret-broker", "admin", "admin", 15 * time.Minute},

		{"unknown user", "mallory@example.com", "secret-broker", "", "", 0},
		{"audience not configured", "alice@example.com", "payroll", "", "", 0},
		{"empty audience", "alice@example.com", "", "", "", 0},
		{"audience differing only in case", "alice@example.com", "Secret-Broker", "", "", 0},
		// Allowed at the audience, but alice does not hold it.
		{"role not held", "alice@example.com", "secret-broker", "admin", "", 0},
		// Held by alice, but the audience does not admit it.
		{"role not allowed for audience", "alice@example.com", "secret-broker", "deploy", "", 0},
		{"role allowed elsewhere only", "alice@example.com", "billing-api", "reader", "", 0},
		// bob has no default role, so an unspecified role resolves to nothing.
		{"no default role", "bob@example.com", "secret-broker", "", "", 0},
		// Service roles are not user roles, whoever asks.
		{"service role requested by a user", "alice@example.com", "secret-broker", "fetch", "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			grant, err := authorizeUserJWT(cfg, tc.email, tc.audience, tc.role)
			if tc.wantRole == "" {
				if err == nil {
					t.Fatalf("granted %+v, want a refusal", grant)
				}
				if status := jwtErrorStatus(err); status != http.StatusForbidden {
					t.Errorf("refusal maps to %d, want 403", status)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			want := jwtGrant{
				Subject: tc.email, SubjectType: httpcred.SubjectUser,
				Audience: tc.audience, Role: tc.wantRole, Validity: tc.wantValidity,
			}
			if grant != want {
				t.Errorf("grant = %+v, want %+v", grant, want)
			}
		})
	}

	t.Run("disabled", func(t *testing.T) {
		_, err := authorizeUserJWT(testConfig(), "alice@example.com", "secret-broker", "")
		if jwtErrorStatus(err) != http.StatusNotFound {
			t.Errorf("error = %v, want the not-enabled error", err)
		}
	})
}

// SSH principals and HTTP roles are separate currencies: a role that carries
// no principals is useless for SSH and perfectly good for a token, and the
// principals a role does carry never appear in a token.
func TestPrincipalsAreNotHTTPPermissions(t *testing.T) {
	cfg := jwtTestConfig(t)
	setupDeviceTest(t, cfg)

	if _, _, err := resolvePrincipals("alice@example.com", "reader"); err == nil {
		t.Error("SSH accepted a role with no principals")
	}
	grant, err := authorizeUserJWT(cfg, "alice@example.com", "secret-broker", "reader")
	if err != nil {
		t.Fatalf("token refused for a principal-less role: %v", err)
	}

	client := newTestClient(t)
	token, _, err := issueJWT(cfg, grant, client.pub())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	for _, principal := range []string{"root", "admin", "deploy", "principals"} {
		if bytes.Contains(payload, []byte(`"`+principal+`"`)) {
			t.Errorf("token payload mentions %q: %s", principal, payload)
		}
	}
}

// ---------------------------------------------------------------------------
// Machine identities: POST /token
// ---------------------------------------------------------------------------

func TestTokenEndpointIssuesForGrantedService(t *testing.T) {
	setupDeviceTest(t, jwtTestConfig(t))
	client := newTestClient(t)

	rr := postToken(testAgentToken, tokenBody(client, "secret-broker", "fetch"))
	resp := decodeTokenResponse(t, rr)

	if resp.TokenType != "DPoP" || resp.Audience != "secret-broker" || resp.Role != "fetch" || resp.Subject != "service:agent" {
		t.Errorf("response = %+v", resp)
	}
	if resp.ExpiresIn < 890 || resp.ExpiresIn > 900 {
		t.Errorf("expires_in = %d, want ~900 (the 15m default)", resp.ExpiresIn)
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}

	claims := brokerAccepts(t, client, resp.AccessToken, "secret-broker")
	if claims.Subject != "service:agent" || claims.SubjectType != httpcred.SubjectService || claims.Role != "fetch" {
		t.Errorf("claims = %+v", claims)
	}
	if claims.Issuer != testJWTIssuer || claims.KeyThumbprint != client.thumbprint() || claims.ID == "" {
		t.Errorf("claims = %+v", claims)
	}
	if d := claims.Expiry.Sub(claims.IssuedAt); d != 15*time.Minute {
		t.Errorf("lifetime = %s, want 15m", d)
	}
	if !claims.NotBefore.Equal(claims.IssuedAt) {
		t.Errorf("nbf %s != iat %s", claims.NotBefore, claims.IssuedAt)
	}
}

func TestTokenEndpointAuthorizationBoundaries(t *testing.T) {
	setupDeviceTest(t, jwtTestConfig(t))
	client := newTestClient(t)

	// The central boundary: herdr-hq can already obtain SSH certificates
	// through /sign, and that buys it nothing here.
	t.Run("ssh service has no token rights", func(t *testing.T) {
		if rr := postSign(testServiceToken, testPubKey(t, "")); rr.Code != http.StatusOK {
			t.Fatalf("precondition: /sign = %d, want 200", rr.Code)
		}
		for _, role := range []string{"", "fetch", "default", "admin"} {
			rr := postToken(testServiceToken, tokenBody(client, "secret-broker", role))
			if rr.Code != http.StatusForbidden {
				t.Errorf("role %q: status = %d, want 403; body %s", role, rr.Code, rr.Body.String())
			}
		}
	})

	// And the reverse: a token-only service gets no certificate.
	t.Run("token service has no ssh rights", func(t *testing.T) {
		rr := postSign(testAgentToken, testPubKey(t, ""))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("/sign = %d, want 403", rr.Code)
		}
		if _, _, _, _, err := ssh.ParseAuthorizedKey(rr.Body.Bytes()); err == nil {
			t.Fatal("/sign returned something that parses as a key")
		}
	})

	refused := []struct {
		name           string
		audience, role string
	}{
		{"audience not configured", "payroll", "fetch"},
		{"audience that grants the service nothing", "billing-api", "fetch"},
		{"role not granted", "secret-broker", "admin"},
		// allowed_roles is for users; it does not extend to services.
		{"user role", "secret-broker", "default"},
		{"role omitted with several granted", "secret-broker", ""},
		{"empty audience", "", "fetch"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			rr := postToken(testAgentToken, tokenBody(client, tc.audience, tc.role))
			if rr.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body %s", rr.Code, rr.Body.String())
			}
			if strings.Contains(rr.Body.String(), "access_token") {
				t.Fatal("refusal carries a token")
			}
		})
	}

	t.Run("role may be omitted when exactly one is granted", func(t *testing.T) {
		cfg := jwtTestConfig(t)
		aud := cfg.JWT.Audiences["secret-broker"]
		aud.Services = map[string][]string{"agent": {"fetch"}}
		cfg.JWT.Audiences["secret-broker"] = aud
		setupDeviceTest(t, cfg)
		defer setupDeviceTest(t, jwtTestConfig(t))

		resp := decodeTokenResponse(t, postToken(testAgentToken, tokenBody(client, "secret-broker", "")))
		if resp.Role != "fetch" {
			t.Errorf("role = %q, want fetch", resp.Role)
		}
	})
}

func TestTokenEndpointRejectsBadRequests(t *testing.T) {
	setupDeviceTest(t, jwtTestConfig(t))
	client := newTestClient(t)
	good := tokenBody(client, "secret-broker", "fetch")

	t.Run("no bearer token", func(t *testing.T) {
		if rr := postToken("", good); rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rr.Code)
		}
	})
	t.Run("unknown bearer token", func(t *testing.T) {
		rr := postToken("not-a-token", good)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rr.Code)
		}
		if strings.Contains(rr.Body.String(), "not-a-token") {
			t.Error("response echoes the presented token")
		}
	})
	t.Run("GET", func(t *testing.T) {
		rr := httptest.NewRecorder()
		handleToken(rr, httptest.NewRequest(http.MethodGet, "/token", nil))
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", rr.Code)
		}
	})

	// The issuer decides every claim. A request that tries to supply one is
	// rejected outright rather than having the extra field quietly dropped.
	for _, claim := range []string{"sub", "exp", "iss", "aud", "cnf", "principals", "validity"} {
		t.Run("client-supplied "+claim, func(t *testing.T) {
			body := tokenBody(client, "secret-broker", "fetch")
			body[claim] = "attacker-chosen"
			if rr := postToken(testAgentToken, body); rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", rr.Code, rr.Body.String())
			}
		})
	}

	bad := map[string]string{
		"not json":    `audience=secret-broker`,
		"missing jwk": `{"audience":"secret-broker","role":"fetch"}`,
		"private jwk": fmt.Sprintf(`{"audience":"secret-broker","role":"fetch","jwk":{"kty":"OKP","crv":"Ed25519","x":%q,"d":%q}}`,
			base64.RawURLEncoding.EncodeToString(client.pub()), base64.RawURLEncoding.EncodeToString(client.key.Seed())),
		"rsa jwk":     `{"audience":"secret-broker","role":"fetch","jwk":{"kty":"RSA","n":"AQAB","e":"AQAB"}}`,
		"two objects": string(mustJSON(good)) + string(mustJSON(good)),
		"oversized":   `{"audience":"` + strings.Repeat("a", maxTokenRequestBody) + `"}`,
	}
	for name, body := range bad {
		t.Run(name, func(t *testing.T) {
			if rr := postToken(testAgentToken, body); rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", rr.Code, rr.Body.String())
			}
		})
	}

	t.Run("disabled", func(t *testing.T) {
		cfg := signTestConfig()
		setupDeviceTest(t, cfg)
		if rr := postToken(testServiceToken, good); rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rr.Code)
		}
	})
}

// ---------------------------------------------------------------------------
// Browser flow
// ---------------------------------------------------------------------------

func getLogin(query url.Values) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	handleLogin(rr, httptest.NewRequest(http.MethodGet, "/login?"+query.Encode(), nil))
	return rr
}

// stateFromRedirect decodes the state voussh handed to the identity provider.
func stateFromRedirect(t *testing.T, rr *httptest.ResponseRecorder) StateData {
	t.Helper()
	if rr.Code != http.StatusTemporaryRedirect {
		t.Fatalf("/login = %d, want a redirect; body %s", rr.Code, rr.Body.String())
	}
	location, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Host != "accounts.example.com" {
		t.Fatalf("redirected to %s, want the identity provider", location.Host)
	}
	state, err := decodeState(location.Query().Get("state"))
	if err != nil {
		t.Fatalf("state does not decode: %v", err)
	}
	return state
}

var approvalRE = regexp.MustCompile(`name="approval" value="([^"]+)"`)

// approvalFrom runs the callback leg (the identity has been verified) and
// returns the confirmation page with its sealed approval.
func approvalFrom(t *testing.T, state StateData, email string) (page, sealed string) {
	t.Helper()
	rr := httptest.NewRecorder()
	handleJWTCallback(rr, httptest.NewRequest(http.MethodGet, "/callback", nil), state, email)
	if rr.Code != http.StatusOK {
		t.Fatalf("callback = %d, body %s", rr.Code, rr.Body.String())
	}
	m := approvalRE.FindStringSubmatch(rr.Body.String())
	if m == nil {
		t.Fatalf("no approval field in page: %s", rr.Body.String())
	}
	return rr.Body.String(), m[1]
}

func postApprove(sealed, action string) *httptest.ResponseRecorder {
	return postForm(handleLoginApprove, "/login/approve", url.Values{"approval": {sealed}, "action": {action}})
}

// cliRedirect parses the redirect that returns the browser to the CLI.
func cliRedirect(t *testing.T, rr *httptest.ResponseRecorder, port string) url.Values {
	t.Helper()
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body %s", rr.Code, rr.Body.String())
	}
	location, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Scheme != "http" || location.Host != "localhost:"+port || location.Path != "/callback" || location.User != nil {
		t.Fatalf("redirected to %s, want the CLI listener on localhost:%s", location, port)
	}
	return location.Query()
}

func browserLoginQuery(client *testClient, audience, role string) url.Values {
	q := url.Values{
		"cli_port": {"45678"}, "cli_state": {"nonce-123"},
		"audience": {audience}, "jwk": {client.jwkParam()},
	}
	if role != "" {
		q.Set("role", role)
	}
	return q
}

func TestBrowserFlowIssuesToken(t *testing.T) {
	setupDeviceTest(t, jwtTestConfig(t))
	client := newTestClient(t)

	// 1. vsh opens /login; voussh hands off to the identity provider.
	state := stateFromRedirect(t, getLogin(browserLoginQuery(client, "secret-broker", "")))
	if state.Audience != "secret-broker" || state.Port != "45678" || state.Nonce != "nonce-123" {
		t.Fatalf("state = %+v", state)
	}
	if state.JWK != string(client.jwk()) {
		t.Fatalf("state carries %q, want the canonical JWK", state.JWK)
	}

	// 2. The identity provider returns; the user is shown what was asked for.
	page, sealed := approvalFrom(t, state, "alice@example.com")
	for _, want := range []string{"alice@example.com", "secret-broker", "default", client.thumbprint(), "15m0s"} {
		if !strings.Contains(page, want) {
			t.Errorf("confirmation page does not show %q", want)
		}
	}
	// SSH principals have no business on a token confirmation page.
	if strings.Contains(page, "Principals") || strings.Contains(page, "root") {
		t.Error("confirmation page mentions SSH principals")
	}

	// 3. The user approves; the token goes to the CLI listener.
	params := cliRedirect(t, postApprove(sealed, "approve"), "45678")
	if params.Get("state") != "nonce-123" {
		t.Errorf("state = %q, want the CLI's nonce returned", params.Get("state"))
	}
	token := params.Get("jwt")
	if token == "" {
		t.Fatalf("no token in redirect: %v", params)
	}

	claims := brokerAccepts(t, client, token, "secret-broker")
	if claims.Subject != "alice@example.com" || claims.SubjectType != httpcred.SubjectUser || claims.Role != "default" {
		t.Errorf("claims = %+v", claims)
	}
	if claims.KeyThumbprint != client.thumbprint() {
		t.Error("token is not bound to the client's key")
	}
}

func TestBrowserFlowRequestedRole(t *testing.T) {
	setupDeviceTest(t, jwtTestConfig(t))
	client := newTestClient(t)

	state := stateFromRedirect(t, getLogin(browserLoginQuery(client, "secret-broker", "reader")))
	_, sealed := approvalFrom(t, state, "alice@example.com")
	token := cliRedirect(t, postApprove(sealed, "approve"), "45678").Get("jwt")
	if claims := brokerAccepts(t, client, token, "secret-broker"); claims.Role != "reader" {
		t.Errorf("role = %q, want reader", claims.Role)
	}
}

func TestBrowserFlowRefusals(t *testing.T) {
	cfg := jwtTestConfig(t)
	setupDeviceTest(t, cfg)
	client := newTestClient(t)

	t.Run("reject", func(t *testing.T) {
		state := stateFromRedirect(t, getLogin(browserLoginQuery(client, "secret-broker", "")))
		_, sealed := approvalFrom(t, state, "alice@example.com")
		params := cliRedirect(t, postApprove(sealed, "deny"), "45678")
		if params.Get("error") != "access_denied" || params.Get("jwt") != "" || params.Get("state") != "nonce-123" {
			t.Errorf("redirect = %v, want access_denied and no token", params)
		}
	})

	// Not authorized: the user never reaches a confirmation page, and the
	// waiting CLI is told why.
	for name, tc := range map[string]struct{ email, role string }{
		"unknown user":         {"mallory@example.com", ""},
		"role not held":        {"alice@example.com", "admin"},
		"role not allowed":     {"alice@example.com", "deploy"},
		"user without default": {"bob@example.com", ""},
	} {
		t.Run(name, func(t *testing.T) {
			state := stateFromRedirect(t, getLogin(browserLoginQuery(client, "secret-broker", tc.role)))
			rr := httptest.NewRecorder()
			handleJWTCallback(rr, httptest.NewRequest(http.MethodGet, "/callback", nil), state, tc.email)
			params := cliRedirect(t, rr, "45678")
			if params.Get("error") != "access_denied" || params.Get("jwt") != "" {
				t.Errorf("redirect = %v, want access_denied and no token", params)
			}
			if strings.Contains(rr.Body.String(), "approval") {
				t.Error("an approval form was rendered for an unauthorized request")
			}
		})
	}

	// The sealed approval is the only thing /login/approve trusts, so every
	// way of presenting a different one must fail.
	t.Run("approval cannot be forged or altered", func(t *testing.T) {
		state := stateFromRedirect(t, getLogin(browserLoginQuery(client, "secret-broker", "")))
		_, sealed := approvalFrom(t, state, "alice@example.com")
		payload, sig, _ := strings.Cut(sealed, ".")

		raw, err := base64.RawURLEncoding.DecodeString(payload)
		if err != nil {
			t.Fatal(err)
		}
		var approval jwtApproval
		if err := json.Unmarshal(raw, &approval); err != nil {
			t.Fatal(err)
		}
		reseal := func(mutate func(*jwtApproval)) string {
			a := approval
			mutate(&a)
			altered, _ := json.Marshal(a)
			return base64.RawURLEncoding.EncodeToString(altered) + "." + sig
		}
		attacker := newTestClient(t)

		forgeries := map[string]string{
			"empty":          "",
			"no signature":   payload,
			"bad signature":  payload + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			"other audience": reseal(func(a *jwtApproval) { a.Audience = "billing-api" }),
			"other role":     reseal(func(a *jwtApproval) { a.Role = "reader" }),
			"other identity": reseal(func(a *jwtApproval) { a.Email = "bob@example.com" }),
			"other key":      reseal(func(a *jwtApproval) { a.JWK = string(attacker.jwk()) }),
			"other port":     reseal(func(a *jwtApproval) { a.Port = "1" }),
			"longer expiry":  reseal(func(a *jwtApproval) { a.Expires += 3600 }),
		}
		for name, forged := range forgeries {
			rr := postApprove(forged, "approve")
			if rr.Code != http.StatusForbidden || rr.Header().Get("Location") != "" {
				t.Errorf("%s: status = %d, Location %q; want 403 and no redirect", name, rr.Code, rr.Header().Get("Location"))
			}
		}

		// A key from another deployment cannot mint approvals for this one.
		foreign, err := sealApproval(bytes.Repeat([]byte{7}, 32), approval)
		if err != nil {
			t.Fatal(err)
		}
		if rr := postApprove(foreign, "approve"); rr.Code != http.StatusForbidden {
			t.Errorf("approval sealed with a foreign key: status = %d, want 403", rr.Code)
		}
	})

	t.Run("approval expires", func(t *testing.T) {
		key := cfg.JWT.keys.approvalKey
		sealed, err := sealApproval(key, jwtApproval{
			Email: "alice@example.com", Audience: "secret-broker", Role: "default",
			JWK: string(client.jwk()), Port: "45678", Expires: time.Now().Add(-time.Second).Unix(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if rr := postApprove(sealed, "approve"); rr.Code != http.StatusForbidden {
			t.Errorf("expired approval: status = %d, want 403", rr.Code)
		}
	})

	// Policy is checked again when the user clicks Approve.
	t.Run("authorization withdrawn before approval", func(t *testing.T) {
		state := stateFromRedirect(t, getLogin(browserLoginQuery(client, "secret-broker", "")))
		_, sealed := approvalFrom(t, state, "alice@example.com")

		revoked := jwtTestConfig(t)
		revoked.JWT.keys = cfg.JWT.keys // same keys: only the policy changed
		delete(revoked.Users, "alice@example.com")
		configPtr.Store(revoked)
		defer configPtr.Store(cfg)

		params := cliRedirect(t, postApprove(sealed, "approve"), "45678")
		if params.Get("error") != "access_denied" || params.Get("jwt") != "" {
			t.Errorf("redirect = %v, want access_denied and no token", params)
		}
	})

	t.Run("GET is not an approval", func(t *testing.T) {
		rr := httptest.NewRecorder()
		handleLoginApprove(rr, httptest.NewRequest(http.MethodGet, "/login/approve", nil))
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want 405", rr.Code)
		}
	})
}

func TestBrowserLoginValidatesRequest(t *testing.T) {
	setupDeviceTest(t, jwtTestConfig(t))
	client := newTestClient(t)

	cases := []struct {
		name   string
		mutate func(url.Values)
		want   int
	}{
		{"audience not configured", func(q url.Values) { q.Set("audience", "payroll") }, http.StatusForbidden},
		{"jwk without audience", func(q url.Values) { q.Del("audience") }, http.StatusForbidden},
		{"audience without jwk", func(q url.Values) { q.Del("jwk") }, http.StatusBadRequest},
		{"jwk not base64url", func(q url.Values) { q.Set("jwk", "{}") }, http.StatusBadRequest},
		{"jwk not a key", func(q url.Values) {
			q.Set("jwk", base64.RawURLEncoding.EncodeToString([]byte(`{"kty":"oct","k":"AA"}`)))
		}, http.StatusBadRequest},
		{"no cli_port", func(q url.Values) { q.Del("cli_port") }, http.StatusBadRequest},
		{"cli_port smuggling a host", func(q url.Values) { q.Set("cli_port", "1@evil.example") }, http.StatusBadRequest},
		{"cli_port out of range", func(q url.Values) { q.Set("cli_port", "70000") }, http.StatusBadRequest},
		{"cli_state with odd characters", func(q url.Values) { q.Set("cli_state", "a&jwt=x") }, http.StatusBadRequest},
		{"both credential kinds", func(q url.Values) { q.Set("pubkey", "AAAA") }, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := browserLoginQuery(client, "secret-broker", "")
			tc.mutate(q)
			rr := getLogin(q)
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d; body %s", rr.Code, tc.want, rr.Body.String())
			}
			if rr.Header().Get("Location") != "" {
				t.Error("an invalid request was still sent to the identity provider")
			}
		})
	}

	// The state parameter is unauthenticated, so the callback must not rely
	// on /login having vetted it.
	t.Run("forged state", func(t *testing.T) {
		for name, state := range map[string]StateData{
			"port":      {Port: "1@evil.example", Audience: "secret-broker", JWK: string(client.jwk())},
			"no port":   {Audience: "secret-broker", JWK: string(client.jwk())},
			"jwk":       {Port: "45678", Audience: "secret-broker", JWK: `{"kty":"oct","k":"AA"}`},
			"no jwk":    {Port: "45678", Audience: "secret-broker"},
			"bad nonce": {Port: "45678", Audience: "secret-broker", JWK: string(client.jwk()), Nonce: "a b"},
		} {
			rr := httptest.NewRecorder()
			handleJWTCallback(rr, httptest.NewRequest(http.MethodGet, "/callback", nil), state, "alice@example.com")
			if rr.Code != http.StatusBadRequest || rr.Header().Get("Location") != "" {
				t.Errorf("%s: status = %d, Location %q; want 400 and no redirect", name, rr.Code, rr.Header().Get("Location"))
			}
		}
	})

	t.Run("disabled", func(t *testing.T) {
		setupDeviceTest(t, nil)
		if rr := getLogin(browserLoginQuery(client, "secret-broker", "")); rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rr.Code)
		}
	})
}

// The state parameter comes back from the identity provider unauthenticated,
// so a forged one can carry a port /login would never have accepted. The
// callback must refuse it before doing anything else — in particular before
// signing a certificate and redirecting it to wherever the "port" points.
func TestCallbackRejectsForgedPort(t *testing.T) {
	setupDeviceTest(t, nil)
	pubKeyB64 := base64.RawURLEncoding.EncodeToString(testPubKey(t, ""))

	for _, port := range []string{"1@evil.example", "80/../x", "evil.example"} {
		state, err := encodeState(StateData{Port: port, Pubkey: pubKeyB64})
		if err != nil {
			t.Fatal(err)
		}
		rr := httptest.NewRecorder()
		handleCallback(rr, httptest.NewRequest(http.MethodGet, "/callback?code=anything&state="+url.QueryEscape(state), nil))
		if rr.Code != http.StatusBadRequest {
			t.Errorf("port %q: status = %d, want 400", port, rr.Code)
		}
		if rr.Header().Get("Location") != "" {
			t.Errorf("port %q: redirected to %s", port, rr.Header().Get("Location"))
		}
	}
}

func TestValidCLIPort(t *testing.T) {
	for _, port := range []string{"1", "80", "45678", "65535"} {
		if !validCLIPort(port) {
			t.Errorf("validCLIPort(%q) = false", port)
		}
	}
	for _, port := range []string{"", "0", "65536", "999999", "-1", "+80", " 80", "80 ", "8o80", "1@evil.example", "80/..", "80#", "٨٠"} {
		if validCLIPort(port) {
			t.Errorf("validCLIPort(%q) = true", port)
		}
	}
}

// ---------------------------------------------------------------------------
// Device flow
// ---------------------------------------------------------------------------

func startTokenDeviceRequest(t *testing.T, client *testClient, audience, role string) deviceCodeResponse {
	t.Helper()
	form := url.Values{"audience": {audience}, "jwk": {client.jwkParam()}}
	if role != "" {
		form.Set("role", role)
	}
	rr := postForm(handleDeviceCode, "/device/code", form)
	if rr.Code != http.StatusOK {
		t.Fatalf("/device/code = %d, body %s", rr.Code, rr.Body.String())
	}
	var resp deviceCodeResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestDeviceFlowIssuesToken(t *testing.T) {
	setupDeviceTest(t, jwtTestConfig(t))
	client := newTestClient(t)

	resp := startTokenDeviceRequest(t, client, "secret-broker", "reader")
	if got := deviceErrorCode(t, pollToken(t, resp.DeviceCode)); got != "authorization_pending" {
		t.Fatalf("first poll error = %q, want authorization_pending", got)
	}

	// The browser completes the identity provider login.
	rr := httptest.NewRecorder()
	handleDeviceCallback(rr, resp.UserCode, "alice@example.com")
	if rr.Code != http.StatusOK {
		t.Fatalf("callback = %d, body %s", rr.Code, rr.Body.String())
	}
	page := rr.Body.String()
	for _, want := range []string{"alice@example.com", "Audience", "secret-broker", "reader", client.thumbprint(), resp.UserCode} {
		if !strings.Contains(page, want) {
			t.Errorf("approval page does not show %q", want)
		}
	}
	if strings.Contains(page, "Principals") || strings.Contains(page, "SSH key") {
		t.Error("token approval page uses the certificate wording")
	}

	// Still nothing to collect until the user confirms.
	time.Sleep(2 * time.Millisecond)
	if got := deviceErrorCode(t, pollToken(t, resp.DeviceCode)); got != "authorization_pending" {
		t.Fatalf("poll before approval = %q, want authorization_pending", got)
	}

	rr = postForm(handleDeviceApprove, "/device/approve", url.Values{
		"user_code": {resp.UserCode}, "approval_token": {approvalTokenFrom(t, page)}, "action": {"approve"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("approve = %d, body %s", rr.Code, rr.Body.String())
	}

	time.Sleep(2 * time.Millisecond)
	tok := decodeTokenResponse(t, pollToken(t, resp.DeviceCode))
	if tok.TokenType != "DPoP" || tok.Audience != "secret-broker" || tok.Role != "reader" || tok.Subject != "alice@example.com" {
		t.Errorf("token response = %+v", tok)
	}

	claims := brokerAccepts(t, client, tok.AccessToken, "secret-broker")
	if claims.Subject != "alice@example.com" || claims.SubjectType != httpcred.SubjectUser || claims.Role != "reader" {
		t.Errorf("claims = %+v", claims)
	}
	if claims.KeyThumbprint != client.thumbprint() {
		t.Error("token is not bound to the key submitted with the device request")
	}

	// Collected exactly once.
	time.Sleep(2 * time.Millisecond)
	if got := deviceErrorCode(t, pollToken(t, resp.DeviceCode)); got != "invalid_grant" {
		t.Errorf("replayed poll error = %q, want invalid_grant", got)
	}
}

func TestDeviceFlowTokenRefusals(t *testing.T) {
	cfg := jwtTestConfig(t)
	setupDeviceTest(t, cfg)
	client := newTestClient(t)

	t.Run("bad requests", func(t *testing.T) {
		bad := map[string]url.Values{
			"audience not configured": {"audience": {"payroll"}, "jwk": {client.jwkParam()}},
			"jwk without audience":    {"jwk": {client.jwkParam()}},
			"audience without jwk":    {"audience": {"secret-broker"}},
			"jwk not a key":           {"audience": {"secret-broker"}, "jwk": {"AAAA"}},
			"both credential kinds": {
				"audience": {"secret-broker"}, "jwk": {client.jwkParam()},
				"pubkey": {base64.RawURLEncoding.EncodeToString(testPubKey(t, ""))},
			},
		}
		for name, form := range bad {
			rr := postForm(handleDeviceCode, "/device/code", form)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("%s: status = %d, want 400; body %s", name, rr.Code, rr.Body.String())
			}
			if strings.Contains(rr.Body.String(), "device_code") {
				t.Errorf("%s: codes were minted", name)
			}
		}
	})

	for name, tc := range map[string]struct{ email, role string }{
		"unknown user":     {"mallory@example.com", ""},
		"role not held":    {"alice@example.com", "admin"},
		"role not allowed": {"alice@example.com", "deploy"},
	} {
		t.Run(name, func(t *testing.T) {
			resp := startTokenDeviceRequest(t, client, "secret-broker", tc.role)
			rr := httptest.NewRecorder()
			handleDeviceCallback(rr, resp.UserCode, tc.email)
			if rr.Code != http.StatusForbidden {
				t.Fatalf("callback = %d, want 403", rr.Code)
			}
			if strings.Contains(rr.Body.String(), "approval_token") {
				t.Fatal("an approval form was rendered for an unauthorized request")
			}
			if got := deviceErrorCode(t, pollToken(t, resp.DeviceCode)); got != "authorization_pending" {
				t.Errorf("poll = %q; the request must not have been approved", got)
			}
		})
	}

	t.Run("reject", func(t *testing.T) {
		resp := startTokenDeviceRequest(t, client, "secret-broker", "")
		rr := httptest.NewRecorder()
		handleDeviceCallback(rr, resp.UserCode, "alice@example.com")
		rr = postForm(handleDeviceApprove, "/device/approve", url.Values{
			"user_code": {resp.UserCode}, "approval_token": {approvalTokenFrom(t, rr.Body.String())}, "action": {"deny"},
		})
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "No token was issued") {
			t.Fatalf("deny = %d, body %s", rr.Code, rr.Body.String())
		}
		if got := deviceErrorCode(t, pollToken(t, resp.DeviceCode)); got != "access_denied" {
			t.Errorf("poll after deny = %q, want access_denied", got)
		}
	})

	// Policy is checked again when the user clicks Approve.
	t.Run("authorization withdrawn before approval", func(t *testing.T) {
		resp := startTokenDeviceRequest(t, client, "secret-broker", "")
		rr := httptest.NewRecorder()
		handleDeviceCallback(rr, resp.UserCode, "alice@example.com")
		approval := approvalTokenFrom(t, rr.Body.String())

		revoked := jwtTestConfig(t)
		revoked.JWT.keys = cfg.JWT.keys
		aud := revoked.JWT.Audiences["secret-broker"]
		aud.AllowedRoles = []string{"admin"}
		revoked.JWT.Audiences["secret-broker"] = aud
		configPtr.Store(revoked)
		defer configPtr.Store(cfg)

		rr = postForm(handleDeviceApprove, "/device/approve", url.Values{
			"user_code": {resp.UserCode}, "approval_token": {approval}, "action": {"approve"},
		})
		if rr.Code != http.StatusForbidden {
			t.Fatalf("approve = %d, want 403", rr.Code)
		}
		if got := deviceErrorCode(t, pollToken(t, resp.DeviceCode)); got != "authorization_pending" {
			t.Errorf("poll = %q; no token may have been released", got)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		setupDeviceTest(t, nil)
		defer setupDeviceTest(t, cfg)
		rr := postForm(handleDeviceCode, "/device/code", url.Values{"audience": {"secret-broker"}, "jwk": {client.jwkParam()}})
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rr.Code)
		}
	})
}

// ---------------------------------------------------------------------------
// Compatibility: enabling HTTP credentials changes nothing for SSH.
// ---------------------------------------------------------------------------

func TestSSHIssuanceUnchangedWithJWTEnabled(t *testing.T) {
	setupDeviceTest(t, jwtTestConfig(t))
	pubKey := testPubKey(t, "tester@laptop")
	pubKeyB64 := base64.RawURLEncoding.EncodeToString(pubKey)

	// Browser flow: the state handed to the identity provider is exactly the
	// three fields it has always been.
	t.Run("browser login state", func(t *testing.T) {
		rr := getLogin(url.Values{"cli_port": {"45678"}, "role": {"deploy"}, "pubkey": {pubKeyB64}})
		state := stateFromRedirect(t, rr)
		if state != (StateData{Port: "45678", Role: "deploy", Pubkey: pubKeyB64}) {
			t.Errorf("state = %+v", state)
		}
		location, _ := url.Parse(rr.Header().Get("Location"))
		raw, err := base64.RawURLEncoding.DecodeString(location.Query().Get("state"))
		if err != nil {
			t.Fatal(err)
		}
		want := fmt.Sprintf(`{"p":"45678","r":"deploy","k":%q}`, pubKeyB64)
		if string(raw) != want {
			t.Errorf("state on the wire = %s, want %s", raw, want)
		}
	})

	// The port is spliced into the URL the certificate is redirected to.
	t.Run("browser login rejects a non-numeric port", func(t *testing.T) {
		rr := getLogin(url.Values{"cli_port": {"1@evil.example"}, "pubkey": {pubKeyB64}})
		if rr.Code != http.StatusBadRequest || rr.Header().Get("Location") != "" {
			t.Fatalf("status = %d, Location %q; want 400", rr.Code, rr.Header().Get("Location"))
		}
		// A login with no CLI listener at all is still allowed (manual copy).
		if rr := getLogin(url.Values{"pubkey": {pubKeyB64}}); rr.Code != http.StatusTemporaryRedirect {
			t.Errorf("login without cli_port = %d, want a redirect", rr.Code)
		}
	})

	t.Run("device flow", func(t *testing.T) {
		resp := startDeviceRequest(t, pubKey, "deploy")
		rr := httptest.NewRecorder()
		handleDeviceCallback(rr, resp.UserCode, "alice@example.com")
		if rr.Code != http.StatusOK {
			t.Fatalf("callback = %d, body %s", rr.Code, rr.Body.String())
		}
		page := rr.Body.String()
		for _, want := range []string{"Principals", "SSH key", "SHA256:", "tester@laptop"} {
			if !strings.Contains(page, want) {
				t.Errorf("certificate approval page lost %q", want)
			}
		}
		if strings.Contains(page, "Audience") {
			t.Error("certificate approval page mentions an audience")
		}
		rr = postForm(handleDeviceApprove, "/device/approve", url.Values{
			"user_code": {resp.UserCode}, "approval_token": {approvalTokenFrom(t, page)}, "action": {"approve"},
		})
		if rr.Code != http.StatusOK {
			t.Fatalf("approve = %d", rr.Code)
		}

		time.Sleep(2 * time.Millisecond)
		rr = pollToken(t, resp.DeviceCode)
		if rr.Code != http.StatusOK {
			t.Fatalf("poll = %d, body %s", rr.Code, rr.Body.String())
		}
		// The response has the certificate shape and none of the token fields.
		var fields map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &fields); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"certificate", "email", "role", "principals"} {
			if _, ok := fields[name]; !ok {
				t.Errorf("response is missing %q", name)
			}
		}
		if _, ok := fields["access_token"]; ok {
			t.Error("certificate response carries an access_token")
		}
		parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(fields["certificate"].(string)))
		if err != nil {
			t.Fatalf("certificate does not parse: %v", err)
		}
		cert := parsed.(*ssh.Certificate)
		if cert.KeyId != "alice@example.com@deploy" || strings.Join(cert.ValidPrincipals, ",") != "deploy" {
			t.Errorf("certificate = %s %v", cert.KeyId, cert.ValidPrincipals)
		}
	})

	t.Run("sign", func(t *testing.T) {
		cert := signedCertFrom(t, postSign(testServiceToken, pubKey))
		if cert.KeyId != "herdr-hq@service" || strings.Join(cert.ValidPrincipals, ",") != "tlamadon" {
			t.Errorf("certificate = %s %v", cert.KeyId, cert.ValidPrincipals)
		}
	})

	// The SSH CA key is not among the keys relying services are told to
	// trust. (That a config naming the CA key as the token key is refused
	// outright is covered by TestLoadConfigRejectsCAKeyAsTokenKey.)
	t.Run("separate signing keys", func(t *testing.T) {
		ca := caSigner.PublicKey().(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey)
		for _, k := range publishedKeys(t) {
			if bytes.Equal(k.Key, ca) {
				t.Fatal("the SSH CA key is published as a token verification key")
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

// The token key and the SSH CA key must be different keys.
func TestLoadConfigRejectsCAKeyAsTokenKey(t *testing.T) {
	dir := t.TempDir()
	caPath, _ := writeJWTKey(t, dir, "ca_key")
	jwtPath, _ := writeJWTKey(t, dir, "jwt_ed25519")
	path := filepath.Join(dir, "config.yaml")
	withCA := func(body string) string { return fmt.Sprintf("ca_key: %q\n", caPath) + body }

	writeConfigFile(t, path, withCA(jwtConfigYAML(jwtPath, audiencesYAML)))
	if _, err := loadConfig(path); err != nil {
		t.Fatalf("distinct keys refused: %v", err)
	}

	for name, content := range map[string]string{
		"as the signing key":    withCA(jwtConfigYAML(caPath, audiencesYAML)),
		"as a verification key": withCA(jwtConfigYAML(jwtPath, fmt.Sprintf("  verification_keys:\n    - key: %q\n", caPath+".pub")+audiencesYAML)),
	} {
		writeConfigFile(t, path, content)
		_, err := loadConfig(path)
		if err == nil || !strings.Contains(err.Error(), "SSH CA key") {
			t.Errorf("CA key %s: error = %v, want it refused", name, err)
		}
	}
}

// A misspelt key inside the jwt block must stop the server, not be skipped:
// skipping it would quietly leave tokens on a longer default lifetime.
func TestLoadConfigRejectsUnknownJWTKeys(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := writeJWTKey(t, dir, "jwt_ed25519")
	path := filepath.Join(dir, "config.yaml")

	for name, content := range map[string]string{
		"top level":              jwtConfigYAML(keyPath, "  valididty: 5m\n"+audiencesYAML),
		"in an audience":         jwtConfigYAML(keyPath, audiencesYAML+"      valididty: 5m\n"),
		"misspelt allowed_roles": jwtConfigYAML(keyPath, "  audiences:\n    secret-broker:\n      allowed_role: [default]\n      services: {}\n"),
		"in a verification key":  jwtConfigYAML(keyPath, "  verification_keys:\n    - key: "+keyPath+".pub\n      kid: x\n"+audiencesYAML),
	} {
		t.Run(name, func(t *testing.T) {
			writeConfigFile(t, path, content)
			_, err := loadConfig(path)
			if err == nil || !strings.Contains(err.Error(), "not found in type") {
				t.Fatalf("error = %v, want the unknown key reported", err)
			}
		})
	}

	// Strictness is confined to the jwt block: the rest of the config keeps
	// tolerating keys it does not know, as it always has.
	writeConfigFile(t, path, "some_future_option: true\n"+jwtConfigYAML(keyPath, audiencesYAML))
	if _, err := loadConfig(path); err != nil {
		t.Fatalf("an unknown top-level key is now rejected: %v", err)
	}
}

// The pages on which one click issues a credential must not be frameable.
func TestApprovalPagesForbidFraming(t *testing.T) {
	setupDeviceTest(t, jwtTestConfig(t))
	client := newTestClient(t)
	check := func(name string, rr *httptest.ResponseRecorder) {
		t.Helper()
		if rr.Header().Get("X-Frame-Options") != "DENY" || !strings.Contains(rr.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Errorf("%s can be framed: headers %v", name, rr.Header())
		}
	}

	state := stateFromRedirect(t, getLogin(browserLoginQuery(client, "secret-broker", "")))
	rr := httptest.NewRecorder()
	handleJWTCallback(rr, httptest.NewRequest(http.MethodGet, "/callback", nil), state, "alice@example.com")
	check("browser token approval", rr)

	resp := startTokenDeviceRequest(t, client, "secret-broker", "")
	rr = httptest.NewRecorder()
	handleDeviceCallback(rr, resp.UserCode, "alice@example.com")
	check("device token approval", rr)

	resp = startDeviceRequest(t, testPubKey(t, ""), "")
	rr = httptest.NewRecorder()
	handleDeviceCallback(rr, resp.UserCode, "alice@example.com")
	check("device certificate approval", rr)
}

func TestTokensAreNeverLogged(t *testing.T) {
	setupDeviceTest(t, jwtTestConfig(t))
	client := newTestClient(t)

	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	resp := decodeTokenResponse(t, postToken(testAgentToken, tokenBody(client, "secret-broker", "fetch")))
	claims, err := httpcred.ParseUnverified(resp.AccessToken)
	if err != nil {
		t.Fatal(err)
	}

	state := stateFromRedirect(t, getLogin(browserLoginQuery(client, "secret-broker", "")))
	_, sealed := approvalFrom(t, state, "alice@example.com")
	browserToken := cliRedirect(t, postApprove(sealed, "approve"), "45678").Get("jwt")

	device := startTokenDeviceRequest(t, client, "secret-broker", "")
	rr := httptest.NewRecorder()
	handleDeviceCallback(rr, device.UserCode, "alice@example.com")
	postForm(handleDeviceApprove, "/device/approve", url.Values{
		"user_code": {device.UserCode}, "approval_token": {approvalTokenFrom(t, rr.Body.String())}, "action": {"approve"},
	})
	time.Sleep(2 * time.Millisecond)
	deviceToken := decodeTokenResponse(t, pollToken(t, device.DeviceCode)).AccessToken

	out := logs.String()
	for _, want := range []string{"Token issued", "sub=service:agent", "aud=secret-broker", "role=fetch", "jti=" + claims.ID, "jkt=" + client.thumbprint(), "via=service", "via=browser", "via=device"} {
		if !strings.Contains(out, want) {
			t.Errorf("log does not record %q:\n%s", want, out)
		}
	}
	for _, token := range []string{resp.AccessToken, browserToken, deviceToken} {
		// Neither the whole token nor its signature may appear.
		if strings.Contains(out, token) || strings.Contains(out, token[strings.LastIndex(token, ".")+1:]) {
			t.Fatalf("a token was written to the log:\n%s", out)
		}
	}
	if strings.Contains(out, testAgentToken) {
		t.Fatal("the service token was written to the log")
	}
}

// ---------------------------------------------------------------------------
// Configuration, keys and rotation
// ---------------------------------------------------------------------------

// writeJWTKey generates a key pair on disk the way `voussh jwt-init` does.
func writeJWTKey(t *testing.T, dir, name string) (path string, pub ed25519.PublicKey) {
	t.Helper()
	path = filepath.Join(dir, name)
	pub, err := generateKeyPair(path)
	if err != nil {
		t.Fatalf("generate %s: %v", name, err)
	}
	return path, pub
}

func jwtConfigYAML(signingKey, extra string) string {
	return configFileBase + fmt.Sprintf(`jwt:
  issuer: "https://auth.example.com"
  signing_key: %q
%s`, signingKey, extra)
}

const audiencesYAML = `  audiences:
    secret-broker:
      allowed_roles: [default, admin]
`

func TestLoadConfigJWT(t *testing.T) {
	dir := t.TempDir()
	keyPath, pub := writeJWTKey(t, dir, "jwt_ed25519")
	path := filepath.Join(dir, "config.yaml")

	writeConfigFile(t, path, jwtConfigYAML(keyPath, audiencesYAML))
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if !cfg.jwtEnabled() {
		t.Fatal("jwt block did not enable issuance")
	}
	issuer := cfg.JWT.keys.issuer
	if issuer.Name() != "https://auth.example.com" {
		t.Errorf("issuer = %q", issuer.Name())
	}
	// With no key_id configured, the kid is the key's own thumbprint.
	if issuer.KeyID() != httpcred.Thumbprint(pub) {
		t.Errorf("kid = %q, want the key thumbprint", issuer.KeyID())
	}
	aud, err := cfg.jwtAudience("secret-broker")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.JWT.validityFor(aud); got != 15*time.Minute {
		t.Errorf("default validity = %s, want 15m", got)
	}

	t.Run("validity is configurable up to the ceiling", func(t *testing.T) {
		writeConfigFile(t, path, jwtConfigYAML(keyPath, "  validity: 1h\n"+audiencesYAML+"      validity: 24h\n    short:\n      allowed_roles: [default]\n"))
		cfg, err := loadConfig(path)
		if err != nil {
			t.Fatalf("loadConfig: %v", err)
		}
		if got := cfg.JWT.validityFor(cfg.JWT.Audiences["secret-broker"]); got != 24*time.Hour {
			t.Errorf("per-audience validity = %s, want 24h", got)
		}
		if got := cfg.JWT.validityFor(cfg.JWT.Audiences["short"]); got != time.Hour {
			t.Errorf("inherited validity = %s, want 1h", got)
		}
	})

	t.Run("configured key ids", func(t *testing.T) {
		oldPath, _ := writeJWTKey(t, dir, "jwt_old")
		extra := fmt.Sprintf("  key_id: \"2026-11\"\n  verification_keys:\n    - key: %q\n      key_id: \"2026-10\"\n", oldPath+".pub") + audiencesYAML
		writeConfigFile(t, path, jwtConfigYAML(keyPath, extra))
		cfg, err := loadConfig(path)
		if err != nil {
			t.Fatalf("loadConfig: %v", err)
		}
		keys := cfg.JWT.keys.issuer.Keys()
		if len(keys) != 2 || keys[0].KeyID != "2026-11" || keys[1].KeyID != "2026-10" {
			t.Errorf("published keys = %+v", keys)
		}
	})

	t.Run("verification key given as a JWK", func(t *testing.T) {
		other := newTestClient(t)
		jwkPath := filepath.Join(dir, "next.jwk")
		if err := os.WriteFile(jwkPath, other.jwk(), 0644); err != nil {
			t.Fatal(err)
		}
		writeConfigFile(t, path, jwtConfigYAML(keyPath, fmt.Sprintf("  verification_keys:\n    - key: %q\n", jwkPath)+audiencesYAML))
		cfg, err := loadConfig(path)
		if err != nil {
			t.Fatalf("loadConfig: %v", err)
		}
		keys := cfg.JWT.keys.issuer.Keys()
		if len(keys) != 2 || !bytes.Equal(keys[1].Key, other.pub()) || keys[1].KeyID != other.thumbprint() {
			t.Errorf("published keys = %+v", keys)
		}
	})

	t.Run("pkcs8 signing key", func(t *testing.T) {
		pemPath := filepath.Join(dir, "jwt_pkcs8")
		// The shape `openssl genpkey -algorithm ed25519` produces.
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		pkcs8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(pemPath, pkcs8, 0600); err != nil {
			t.Fatal(err)
		}
		writeConfigFile(t, path, jwtConfigYAML(pemPath, audiencesYAML))
		if _, err := loadConfig(path); err != nil {
			t.Fatalf("loadConfig with a PKCS#8 key: %v", err)
		}
	})
}

func TestLoadConfigRejectsBadJWT(t *testing.T) {
	dir := t.TempDir()
	keyPath, _ := writeJWTKey(t, dir, "jwt_ed25519")
	path := filepath.Join(dir, "config.yaml")
	garbage := filepath.Join(dir, "garbage")
	if err := os.WriteFile(garbage, []byte("not a key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	service := fmt.Sprintf("services:\n  agent:\n    token_sha256: %q\n", sha256Hex("x"))

	sshService := fmt.Sprintf("services:\n  agent:\n    token_sha256: %q\n    principals: [deploy]\n", sha256Hex("x"))
	otherPath, _ := writeJWTKey(t, dir, "jwt_other")

	// Each case names the reason it must be refused for, so that a config
	// which is merely malformed YAML cannot pass for a policy check.
	cases := []struct {
		name, content, reason string
	}{
		{"no issuer", configFileBase + "jwt:\n  signing_key: " + keyPath + "\n" + audiencesYAML, "issuer must not be empty"},
		{"no signing key", configFileBase + "jwt:\n  issuer: x\n" + audiencesYAML, "signing_key must not be empty"},
		{"signing key missing", jwtConfigYAML(filepath.Join(dir, "absent"), audiencesYAML), "no such file"},
		{"signing key is garbage", jwtConfigYAML(garbage, audiencesYAML), "signing_key"},
		{"signing key is a public key", jwtConfigYAML(keyPath+".pub", audiencesYAML), "signing_key"},
		{"validity over the ceiling", jwtConfigYAML(keyPath, "  validity: 25h\n"+audiencesYAML), "maximum is 24h"},
		{"validity not a duration", jwtConfigYAML(keyPath, "  validity: soon\n"+audiencesYAML), "invalid validity"},
		{"validity zero", jwtConfigYAML(keyPath, "  validity: 0s\n"+audiencesYAML), "must be positive"},
		{"audience validity too long", jwtConfigYAML(keyPath, audiencesYAML+"      validity: 720h\n"), "maximum is 24h"},
		{"audience grants nothing", jwtConfigYAML(keyPath, "  audiences:\n    secret-broker: {}\n"), "needs allowed_roles or services"},
		{"audience name with a space", jwtConfigYAML(keyPath, "  audiences:\n    \"secret broker\":\n      allowed_roles: [default]\n"), "must not contain whitespace"},
		{"empty role", jwtConfigYAML(keyPath, "  audiences:\n    secret-broker:\n      allowed_roles: [\"\"]\n"), "empty role"},
		{"grant to an unknown service", jwtConfigYAML(keyPath, "  audiences:\n    secret-broker:\n      services:\n        ghost: [fetch]\n"), "is not defined under services"},
		{"service grant without roles", sshService + jwtConfigYAML(keyPath, "  audiences:\n    secret-broker:\n      services:\n        agent: []\n"), "non-empty list of roles"},
		// A service with neither principals nor a grant can do nothing.
		{"service with nothing to request", service + jwtConfigYAML(keyPath, audiencesYAML), "principals must not be empty"},
		{"verification key missing", jwtConfigYAML(keyPath, "  verification_keys:\n    - key: /nonexistent\n"+audiencesYAML), "verification_keys[0]"},
		{"verification key is private", jwtConfigYAML(keyPath, "  verification_keys:\n    - key: "+keyPath+"\n"+audiencesYAML), "got a private key"},
		{"two keys under one key id", jwtConfigYAML(keyPath, "  key_id: same\n  verification_keys:\n    - key: "+otherPath+".pub\n      key_id: same\n"+audiencesYAML), "share the key id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writeConfigFile(t, path, tc.content)
			_, err := loadConfig(path)
			if err == nil {
				t.Fatal("loadConfig accepted an invalid jwt block")
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("refused for the wrong reason: %v (want mention of %q)", err, tc.reason)
			}
		})
	}

	// The same service becomes valid once an audience grants it a role.
	t.Run("token-only service is valid once granted", func(t *testing.T) {
		writeConfigFile(t, path, service+jwtConfigYAML(keyPath, "  audiences:\n    secret-broker:\n      services:\n        agent: [fetch]\n"))
		if _, err := loadConfig(path); err != nil {
			t.Fatalf("loadConfig: %v", err)
		}
	})
}

// Rotation, end to end through config reloads: announce the new key, switch
// to it, retire the old one. Tokens issued before each step keep verifying
// for anyone who pinned the set published at that step.
func TestReloadRotatesSigningKey(t *testing.T) {
	setupDeviceTest(t, nil)
	dir := t.TempDir()
	oldPath, oldPub := writeJWTKey(t, dir, "jwt_old")
	newPath, newPub := writeJWTKey(t, dir, "jwt_new")
	path := filepath.Join(dir, "config.yaml")
	client := newTestClient(t)

	load := func(content string) {
		t.Helper()
		writeConfigFile(t, path, content)
		reloadConfig(path)
	}
	issue := func() string {
		t.Helper()
		cfg := currentConfig()
		grant, err := authorizeUserJWT(cfg, "alice@example.com", "secret-broker", "")
		if err != nil {
			t.Fatalf("authorize: %v", err)
		}
		token, _, err := issueJWT(cfg, grant, client.pub())
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		return token
	}
	publishedIDs := func() []string {
		var ids []string
		for _, k := range publishedKeys(t) {
			ids = append(ids, k.KeyID)
		}
		return ids
	}
	oldID, newID := httpcred.Thumbprint(oldPub), httpcred.Thumbprint(newPub)

	// Start: one key.
	writeConfigFile(t, path, jwtConfigYAML(oldPath, audiencesYAML))
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	configPtr.Store(cfg)
	oldToken := issue()
	brokerAccepts(t, client, oldToken, "secret-broker")

	// Step 1: publish the new key alongside; keep signing with the old.
	load(jwtConfigYAML(oldPath, fmt.Sprintf("  verification_keys:\n    - key: %q\n", newPath+".pub")+audiencesYAML))
	if ids := publishedIDs(); len(ids) != 2 || ids[0] != oldID || ids[1] != newID {
		t.Fatalf("step 1 publishes %v, want [old new]", ids)
	}
	if claims, _ := httpcred.ParseUnverified(issue()); claims.Issuer == "" {
		t.Fatal("step 1 cannot issue")
	}

	// Step 2: sign with the new key; keep publishing the old.
	load(jwtConfigYAML(newPath, fmt.Sprintf("  verification_keys:\n    - key: %q\n", oldPath+".pub")+audiencesYAML))
	if ids := publishedIDs(); len(ids) != 2 || ids[0] != newID || ids[1] != oldID {
		t.Fatalf("step 2 publishes %v, want [new old]", ids)
	}
	newToken := issue()
	// Both generations verify against the set published now.
	brokerAccepts(t, client, oldToken, "secret-broker")
	brokerAccepts(t, client, newToken, "secret-broker")

	// A broken edit mid-rotation is refused and the working keys are kept.
	load(jwtConfigYAML(filepath.Join(dir, "absent"), audiencesYAML))
	if ids := publishedIDs(); len(ids) != 2 || ids[0] != newID {
		t.Fatalf("after a broken reload the server publishes %v", ids)
	}
	brokerAccepts(t, client, issue(), "secret-broker")

	// Step 3: retire the old key.
	load(jwtConfigYAML(newPath, audiencesYAML))
	if ids := publishedIDs(); len(ids) != 1 || ids[0] != newID {
		t.Fatalf("step 3 publishes %v, want [new]", ids)
	}
	brokerAccepts(t, client, newToken, "secret-broker")

	// Removing the block switches the feature off entirely.
	load(configFileBase)
	rr := httptest.NewRecorder()
	handleJWKS(rr, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rr.Code != http.StatusNotFound {
		t.Errorf("jwks after removing the jwt block = %d, want 404", rr.Code)
	}
}

func TestApprovalSealing(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	now := time.Unix(1790000000, 0)
	approval := jwtApproval{
		Email: "alice@example.com", Audience: "secret-broker", Role: "default",
		JWK: `{"crv":"Ed25519","kty":"OKP","x":"AA"}`, Port: "45678", Nonce: "n", Expires: now.Add(time.Minute).Unix(),
	}
	sealed, err := sealApproval(key, approval)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := openApproval(key, sealed, now); !ok || got != approval {
		t.Fatalf("round trip = %+v, %v", got, ok)
	}
	if _, ok := openApproval(key, sealed, now.Add(2*time.Minute)); ok {
		t.Error("an expired approval opened")
	}
	if _, ok := openApproval(bytes.Repeat([]byte{2}, 32), sealed, now); ok {
		t.Error("an approval opened under the wrong key")
	}
	// The approval MAC must not be interchangeable with the admin cookie's.
	adminCookieKey = key
	payload, _, _ := strings.Cut(sealed, ".")
	if _, ok := openApproval(key, payload+"."+adminCookieMAC(payload), now); ok {
		t.Error("an admin-cookie MAC was accepted as an approval MAC")
	}
}
