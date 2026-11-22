package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/voussh/voussh/httpcred"
)

// fakeBroker is a relying service: it authenticates every request with the
// reference verifier, offline, against keys pinned at construction.
type fakeBroker struct {
	server   *httptest.Server
	verifier *httpcred.Verifier

	mu           sync.Mutex
	requireNonce string
	proofs       []string
	failures     []error
}

func newFakeBroker(t *testing.T, issuer *testIssuer) *fakeBroker {
	t.Helper()
	b := &fakeBroker{}
	b.server = httptest.NewServer(http.HandlerFunc(b.handle))
	t.Cleanup(b.server.Close)

	verifier, err := httpcred.NewVerifier(httpcred.VerifierConfig{
		Issuer: testIssuerName, Audience: testAudience,
		Keys: issuer.issuer.Keys(), Origin: b.server.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	b.verifier = verifier
	return b
}

func (b *fakeBroker) handle(w http.ResponseWriter, r *http.Request) {
	b.mu.Lock()
	defer b.mu.Unlock()
	proof := r.Header.Get("DPoP")
	b.proofs = append(b.proofs, proof)

	if r.URL.Path == "/moved" {
		http.Redirect(w, r, "https://elsewhere.example/steal", http.StatusFound)
		return
	}
	if b.requireNonce != "" && proofNonce(proof) != b.requireNonce {
		w.Header().Set("DPoP-Nonce", b.requireNonce)
		w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	claims, err := b.verifier.VerifyHTTP(r)
	if err != nil {
		b.failures = append(b.failures, err)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	body, _ := io.ReadAll(r.Body)
	json.NewEncoder(w).Encode(map[string]string{
		"subject": claims.Subject, "role": claims.Role, "method": r.Method,
		"body": string(body), "x-request": r.Header.Get("X-Request"),
	})
}

func proofNonce(proof string) string {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Nonce string `json:"nonce"`
	}
	json.Unmarshal(raw, &claims)
	return claims.Nonce
}

// noRedirectClient is the production client, so the tests below exercise the
// redirect policy vsh actually ships with.
func noRedirectClient() *http.Client { return newRequestClient(10 * time.Second) }

func readJSON(t *testing.T, resp *http.Response) map[string]string {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body %s", resp.StatusCode, body)
	}
	var out map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSignedRequestIsAcceptedByAVerifyingBroker(t *testing.T) {
	issuer := newTestIssuer(t)
	broker := newFakeBroker(t, issuer)
	key, pub := newKey(t)
	token := issuer.issue(pub, nil)
	client := noRedirectClient()

	resp, err := signedRequest(client, key, token, "GET", broker.server.URL+"/v1/secrets/db?version=3", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := readJSON(t, resp); got["subject"] != "alice@example.com" || got["role"] != "default" {
		t.Errorf("broker saw %v", got)
	}

	// A body, a method and extra headers all pass through.
	headers := http.Header{"X-Request": {"42"}, "Content-Type": {"application/json"}}
	resp, err = signedRequest(client, key, token, "PUT", broker.server.URL+"/v1/secrets/db", headers, []byte(`{"value":"s3cret"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := readJSON(t, resp); got["method"] != "PUT" || got["body"] != `{"value":"s3cret"}` || got["x-request"] != "42" {
		t.Errorf("broker saw %v", got)
	}

	// Every request carries its own proof: the broker's replay cache would
	// have refused a reused one.
	for i := 0; i < 3; i++ {
		resp, err := signedRequest(client, key, token, "GET", broker.server.URL+"/v1/secrets/db", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		readJSON(t, resp)
	}
	seen := map[string]bool{}
	for _, proof := range broker.proofs {
		if seen[proof] {
			t.Fatal("a DPoP proof was sent twice")
		}
		seen[proof] = true
	}
	if len(broker.failures) != 0 {
		t.Errorf("broker rejected requests: %v", broker.failures)
	}
}

// The token alone is worthless: without the private key, or with the wrong
// one, the same broker turns the request away.
func TestStolenTokenIsUselessWithoutTheKey(t *testing.T) {
	issuer := newTestIssuer(t)
	broker := newFakeBroker(t, issuer)
	_, pub := newKey(t)
	thiefKey, _ := newKey(t)
	token := issuer.issue(pub, nil)

	resp, err := signedRequest(noRedirectClient(), thiefKey, token, "GET", broker.server.URL+"/v1/secrets/db", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}

	req, _ := http.NewRequest("GET", broker.server.URL+"/v1/secrets/db", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bearer use: status = %d, want 401", resp.StatusCode)
	}
}

func TestSignedRequestAnswersNonceChallenge(t *testing.T) {
	issuer := newTestIssuer(t)
	broker := newFakeBroker(t, issuer)
	broker.requireNonce = "nonce-from-broker"
	key, pub := newKey(t)
	token := issuer.issue(pub, nil)

	resp, err := signedRequest(noRedirectClient(), key, token, "POST", broker.server.URL+"/v1/secrets/db", nil, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if got := readJSON(t, resp); got["body"] != "payload" {
		t.Errorf("body after the retry = %q, want it resent intact", got["body"])
	}
	if len(broker.proofs) != 2 || broker.proofs[0] == broker.proofs[1] {
		t.Fatalf("broker saw %d proofs, want two distinct ones", len(broker.proofs))
	}
	if proofNonce(broker.proofs[0]) != "" || proofNonce(broker.proofs[1]) != "nonce-from-broker" {
		t.Error("the retry did not carry the broker's nonce")
	}
}

func TestSignedRequestDoesNotFollowRedirects(t *testing.T) {
	issuer := newTestIssuer(t)
	broker := newFakeBroker(t, issuer)
	key, pub := newKey(t)

	resp, err := signedRequest(noRedirectClient(), key, issuer.issue(pub, nil), "GET", broker.server.URL+"/moved", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want the 302 returned as-is", resp.StatusCode)
	}
	if len(broker.proofs) != 1 {
		t.Errorf("%d requests made, want exactly one", len(broker.proofs))
	}

	// The control: an ordinary client would have followed it, taking the
	// Authorization header along for same-host hops.
	var followed bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/landing", http.StatusFound)
			return
		}
		followed = true
	}))
	defer target.Close()
	resp, err = signedRequest(noRedirectClient(), key, issuer.issue(pub, nil), "GET", target.URL+"/start", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if followed || resp.StatusCode != http.StatusFound {
		t.Errorf("a same-host redirect was followed (status %d)", resp.StatusCode)
	}
}

func TestProofMatchesRequest(t *testing.T) {
	issuer := newTestIssuer(t)
	key, pub := newKey(t)
	token := issuer.issue(pub, nil)

	var proof, authorization string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proof, authorization = r.Header.Get("DPoP"), r.Header.Get("Authorization")
	}))
	defer server.Close()

	target := server.URL + "/v1/items?page=2"
	resp, err := signedRequest(noRedirectClient(), key, token, "DELETE", target, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if authorization != "DPoP "+token {
		t.Errorf("Authorization = %q", authorization)
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("proof is not a compact JWS: %q", proof)
	}
	var header struct {
		Typ string            `json:"typ"`
		Alg string            `json:"alg"`
		JWK map[string]string `json:"jwk"`
	}
	var claims struct {
		Jti string `json:"jti"`
		Htm string `json:"htm"`
		Htu string `json:"htu"`
		Iat int64  `json:"iat"`
		Ath string `json:"ath"`
	}
	for i, dst := range []any{&header, &claims} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			t.Fatal(err)
		}
	}
	if header.Typ != "dpop+jwt" || header.Alg != "EdDSA" {
		t.Errorf("header = %+v", header)
	}
	if len(header.JWK) != 3 || header.JWK["x"] != base64.RawURLEncoding.EncodeToString(pub) {
		t.Errorf("embedded jwk = %v, want the public key and nothing else", header.JWK)
	}
	if claims.Htm != "DELETE" || claims.Htu != server.URL+"/v1/items" {
		t.Errorf("htm/htu = %s %s, want the method and the URL without its query", claims.Htm, claims.Htu)
	}
	if claims.Ath != httpcred.TokenHash(token) || len(claims.Jti) < 16 || claims.Iat == 0 {
		t.Errorf("claims = %+v", claims)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		t.Error("proof signature does not verify under the client key")
	}
}

func TestParseHeaders(t *testing.T) {
	headers, err := parseHeaders([]string{"Content-Type: application/json", "x-trace:  abc ", "X-Multi: 1", "X-Multi: 2"})
	if err != nil {
		t.Fatal(err)
	}
	if headers.Get("Content-Type") != "application/json" || headers.Get("X-Trace") != "abc" || len(headers["X-Multi"]) != 2 {
		t.Errorf("headers = %v", headers)
	}
	// The credential headers are not the caller's to set.
	for _, entry := range []string{"Authorization: Bearer x", "authorization: x", "DPoP: x", "dpop:x", "no-colon", ": value"} {
		if _, err := parseHeaders([]string{entry}); err == nil {
			t.Errorf("parseHeaders accepted %q", entry)
		}
	}
}

func TestCheckRequestURL(t *testing.T) {
	for _, ok := range []string{"https://broker.example.com/x", "http://localhost:8080/x", "http://127.0.0.1/x", "http://[::1]:9/x"} {
		if err := checkRequestURL(ok, false); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://broker.example.com/x", "broker.example.com/x", "ftp://x/y", "/relative", ""} {
		if err := checkRequestURL(bad, false); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if err := checkRequestURL("http://broker.internal/x", true); err != nil {
		t.Errorf("--allow-http did not allow plain http: %v", err)
	}
}

func TestReadRequestBody(t *testing.T) {
	path := filepath.Join(t.TempDir(), "body.json")
	if err := os.WriteFile(path, []byte(`{"a":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	for input, want := range map[string]string{"": "", "literal": "literal", "@" + path: `{"a":1}`} {
		got, err := readRequestBody(input)
		if err != nil || string(got) != want {
			t.Errorf("readRequestBody(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	if _, err := readRequestBody("@/nonexistent/file"); err == nil {
		t.Error("a missing body file was accepted")
	}
}
