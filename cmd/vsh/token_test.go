package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tlamadon/voussh/httpcred"
	"github.com/tlamadon/voussh/internal/keyfile"
)

const (
	testIssuerName = "https://auth.example.com"
	testAudience   = "secret-broker"
)

// useTempConfigDir points vsh's state at a scratch directory.
func useTempConfigDir(t *testing.T) {
	t.Helper()
	oldDir, oldServer := vshDir, serverURL
	vshDir = t.TempDir()
	t.Cleanup(func() { vshDir, serverURL = oldDir, oldServer })
}

// testIssuer stands in for voussh: it signs tokens for whatever key it is
// handed, which is all these client-side tests need.
type testIssuer struct {
	t      *testing.T
	issuer *httpcred.Issuer
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := httpcred.NewIssuer(testIssuerName, key, "")
	if err != nil {
		t.Fatal(err)
	}
	return &testIssuer{t: t, issuer: issuer}
}

func (i *testIssuer) issue(pub ed25519.PublicKey, adjust func(*httpcred.TokenRequest)) string {
	i.t.Helper()
	req := httpcred.TokenRequest{
		Subject: "alice@example.com", SubjectType: httpcred.SubjectUser,
		Audience: testAudience, Role: "default", Key: pub, Validity: 15 * time.Minute,
	}
	if adjust != nil {
		adjust(&req)
	}
	token, _, err := i.issuer.Issue(req)
	if err != nil {
		i.t.Fatal(err)
	}
	return token
}

func newKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key, pub
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

func TestTokenStorageIsOwnerOnly(t *testing.T) {
	useTempConfigDir(t)
	// A pre-existing, world-readable directory must be tightened, not trusted.
	if err := os.MkdirAll(tokenDir(), 0755); err != nil {
		t.Fatal(err)
	}

	rec := &tokenRecord{
		Server: "https://ca.example.com", Audience: testAudience, Role: "default",
		Subject: "alice@example.com", ExpiresAt: time.Now().Add(time.Minute).Truncate(time.Second),
		KeyPath: "/k", Mode: tokenModeBrowser, AccessToken: "header.payload.signature",
	}
	if err := saveToken(rec); err != nil {
		t.Fatalf("saveToken: %v", err)
	}

	dirInfo, err := os.Stat(tokenDir())
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0700 {
		t.Errorf("token directory mode = %o, want 700", perm)
	}
	fileInfo, err := os.Stat(filepath.Join(tokenDir(), tokenFileName(testAudience)))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fileInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("token file mode = %o, want 600", perm)
	}

	loaded, err := loadToken(testAudience)
	if err != nil {
		t.Fatalf("loadToken: %v", err)
	}
	if loaded.AccessToken != rec.AccessToken || loaded.Role != "default" || !loaded.ExpiresAt.Equal(rec.ExpiresAt) {
		t.Errorf("loaded = %+v", loaded)
	}

	// A second login for the same audience replaces the first.
	rec.Role = "admin"
	if err := saveToken(rec); err != nil {
		t.Fatal(err)
	}
	if all := listTokens(); len(all) != 1 || all[0].Role != "admin" {
		t.Errorf("after re-login: %+v", all)
	}
	// No temp files left behind next to the credential.
	entries, _ := os.ReadDir(tokenDir())
	if len(entries) != 1 {
		t.Errorf("token directory holds %d entries, want 1", len(entries))
	}
}

func TestTokenFileName(t *testing.T) {
	if got := tokenFileName("secret-broker"); got != "secret-broker.json" {
		t.Errorf("simple audience = %q", got)
	}
	// Audiences can be URLs; the name must stay inside the token directory.
	for _, audience := range []string{"https://broker.example.com/api", "../../etc/passwd", "a/b", ".hidden", "..", "a b", strings.Repeat("x", 300)} {
		name := tokenFileName(audience)
		if strings.ContainsAny(name, `/\ `) || strings.HasPrefix(name, ".") || filepath.Base(name) != name {
			t.Errorf("tokenFileName(%q) = %q is not a safe file name", audience, name)
		}
		if len(name) > 100 {
			t.Errorf("tokenFileName(%q) is %d bytes long", audience, len(name))
		}
	}
	// Nor on a filesystem that ignores case.
	if strings.EqualFold(tokenFileName("API"), tokenFileName("api")) {
		t.Error("audiences differing only in case map to one file on a case-insensitive filesystem")
	}
	// Audiences that sanitise to the same text must not share a file.
	if tokenFileName("a/b") == tokenFileName("a_b") || tokenFileName("a/b") == tokenFileName("a:b") {
		t.Error("distinct audiences map to one file")
	}
}

func TestSelectToken(t *testing.T) {
	useTempConfigDir(t)

	if _, err := selectToken(""); err == nil {
		t.Error("selected a credential from an empty store")
	}
	if _, err := selectToken(testAudience); err == nil || !strings.Contains(err.Error(), "vsh token login") {
		t.Errorf("missing credential error = %v, want a hint to log in", err)
	}

	save := func(audience string) {
		rec := &tokenRecord{Audience: audience, ExpiresAt: time.Now().Add(time.Minute), AccessToken: "t"}
		if err := saveToken(rec); err != nil {
			t.Fatal(err)
		}
	}
	save(testAudience)
	if rec, err := selectToken(""); err != nil || rec.Audience != testAudience {
		t.Errorf("single credential not selected by default: %v", err)
	}

	save("billing-api")
	if _, err := selectToken(""); err == nil || !strings.Contains(err.Error(), "billing-api") {
		t.Errorf("ambiguous selection error = %v, want the choices listed", err)
	}
	if rec, err := selectToken("billing-api"); err != nil || rec.Audience != "billing-api" {
		t.Errorf("explicit selection failed: %v", err)
	}
}

// A credential is only ever returned for the audience it records, whatever
// file it was found in.
func TestLoadTokenChecksAudience(t *testing.T) {
	useTempConfigDir(t)
	rec := &tokenRecord{Audience: "billing-api", ExpiresAt: time.Now().Add(time.Minute), AccessToken: "t"}
	if err := saveToken(rec); err != nil {
		t.Fatal(err)
	}
	// Put that record where another audience's would be looked for.
	data, err := os.ReadFile(filepath.Join(tokenDir(), tokenFileName("billing-api")))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tokenDir(), tokenFileName(testAudience)), data, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := loadToken(testAudience); err == nil {
		t.Fatalf("loadToken(%q) returned the credential for %q", testAudience, got.Audience)
	}
}

func TestEnsureHTTPKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "http_ed25519")

	key, err := ensureHTTPKey(path)
	if err != nil {
		t.Fatalf("ensureHTTPKey: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("key file mode = %o, want 600", perm)
	}
	// The same key comes back on every later call: it is generated once.
	again, err := ensureHTTPKey(path)
	if err != nil || !bytes.Equal(key, again) {
		t.Fatalf("second call returned a different key (%v)", err)
	}
	// And it is in a format the rest of the tooling reads.
	if loaded, err := keyfile.LoadPrivate(path); err != nil || !bytes.Equal(loaded, key) {
		t.Fatalf("key file does not load back: %v", err)
	}
}

// ---------------------------------------------------------------------------
// What the client accepts from the server
// ---------------------------------------------------------------------------

func TestCheckIssuedToken(t *testing.T) {
	issuer := newTestIssuer(t)
	keys := issuer.issuer.Keys()
	_, pub := newKey(t)
	_, otherPub := newKey(t)

	claims, err := checkIssuedToken(issuer.issue(pub, nil), keys, pub, testAudience)
	if err != nil {
		t.Fatalf("valid token refused: %v", err)
	}
	if claims.Subject != "alice@example.com" || claims.Role != "default" {
		t.Errorf("claims = %+v", claims)
	}

	// A token with all the right claims that the server did not sign: what
	// someone able to reach the loopback listener could fabricate.
	impostor := newTestIssuer(t)
	valid := issuer.issue(pub, nil)
	parts := strings.Split(valid, ".")

	bad := map[string]string{
		"bound to another key": issuer.issue(otherPub, nil),
		"for another audience": issuer.issue(pub, func(r *httpcred.TokenRequest) { r.Audience = "billing-api" }),
		"already expired": issuer.issue(pub, func(r *httpcred.TokenRequest) {
			r.Now = time.Now().Add(-time.Hour)
		}),
		"signed by someone else": impostor.issue(pub, nil),
		"signature stripped":     parts[0] + "." + parts[1] + ".",
		"not a token":            "certainly-not-a-jwt",
		"empty":                  "",
	}
	for name, token := range bad {
		if _, err := checkIssuedToken(token, keys, pub, testAudience); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTokenCallbackHandler(t *testing.T) {
	issuer := newTestIssuer(t)
	_, pub := newKey(t)
	token := issuer.issue(pub, nil)
	const nonce = "expected-nonce"

	call := func(query url.Values) (*httptest.ResponseRecorder, *tokenCallbackResult) {
		results := make(chan tokenCallbackResult, 1)
		rr := httptest.NewRecorder()
		tokenCallbackHandler(nonce, results)(rr, httptest.NewRequest(http.MethodGet, "/callback?"+query.Encode(), nil))
		select {
		case result := <-results:
			return rr, &result
		default:
			return rr, nil
		}
	}

	t.Run("token", func(t *testing.T) {
		rr, result := call(url.Values{"state": {nonce}, "jwt": {token}})
		if result == nil || result.err != nil || result.token != token {
			t.Fatalf("result = %+v", result)
		}
		page := rr.Body.String()
		for _, want := range []string{"alice@example.com", testAudience, "default"} {
			if !strings.Contains(page, want) {
				t.Errorf("page does not show %q", want)
			}
		}
		// The page stays in the browser; the token must not.
		if strings.Contains(page, token) || strings.Contains(page, token[strings.LastIndex(token, ".")+1:]) {
			t.Error("the result page contains the token")
		}
	})

	t.Run("refusal", func(t *testing.T) {
		rr, result := call(url.Values{"state": {nonce}, "error": {"access_denied"}, "error_description": {`role "admin" not available`}})
		if result == nil || result.err == nil || !strings.Contains(result.err.Error(), "admin") {
			t.Fatalf("result = %+v", result)
		}
		if !strings.Contains(rr.Body.String(), "failed") {
			t.Error("page does not report the failure")
		}
	})

	t.Run("reason is escaped", func(t *testing.T) {
		rr, _ := call(url.Values{"state": {nonce}, "error": {"x"}, "error_description": {"<script>alert(1)</script>"}})
		if strings.Contains(rr.Body.String(), "<script>") {
			t.Error("error description rendered unescaped")
		}
	})

	t.Run("neither token nor error", func(t *testing.T) {
		if _, result := call(url.Values{"state": {nonce}}); result == nil || result.err == nil {
			t.Fatalf("result = %+v, want an error", result)
		}
	})

	// A request without the nonce is somebody else's: it must neither end
	// the login nor be allowed to supply the token.
	for name, query := range map[string]url.Values{
		"no state":         {"jwt": {token}},
		"wrong state":      {"state": {"guess"}, "jwt": {token}},
		"injected refusal": {"state": {"guess"}, "error": {"access_denied"}},
	} {
		t.Run(name, func(t *testing.T) {
			rr, result := call(query)
			if result != nil {
				t.Fatalf("a request without the nonce produced a result: %+v", result)
			}
			if rr.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rr.Code)
			}
		})
	}

	t.Run("page reload does not block", func(t *testing.T) {
		results := make(chan tokenCallbackResult, 1)
		handler := tokenCallbackHandler(nonce, results)
		done := make(chan struct{})
		go func() {
			for i := 0; i < 3; i++ {
				handler(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/callback?state="+nonce+"&jwt="+token, nil))
			}
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("handler blocked on a repeated request")
		}
	})
}

// ---------------------------------------------------------------------------
// Login workflows against a stand-in server
// ---------------------------------------------------------------------------

// fakeVoussh implements just enough of the server's token endpoints.
type fakeVoussh struct {
	t      *testing.T
	issuer *testIssuer
	server *httptest.Server

	mu        sync.Mutex
	requests  int
	tokenBody map[string]json.RawMessage // last POST /token body
	bearer    string
	deviceJWK ed25519.PublicKey
	deviceAud string
	polls     int
}

func newFakeVoussh(t *testing.T) *fakeVoussh {
	f := &fakeVoussh{t: t, issuer: newTestIssuer(t)}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Write(f.issuer.issuer.JWKS())
	})
	mux.HandleFunc("/token", f.handleToken)
	mux.HandleFunc("/device/code", f.handleDeviceCode)
	mux.HandleFunc("/device/token", f.handleDeviceToken)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeVoussh) respond(w http.ResponseWriter, pub ed25519.PublicKey, audience string) {
	token := f.issuer.issue(pub, func(r *httpcred.TokenRequest) { r.Audience = audience })
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResponse{AccessToken: token, TokenType: "DPoP", ExpiresIn: 900, Audience: audience})
}

func (f *fakeVoussh) handleToken(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	f.bearer = r.Header.Get("Authorization")
	body, _ := io.ReadAll(r.Body)
	f.tokenBody = map[string]json.RawMessage{}
	if err := json.Unmarshal(body, &f.tokenBody); err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	if f.bearer != "Bearer service-secret" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"unauthorized"}`)
		return
	}
	pub, err := httpcred.ParsePublicJWK(f.tokenBody["jwk"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var audience string
	json.Unmarshal(f.tokenBody["audience"], &audience)
	f.respond(w, pub, audience)
}

func (f *fakeVoussh) handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r.ParseForm()
	raw, err := base64.RawURLEncoding.DecodeString(r.PostForm.Get("jwk"))
	if err != nil {
		http.Error(w, "bad jwk", http.StatusBadRequest)
		return
	}
	pub, err := httpcred.ParsePublicJWK(raw)
	if err != nil || r.PostForm.Get("pubkey") != "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	f.deviceJWK, f.deviceAud = pub, r.PostForm.Get("audience")
	json.NewEncoder(w).Encode(deviceCodeResponse{
		DeviceCode: "device-code", UserCode: "WDJB-MJHT",
		VerificationURI: f.server.URL + "/device", ExpiresIn: 60, Interval: 1,
	})
}

func (f *fakeVoussh) handleDeviceToken(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r.ParseForm()
	f.polls++
	if r.PostForm.Get("device_code") != "device-code" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"invalid_grant"}`)
		return
	}
	f.respond(w, f.deviceJWK, f.deviceAud)
}

func writeServiceToken(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "service-token")
	if err := os.WriteFile(path, []byte(value+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTokenLoginWithServiceToken(t *testing.T) {
	useTempConfigDir(t)
	fake := newFakeVoussh(t)
	keyPath := filepath.Join(t.TempDir(), "key")

	rec, err := tokenLogin(tokenLoginOptions{
		Server: fake.server.URL + "/", Audience: testAudience, Role: "fetch",
		Mode: tokenModeService, KeyPath: keyPath, ServiceTokenFile: writeServiceToken(t, "service-secret"),
	})
	if err != nil {
		t.Fatalf("tokenLogin: %v", err)
	}

	if fake.bearer != "Bearer service-secret" {
		t.Errorf("Authorization = %q", fake.bearer)
	}
	// What left the machine: the audience, the role and a public key —
	// and no member of that key beyond its public half.
	var jwk map[string]string
	if err := json.Unmarshal(fake.tokenBody["jwk"], &jwk); err != nil {
		t.Fatal(err)
	}
	if len(jwk) != 3 || jwk["kty"] != "OKP" || jwk["crv"] != "Ed25519" || jwk["x"] == "" {
		t.Errorf("submitted jwk = %v, want exactly the public members", jwk)
	}
	key, err := keyfile.LoadPrivate(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if seed := base64.RawURLEncoding.EncodeToString(key.Seed()); strings.Contains(fmt.Sprint(fake.tokenBody), seed) {
		t.Fatal("the private key was sent to the server")
	}
	if len(fake.tokenBody) != 3 {
		t.Errorf("request body has fields %v, want audience, role and jwk only", fake.tokenBody)
	}

	if rec.Mode != tokenModeService || rec.Audience != testAudience || rec.Server != fake.server.URL {
		t.Errorf("record = %+v", rec)
	}
	if rec.KeyThumbprint != httpcred.Thumbprint(key.Public().(ed25519.PublicKey)) {
		t.Error("stored token is not bound to the local key")
	}
	stored, err := loadToken(testAudience)
	if err != nil || stored.AccessToken != rec.AccessToken {
		t.Fatalf("credential was not stored: %v", err)
	}
	// The record remembers where the service token lives, never what it is.
	raw, _ := os.ReadFile(filepath.Join(tokenDir(), tokenFileName(testAudience)))
	if bytes.Contains(raw, []byte("service-secret")) {
		t.Fatal("the service token was copied into the credential store")
	}

	t.Run("rejected service token", func(t *testing.T) {
		_, err := tokenLogin(tokenLoginOptions{
			Server: fake.server.URL, Audience: "other", Mode: tokenModeService,
			KeyPath: keyPath, ServiceTokenFile: writeServiceToken(t, "wrong"),
		})
		if err == nil {
			t.Fatal("login succeeded with a rejected service token")
		}
		if _, err := loadToken("other"); err == nil {
			t.Error("a credential was stored after a failed login")
		}
	})
}

func TestTokenLoginWithDeviceFlow(t *testing.T) {
	useTempConfigDir(t)
	fake := newFakeVoussh(t)

	rec, err := tokenLogin(tokenLoginOptions{
		Server: fake.server.URL, Audience: testAudience, Mode: tokenModeDevice,
		KeyPath: filepath.Join(t.TempDir(), "key"),
	})
	if err != nil {
		t.Fatalf("tokenLogin: %v", err)
	}
	if fake.deviceAud != testAudience {
		t.Errorf("device request audience = %q", fake.deviceAud)
	}
	if rec.Mode != tokenModeDevice || rec.Subject != "alice@example.com" || rec.expired(0) {
		t.Errorf("record = %+v", rec)
	}
	if rec.KeyThumbprint != httpcred.Thumbprint(fake.deviceJWK) {
		t.Error("stored token is not bound to the key sent with the device request")
	}
}

// The browser flow, with the test playing the browser: it follows /login to
// wherever the server sends it, which ends at vsh's own loopback listener.
func TestTokenLoginWithBrowserFlow(t *testing.T) {
	useTempConfigDir(t)
	issuer := newTestIssuer(t)

	var login url.Values
	respond := func(q url.Values) url.Values { return nil }
	issuesTokens := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" && issuesTokens {
			w.Write(issuer.issuer.JWKS())
			return
		}
		if r.URL.Path != "/login" {
			http.NotFound(w, r)
			return
		}
		login = r.URL.Query()
		// Stands in for Google sign-in plus the confirmation page.
		http.Redirect(w, r, "http://localhost:"+login.Get("cli_port")+"/callback?"+respond(login).Encode(), http.StatusSeeOther)
	}))
	defer server.Close()

	oldOpen := openLoginURL
	defer func() { openLoginURL = oldOpen }()
	openLoginURL = func(loginURL string) {
		go func() {
			resp, err := http.Get(loginURL)
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	submittedKey := func(q url.Values) ed25519.PublicKey {
		raw, err := base64.RawURLEncoding.DecodeString(q.Get("jwk"))
		if err != nil {
			t.Errorf("jwk parameter is not base64url: %v", err)
			return nil
		}
		pub, err := httpcred.ParsePublicJWK(raw)
		if err != nil {
			t.Errorf("jwk parameter is not a public JWK: %v", err)
		}
		return pub
	}
	keyPath := filepath.Join(t.TempDir(), "key")
	opts := tokenLoginOptions{Server: server.URL, Audience: testAudience, Role: "reader", Mode: tokenModeBrowser, KeyPath: keyPath}

	t.Run("approved", func(t *testing.T) {
		respond = func(q url.Values) url.Values {
			token := issuer.issue(submittedKey(q), func(r *httpcred.TokenRequest) { r.Role = q.Get("role") })
			return url.Values{"jwt": {token}, "state": {q.Get("cli_state")}}
		}
		rec, err := tokenLogin(opts)
		if err != nil {
			t.Fatalf("tokenLogin: %v", err)
		}
		if login.Get("audience") != testAudience || login.Get("role") != "reader" || len(login.Get("cli_state")) < 16 {
			t.Errorf("login request = %v", login)
		}
		if login.Get("pubkey") != "" {
			t.Error("a token login also sent an SSH public key")
		}
		key, err := keyfile.LoadPrivate(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		if seed := base64.RawURLEncoding.EncodeToString(key.Seed()); strings.Contains(login.Encode(), seed) {
			t.Fatal("the private key was sent to the server")
		}
		if rec.Role != "reader" || rec.Mode != tokenModeBrowser || rec.KeyThumbprint != httpcred.Thumbprint(key.Public().(ed25519.PublicKey)) {
			t.Errorf("record = %+v", rec)
		}
	})

	t.Run("rejected", func(t *testing.T) {
		respond = func(q url.Values) url.Values {
			return url.Values{"error": {"access_denied"}, "error_description": {"the request was rejected"}, "state": {q.Get("cli_state")}}
		}
		os.Remove(filepath.Join(tokenDir(), tokenFileName(testAudience)))
		if _, err := tokenLogin(opts); err == nil || !strings.Contains(err.Error(), "rejected") {
			t.Fatalf("error = %v, want the rejection reported", err)
		}
		if _, err := loadToken(testAudience); err == nil {
			t.Error("a credential was stored after a rejected login")
		}
	})

	// A server without HTTP credentials would run this as a certificate
	// login; vsh must notice up front instead of waiting for a token.
	t.Run("server does not issue tokens", func(t *testing.T) {
		issuesTokens = false
		defer func() { issuesTokens = true }()
		opened := false
		browser := openLoginURL
		openLoginURL = func(string) { opened = true }
		defer func() { openLoginURL = browser }()

		if _, err := tokenLogin(opts); err == nil || !strings.Contains(err.Error(), "does not issue HTTP credentials") {
			t.Fatalf("error = %v, want the server's lack of support reported", err)
		}
		if opened {
			t.Error("the browser was opened against a server that cannot issue tokens")
		}
	})

	// A server that answers with a token for somebody else's key must not
	// get it stored.
	t.Run("token for another key", func(t *testing.T) {
		_, otherPub := newKey(t)
		respond = func(q url.Values) url.Values {
			return url.Values{"jwt": {issuer.issue(otherPub, nil)}, "state": {q.Get("cli_state")}}
		}
		if _, err := tokenLogin(opts); err == nil || !strings.Contains(err.Error(), "different key") {
			t.Fatalf("error = %v, want the key mismatch reported", err)
		}
		if _, err := loadToken(testAudience); err == nil {
			t.Error("a mismatched credential was stored")
		}
	})
}

// Renewal repeats the workflow that produced the credential, with the same
// key, so the renewed token is a drop-in replacement.
func TestRenewReusesTheOriginalWorkflow(t *testing.T) {
	useTempConfigDir(t)
	fake := newFakeVoussh(t)
	first, err := tokenLogin(tokenLoginOptions{
		Server: fake.server.URL, Audience: testAudience, Role: "fetch", Mode: tokenModeService,
		KeyPath: filepath.Join(t.TempDir(), "key"), ServiceTokenFile: writeServiceToken(t, "service-secret"),
	})
	if err != nil {
		t.Fatal(err)
	}

	opts := renewOptions(first)
	if opts.Server != first.Server || opts.Mode != tokenModeService || opts.KeyPath != first.KeyPath ||
		opts.ServiceTokenFile != first.ServiceTokenFile || opts.Audience != testAudience {
		t.Fatalf("renewOptions = %+v", opts)
	}
	second, err := tokenLogin(opts)
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if second.AccessToken == first.AccessToken {
		t.Error("renewal returned the same token")
	}
	if second.KeyThumbprint != first.KeyThumbprint {
		t.Error("renewal switched keys")
	}

	// A renewal that comes back as somebody else is refused, and the stored
	// credential is left as it was.
	stolen := *second
	stolen.Subject = "mallory@example.com"
	if _, err := tokenLogin(renewOptions(&stolen)); err == nil || !strings.Contains(err.Error(), "refusing to replace") {
		t.Fatalf("error = %v, want the identity change refused", err)
	}
	if kept, err := loadToken(testAudience); err != nil || kept.AccessToken != second.AccessToken {
		t.Errorf("stored credential changed after a refused renewal (%v)", err)
	}
}

func TestUsableToken(t *testing.T) {
	useTempConfigDir(t)
	fake := newFakeVoussh(t)
	issuer := newTestIssuer(t)
	_, pub := newKey(t)

	store := func(mode string, expiresIn time.Duration, extra func(*tokenRecord)) {
		rec := &tokenRecord{
			Server: fake.server.URL, Audience: testAudience, Role: "default", Mode: mode,
			ExpiresAt: time.Now().Add(expiresIn), AccessToken: issuer.issue(pub, nil),
		}
		if extra != nil {
			extra(rec)
		}
		if err := saveToken(rec); err != nil {
			t.Fatal(err)
		}
	}

	store(tokenModeBrowser, 5*time.Minute, nil)
	if _, err := usableToken(testAudience); err != nil {
		t.Fatalf("valid token refused: %v", err)
	}

	// An interactive credential cannot be renewed silently: say how.
	for _, expiresIn := range []time.Duration{-time.Minute, 2 * time.Second} {
		store(tokenModeDevice, expiresIn, nil)
		_, err := usableToken(testAudience)
		if err == nil || !strings.Contains(err.Error(), "vsh token renew") {
			t.Errorf("expiring in %s: error = %v, want a hint to renew", expiresIn, err)
		}
	}
	if fake.requests != 0 {
		t.Fatal("an interactive credential triggered a silent request to the server")
	}

	// A machine credential renews itself.
	store(tokenModeService, -time.Minute, func(rec *tokenRecord) {
		rec.KeyPath = filepath.Join(t.TempDir(), "key")
		rec.ServiceTokenFile = writeServiceToken(t, "service-secret")
	})
	rec, err := usableToken(testAudience)
	if err != nil {
		t.Fatalf("service credential did not renew: %v", err)
	}
	if rec.expired(0) || fake.requests != 1 {
		t.Errorf("renewed record = %+v after %d requests", rec, fake.requests)
	}
}
