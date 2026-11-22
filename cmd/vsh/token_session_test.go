package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tlamadon/voussh/httpcred"
)

// useEmptyHome gives the test a home directory with nothing in it, and a
// config directory that does not exist yet, so that anything vsh writes shows
// up as an entry where there were none.
func useEmptyHome(t *testing.T) string {
	t.Helper()
	oldDir, oldServer := vshDir, serverURL
	t.Cleanup(func() { vshDir, serverURL = oldDir, oldServer })
	home := t.TempDir()
	vshDir = filepath.Join(home, ".config", "voussh")
	serverURL = ""
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	for _, name := range []string{"VSH_SERVER", envLocalToken, envLocalTokenKey} {
		t.Setenv(name, "")
	}
	return home
}

// filesUnder lists everything below dir, directories included.
func filesUnder(t *testing.T, dir string) []string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != dir {
			found = append(found, strings.TrimPrefix(path, dir))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
// The replacement is a pipe, so code that asks sees "not a terminal".
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		out, _ := io.ReadAll(r)
		done <- string(out)
	}()
	fn()
	os.Stdout = old
	w.Close()
	return <-done
}

var exportLine = regexp.MustCompile(`^export (VSH_LOCAL_TOKEN(?:_KEY)?)='([A-Za-z0-9_.+/=-]+)'$`)

// applyExports installs the output of a --local login the way `eval` would,
// insisting that it is exactly the two export lines and nothing else.
func applyExports(t *testing.T, output string) map[string]string {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("a --local login wrote %d lines to stdout, want exactly two exports", len(lines))
	}
	vars := map[string]string{}
	for _, line := range lines {
		m := exportLine.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("stdout line is not an export of a session variable (%d bytes)", len(line))
		}
		vars[m[1]] = m[2]
		t.Setenv(m[1], m[2])
	}
	if len(vars) != 2 {
		t.Fatalf("exports set %d distinct variables, want both", len(vars))
	}
	return vars
}

// browserLoginServer stands in for voussh's browser flow, with the test as
// the browser: /login answers with the redirect that a signed-in user's
// approval would produce, carrying a token for the submitted key.
func browserLoginServer(t *testing.T, issuer *testIssuer) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/jwks.json":
			w.Write(issuer.issuer.JWKS())
		case "/login":
			q := r.URL.Query()
			raw, _ := base64.RawURLEncoding.DecodeString(q.Get("jwk"))
			pub, err := httpcred.ParsePublicJWK(raw)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			back := url.Values{"jwt": {issuer.issue(pub, nil)}, "state": {q.Get("cli_state")}}
			http.Redirect(w, r, "http://localhost:"+q.Get("cli_port")+"/callback?"+back.Encode(), http.StatusSeeOther)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	old := openLoginURL
	openLoginURL = func(loginURL string) {
		go func() {
			if resp, err := http.Get(loginURL); err == nil {
				resp.Body.Close()
			}
		}()
	}
	t.Cleanup(func() { openLoginURL = old })
	return server
}

// sessionEnv puts a session credential for the given token into the
// environment directly, for tests that are not about logging in.
func sessionEnv(t *testing.T, token string, key ed25519.PrivateKey) {
	t.Helper()
	t.Setenv(envLocalToken, token)
	t.Setenv(envLocalTokenKey, base64.StdEncoding.EncodeToString(key.Seed()))
}

// ---------------------------------------------------------------------------
// The two properties the mode exists for
// ---------------------------------------------------------------------------

// A device-flow login with --local, run through the command itself, followed
// by every command that uses the credential: nothing appears under the home
// directory at any point — no key, no token, no history, not even the config
// directory.
func TestSessionLoginWritesNothingToDisk(t *testing.T) {
	home := useEmptyHome(t)
	fake := newFakeVoussh(t)
	broker := newFakeBroker(t, fake.issuer)

	stdout := captureStdout(t, func() {
		cmdTokenLogin([]string{"--local", "--device", "--server", fake.server.URL, "--audience", testAudience})
	})
	if found := filesUnder(t, home); len(found) != 0 {
		t.Fatalf("the login wrote to disk: %v", found)
	}
	vars := applyExports(t, stdout)

	// The credential in the environment is the whole of it: a token bound to
	// a key that came out of the same login.
	rec, err := usableToken("")
	if err != nil {
		t.Fatalf("session credential is not usable: %v", err)
	}
	if !rec.session() || rec.Audience != testAudience || rec.Subject != "alice@example.com" {
		t.Fatalf("record = %+v", rec)
	}
	if rec.AccessToken != vars[envLocalToken] || rec.KeyPath != "" {
		t.Errorf("record does not come from the environment: key path %q", rec.KeyPath)
	}
	if rec.KeyThumbprint != httpcred.Thumbprint(fake.deviceJWK) {
		t.Error("the token is not bound to the key generated for this login")
	}

	// Each command that consumes the credential, through its real entry
	// point. (They exit the test binary on failure, which is a failure.)
	target := broker.server.URL + "/v1/secrets/db"
	if body := captureStdout(t, func() { cmdHTTP([]string{target}) }); !strings.Contains(body, `"subject":"alice@example.com"`) {
		t.Errorf("vsh http with the session credential returned %q", body)
	}
	if out := captureStdout(t, func() { cmdTokenPrint(nil) }); strings.TrimSpace(out) != vars[envLocalToken] {
		t.Error("vsh token print did not print the session token")
	}
	if out := captureStdout(t, func() { cmdTokenProof([]string{target}) }); strings.Count(out, ".") != 2 {
		t.Errorf("vsh token proof did not print a proof")
	}
	status := captureStdout(t, func() { cmdTokenStatus(nil) })
	if !strings.Contains(status, "this shell only") || strings.Contains(status, vars[envLocalToken]) {
		t.Errorf("vsh token status = %q", status)
	}

	if len(broker.failures) != 0 {
		t.Errorf("the broker rejected a request: %v", broker.failures)
	}
	if found := filesUnder(t, home); len(found) != 0 {
		t.Fatalf("using the session wrote to disk: %v", found)
	}
}

// `vsh http` with a session credential sends a proof that a verifying broker
// accepts: signed by the session key, for this request, hashing this token.
func TestSessionCredentialProducesValidProofs(t *testing.T) {
	useEmptyHome(t)
	fake := newFakeVoussh(t)
	broker := newFakeBroker(t, fake.issuer)

	issued, err := tokenLogin(tokenLoginOptions{
		Server: fake.server.URL, Audience: testAudience, Mode: tokenModeDevice, Local: true,
	})
	if err != nil {
		t.Fatalf("tokenLogin: %v", err)
	}
	applyExports(t, sessionExports(issued))

	// From here on, only what the environment holds is used.
	rec, err := usableToken(testAudience)
	if err != nil {
		t.Fatal(err)
	}
	key, err := rec.privateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := newRequestClient(10 * time.Second)
	for _, method := range []string{"GET", "PUT", "GET"} {
		resp, err := signedRequest(client, key, rec.AccessToken, method, broker.server.URL+"/v1/secrets/db?x=1", nil, []byte("body"))
		if err != nil {
			t.Fatal(err)
		}
		if got := readJSON(t, resp); got["subject"] != "alice@example.com" || got["method"] != method {
			t.Errorf("%s: broker saw %v", method, got)
		}
	}
	if len(broker.failures) != 0 {
		t.Fatalf("the broker rejected a proof: %v", broker.failures)
	}

	// The proof key is the session's and no other: the broker only accepted
	// the requests because its thumbprint is the token's cnf.jkt.
	var header struct {
		JWK map[string]string `json:"jwk"`
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(broker.proofs[0], ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatal(err)
	}
	if header.JWK["x"] != base64.RawURLEncoding.EncodeToString(fake.deviceJWK) {
		t.Error("the proof was not signed by the key generated for the session")
	}

	// Each login gets its own key.
	again, err := tokenLogin(tokenLoginOptions{
		Server: fake.server.URL, Audience: testAudience, Mode: tokenModeDevice, Local: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if again.KeyThumbprint == issued.KeyThumbprint {
		t.Error("two --local logins shared a key")
	}
}

// The browser flow gets the same mode for free.
func TestSessionLoginWithBrowserFlow(t *testing.T) {
	home := useEmptyHome(t)
	issuer := newTestIssuer(t)
	server := browserLoginServer(t, issuer)

	rec, err := tokenLogin(tokenLoginOptions{
		Server: server.URL, Audience: testAudience, Mode: tokenModeBrowser, Local: true,
	})
	if err != nil {
		t.Fatalf("tokenLogin: %v", err)
	}
	if !rec.session() || rec.KeyPath != "" {
		t.Errorf("record = %+v", rec)
	}
	if found := filesUnder(t, home); len(found) != 0 {
		t.Fatalf("the login wrote to disk: %v", found)
	}
}

// ---------------------------------------------------------------------------
// Expiry and broken sessions
// ---------------------------------------------------------------------------

func TestExpiredSessionAsksForANewLogin(t *testing.T) {
	useEmptyHome(t)
	fake := newFakeVoussh(t)
	key, pub := newKey(t)
	// A token that has run out, and one about to.
	for _, age := range []time.Duration{time.Hour, 15*time.Minute - 5*time.Second} {
		sessionEnv(t, fake.issuer.issue(pub, func(r *httpcred.TokenRequest) { r.Now = time.Now().Add(-age) }), key)

		_, err := usableToken("")
		if err == nil {
			t.Fatalf("issued %s ago: an expired session token was handed out", age)
		}
		for _, want := range []string{"expired", "Log in again", "vsh token login --local", testAudience} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("issued %s ago: error %q does not mention %q", age, err, want)
			}
		}
	}

	// Nothing was attempted on the user's behalf...
	if fake.requests != 0 || fake.polls != 0 {
		t.Error("an expired session contacted the server by itself")
	}
	// ...and a stored credential for the same audience is not quietly used
	// in its place: the user asked for a session and should hear that it ended.
	stored := &tokenRecord{
		Audience: testAudience, Mode: tokenModeBrowser, Subject: "bob@example.com",
		ExpiresAt: time.Now().Add(time.Hour), AccessToken: "stored",
	}
	if err := saveToken(stored); err != nil {
		t.Fatal(err)
	}
	if rec, err := usableToken(testAudience); err == nil {
		t.Fatalf("fell back to the stored credential of %s", rec.Subject)
	}
}

func TestSessionTokenValidation(t *testing.T) {
	useEmptyHome(t)
	issuer := newTestIssuer(t)
	key, pub := newKey(t)
	otherKey, _ := newKey(t)
	token := issuer.issue(pub, nil)
	seed := base64.StdEncoding.EncodeToString(key.Seed())

	if rec, err := sessionToken(); rec != nil || err != nil {
		t.Fatalf("no variables set: %v, %v", rec, err)
	}
	// A stored credential is there to be fallen back on, if anything did.
	stored := &tokenRecord{Audience: testAudience, Mode: tokenModeBrowser, ExpiresAt: time.Now().Add(time.Hour), AccessToken: "stored"}
	if err := saveToken(stored); err != nil {
		t.Fatal(err)
	}

	sessionEnv(t, token, key)
	rec, err := sessionToken()
	if err != nil {
		t.Fatalf("valid session refused: %v", err)
	}
	if rec.Audience != testAudience || rec.Role != "default" || rec.Subject != "alice@example.com" || rec.Issuer != testIssuerName {
		t.Errorf("record = %+v", rec)
	}

	bad := map[string][2]string{
		"token without key":  {token, ""},
		"key without token":  {"", seed},
		"key not base64":     {token, "!!!"},
		"key of wrong size":  {token, base64.StdEncoding.EncodeToString([]byte("short"))},
		"token not a jwt":    {"not-a-token", seed},
		"token for some key": {token, base64.StdEncoding.EncodeToString(otherKey.Seed())},
	}
	for name, env := range bad {
		t.Setenv(envLocalToken, env[0])
		t.Setenv(envLocalTokenKey, env[1])
		rec, err := sessionToken()
		if err == nil {
			t.Errorf("%s: accepted as %+v", name, rec)
			continue
		}
		// The message says how to clear it, and never repeats the secret.
		if !strings.Contains(err.Error(), "unset VSH_LOCAL_TOKEN VSH_LOCAL_TOKEN_KEY") {
			t.Errorf("%s: error %q does not say how to clear the session", name, err)
		}
		for _, secret := range env {
			if len(secret) > 8 && strings.Contains(err.Error(), secret) {
				t.Errorf("%s: the error message contains a session variable's value", name)
			}
		}
		// A broken session stops every command, rather than being skipped in
		// favour of whatever is on disk.
		if _, err := selectToken(""); err == nil {
			t.Errorf("%s: selectToken ignored the broken session", name)
		}
	}
}

// The session comes first, as a local SSH session does, but only for its own
// audience.
func TestSessionPrecedence(t *testing.T) {
	useEmptyHome(t)
	issuer := newTestIssuer(t)
	key, pub := newKey(t)
	for _, audience := range []string{testAudience, "billing-api"} {
		rec := &tokenRecord{Audience: audience, Mode: tokenModeBrowser, ExpiresAt: time.Now().Add(time.Hour), AccessToken: "stored"}
		if err := saveToken(rec); err != nil {
			t.Fatal(err)
		}
	}
	sessionEnv(t, issuer.issue(pub, nil), key)

	for audience, wantSession := range map[string]bool{"": true, testAudience: true, "billing-api": false} {
		rec, err := selectToken(audience)
		if err != nil {
			t.Fatalf("selectToken(%q): %v", audience, err)
		}
		if rec.session() != wantSession {
			t.Errorf("selectToken(%q): session = %v, want %v", audience, rec.session(), wantSession)
		}
	}
	if _, err := selectToken("unknown"); err == nil {
		t.Error("an audience that is neither the session's nor stored was resolved")
	}
}

// ---------------------------------------------------------------------------
// Getting the credential into the shell, and out again
// ---------------------------------------------------------------------------

// What --local prints must survive a real shell's eval unchanged.
func TestSessionExportsEvaluateInAShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs a POSIX shell")
	}
	issuer := newTestIssuer(t)
	key, pub := newKey(t)
	rec := &tokenRecord{AccessToken: issuer.issue(pub, nil), key: key}
	exports := sessionExports(rec)

	script := `eval "$1"; printf '%s\n%s\n' "$VSH_LOCAL_TOKEN" "$VSH_LOCAL_TOKEN_KEY"; env | grep -c '^VSH_LOCAL_TOKEN'`
	out, err := exec.Command("sh", "-c", script, "sh", exports).Output()
	if err != nil {
		t.Fatalf("eval failed: %v", err)
	}
	want := rec.AccessToken + "\n" + base64.StdEncoding.EncodeToString(key.Seed()) + "\n2\n"
	if string(out) != want {
		t.Error("the shell did not end up with the exported values, exported to its children")
	}
}

// The key must not be able to reach a file through the record.
func TestSessionKeyIsNeverSerialized(t *testing.T) {
	key, _ := newKey(t)
	rec := &tokenRecord{Audience: testAudience, AccessToken: "t", key: key}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding, base64.RawStdEncoding, base64.URLEncoding} {
		if bytes.Contains(raw, []byte(encoding.EncodeToString(key.Seed()))) || bytes.Contains(raw, []byte(encoding.EncodeToString(key))) {
			t.Fatal("a serialized record contains the session key")
		}
	}
	var back tokenRecord
	if err := json.Unmarshal(raw, &back); err != nil || back.session() {
		t.Errorf("a record read back from JSON claims to be a session (%v)", err)
	}
}

// On a terminal the exports would put the token and key on screen, so the
// login is refused before it starts.
func TestSessionLoginRefusesATerminal(t *testing.T) {
	notTerminal, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer notTerminal.Close()
	if err := checkSessionOutput(notTerminal, nil); err != nil {
		t.Errorf("a file was treated as a terminal: %v", err)
	}

	// A character device stands in for the terminal.
	if runtime.GOOS == "windows" {
		t.Skip("no character device to open")
	}
	device, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skip(err)
	}
	defer device.Close()
	err = checkSessionOutput(device, []string{"--local", "--device", "--audience", testAudience})
	if err == nil {
		t.Fatal("a --local login was allowed to print to a terminal")
	}
	if want := `eval "$(vsh token login --local --device --audience secret-broker)"`; !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not show how to run it (%s)", err, want)
	}
}

// A --local login never asks which server to use and never saves one.
func TestSessionLoginServer(t *testing.T) {
	home := useEmptyHome(t)
	failIfAsked(t)

	if _, err := sessionLoginServer(""); err == nil {
		t.Error("a server was invented")
	}
	if got, err := sessionLoginServer("https://ca.example.com/"); err != nil || got != "https://ca.example.com" {
		t.Errorf("explicit server = %q, %v", got, err)
	}
	serverURL = "https://saved.example.com"
	if got, err := sessionLoginServer(""); err != nil || got != "https://saved.example.com" {
		t.Errorf("configured server = %q, %v", got, err)
	}
	if found := filesUnder(t, home); len(found) != 0 {
		t.Errorf("choosing a server wrote to disk: %v", found)
	}
}

func TestSessionLogout(t *testing.T) {
	useEmptyHome(t)
	issuer := newTestIssuer(t)
	key, pub := newKey(t)
	stored := &tokenRecord{Audience: testAudience, Mode: tokenModeBrowser, ExpiresAt: time.Now().Add(time.Hour), AccessToken: "stored"}
	other := &tokenRecord{Audience: "billing-api", Mode: tokenModeBrowser, ExpiresAt: time.Now().Add(time.Hour), AccessToken: "stored"}
	for _, rec := range []*tokenRecord{stored, other} {
		if err := saveToken(rec); err != nil {
			t.Fatal(err)
		}
	}
	storedAudiences := func() string {
		var names []string
		for _, rec := range listTokens() {
			names = append(names, rec.Audience)
		}
		return strings.Join(names, ",")
	}
	const unset = "unset VSH_LOCAL_TOKEN VSH_LOCAL_TOKEN_KEY\n"

	// With a session: --eval prints the command that ends it, and the
	// credentials on disk are left alone.
	sessionEnv(t, issuer.issue(pub, nil), key)
	if out := captureStdout(t, func() { cmdTokenLogout([]string{"--eval"}) }); out != unset {
		t.Errorf("logout --eval printed %q", out)
	}
	// Without --eval nothing can be done but explain; stdout stays empty.
	if out := captureStdout(t, func() { cmdTokenLogout(nil) }); out != "" {
		t.Errorf("logout printed %q to stdout", out)
	}
	if got := storedAudiences(); got != "billing-api,secret-broker" {
		t.Errorf("stored credentials after a session logout: %s", got)
	}

	// Naming another audience is about the disk, session or not.
	if out := captureStdout(t, func() { cmdTokenLogout([]string{"--audience", "billing-api", "--eval"}) }); out != "" {
		t.Errorf("logout of a stored audience printed %q", out)
	}
	if got := storedAudiences(); got != "secret-broker" {
		t.Errorf("stored credentials = %s, want only secret-broker", got)
	}

	// --all means both.
	if out := captureStdout(t, func() { cmdTokenLogout([]string{"--all", "--eval"}) }); out != unset {
		t.Errorf("logout --all --eval printed %q", out)
	}
	if got := storedAudiences(); got != "" {
		t.Errorf("stored credentials after --all: %s", got)
	}

	// A session too broken to read can still be cleared.
	t.Setenv(envLocalTokenKey, "garbage")
	if out := captureStdout(t, func() { cmdTokenLogout([]string{"--eval"}) }); out != unset {
		t.Errorf("logout --eval of a broken session printed %q", out)
	}

	// Without a session, --eval is an ordinary logout that prints nothing to
	// evaluate.
	t.Setenv(envLocalToken, "")
	t.Setenv(envLocalTokenKey, "")
	if err := saveToken(stored); err != nil {
		t.Fatal(err)
	}
	if out := captureStdout(t, func() { cmdTokenLogout([]string{"--eval"}) }); out != "" {
		t.Errorf("logout --eval without a session printed %q", out)
	}
	if got := storedAudiences(); got != "" {
		t.Errorf("the stored credential was not removed: %s", got)
	}
}

// The shell function from `vsh init`, driven by a real shell around a
// stand-in binary: a --local login lands in the shell's environment, its
// messages stay visible, a failed login changes nothing, and logout clears it.
func TestInitShellFunctionHandlesTokenSessions(t *testing.T) {
	stub := `#!/bin/sh
case "$*" in
  "token login --local --audience ok") echo "device code: ABCD" >&2; echo "export VSH_LOCAL_TOKEN='tok'"; echo "export VSH_LOCAL_TOKEN_KEY='key'" ;;
  "token login --local --audience denied") echo "the request was rejected" >&2; exit 1 ;;
  "token logout --eval") echo "unset VSH_LOCAL_TOKEN VSH_LOCAL_TOKEN_KEY" ;;
  *) echo "passthrough: $*" ;;
esac
`
	script := `
vsh token login --local --audience denied 2>/dev/null; echo "denied: status=$? token=[$VSH_LOCAL_TOKEN]"
vsh token login --local --audience ok 2>"$1"; echo "ok: status=$? token=[$VSH_LOCAL_TOKEN] key=[$VSH_LOCAL_TOKEN_KEY]"
"$BASH" -c 'echo "child sees: [$VSH_LOCAL_TOKEN]"'
vsh token status
vsh token logout; echo "logout: token=[$VSH_LOCAL_TOKEN] key=[$VSH_LOCAL_TOKEN_KEY]"
vsh token logout --audience x
`
	stderrFile := filepath.Join(t.TempDir(), "stderr")
	out := runInitFunction(t, stub, script, stderrFile)
	want := `denied: status=1 token=[]
ok: status=0 token=[tok] key=[key]
child sees: [tok]
passthrough: token status
logout: token=[] key=[]
passthrough: token logout --audience x
`
	if out != want {
		t.Errorf("shell session:\n%s\nwant:\n%s", out, want)
	}
	// The device code was not swallowed along with the exports.
	if shown, _ := os.ReadFile(stderrFile); !strings.Contains(string(shown), "device code: ABCD") {
		t.Errorf("the login's messages did not reach the terminal: %q", shown)
	}
}
