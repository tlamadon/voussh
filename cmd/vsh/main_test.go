package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// flushRecorder is a ResponseWriter that records whether Flush was called,
// so ordering against the resultChan send can be asserted.
type flushRecorder struct {
	header  http.Header
	flushed bool
}

func (f *flushRecorder) Header() http.Header {
	if f.header == nil {
		f.header = http.Header{}
	}
	return f.header
}
func (f *flushRecorder) Write(p []byte) (int, error) { return len(p), nil }
func (f *flushRecorder) WriteHeader(int)             {}
func (f *flushRecorder) Flush()                      { f.flushed = true }

// The handler must flush BEFORE signalling resultChan — the main goroutine
// tears the server down on receive, so an unflushed page races the teardown.
// The channel here is unbuffered on purpose: the send synchronises with the
// receive, so everything the handler did before sending (including the
// Flush) happens-before the assertion. If the Flush moved after the send,
// flushed would still be false at receive time, deterministically.
func TestCallbackFlushesBeforeSignalling(t *testing.T) {
	for _, path := range []string{"/callback?cert=ZmFrZQ&role=default", "/callback"} {
		t.Run(path, func(t *testing.T) {
			rec := &flushRecorder{}
			resultChan := make(chan loginResult)
			go callbackHandler(resultChan)(rec, httptest.NewRequest(http.MethodGet, path, nil))
			<-resultChan
			if !rec.flushed {
				t.Error("resultChan signalled before the response was flushed")
			}
		})
	}
}

// testCertB64 builds a real signed certificate, encoded the way the voussh
// server passes it to the callback.
func testCertB64(t *testing.T, keyID string, principals []string, validity time.Duration) string {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caSigner, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatalf("build CA signer: %v", err)
	}
	userPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate user key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(userPub)
	if err != nil {
		t.Fatalf("wrap user key: %v", err)
	}
	cert := &ssh.Certificate{
		Key:             sshPub,
		CertType:        ssh.UserCert,
		KeyId:           keyID,
		ValidPrincipals: principals,
		ValidAfter:      uint64(time.Now().Add(-5 * time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(validity).Unix()),
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(ssh.MarshalAuthorizedKey(cert))
}

// The success page must describe the certificate that was issued — who,
// which principals, for how long — not just say "it worked".
func TestCallbackPageShowsCertificateDetails(t *testing.T) {
	certB64 := testCertB64(t, "alice@example.com@deploy", []string{"root", "admin"}, 8*time.Hour)

	resultChan := make(chan loginResult, 1)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/callback?cert="+certB64+"&role=deploy", nil)
	callbackHandler(resultChan)(rr, req)

	page := rr.Body.String()
	for _, want := range []string{
		"alice@example.com", "deploy", "root, admin", "8h0m0s", "SHA256:", "</html>",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page does not mention %q:\n%s", want, page)
		}
	}

	// The resultChan contract is untouched: the CLI still receives the raw
	// base64 certificate to decode and save itself.
	result := <-resultChan
	if result.cert != certB64 || result.err != nil {
		t.Errorf("result = %+v, want the raw cert and no error", result)
	}
}

// A cert parameter that does not parse must fall back to the plain success
// page rather than breaking a login the CLI is about to complete.
func TestCallbackPageFallsBackOnUnparseableCert(t *testing.T) {
	resultChan := make(chan loginResult, 1)
	rr := httptest.NewRecorder()
	callbackHandler(resultChan)(rr, httptest.NewRequest(http.MethodGet, "/callback?cert=ZmFrZQ", nil))
	<-resultChan

	page := rr.Body.String()
	if !strings.Contains(page, "Login Successful!") || !strings.Contains(page, "</html>") {
		t.Errorf("fallback page is broken:\n%s", page)
	}
}

func TestSplitKeyID(t *testing.T) {
	cases := []struct{ in, email, role string }{
		{"alice@example.com@deploy", "alice@example.com", "deploy"},
		{"herdr-hq@service", "herdr-hq@service", ""}, // one @ is not the email@role shape
		{"no-at-sign", "no-at-sign", ""},
	}
	for _, tc := range cases {
		if email, role := splitKeyID(tc.in); email != tc.email || role != tc.role {
			t.Errorf("splitKeyID(%q) = %q, %q; want %q, %q", tc.in, email, role, tc.email, tc.role)
		}
	}
}

// End-to-end contract: the browser receives the complete result page even
// though the main goroutine tears the callback server down the moment
// resultChan signals. The sequence reproduces the worst-case ordering — the
// client sends its request but reads nothing until after the signal has
// fired AND the server has been shut down. (This cannot deterministically
// reproduce the original Close() truncation: loopback kernel buffers can
// deliver already-flushed bytes even through an abrupt close. The ordering
// half of the fix is therefore pinned separately by
// TestCallbackFlushesBeforeSignalling.)
func TestCallbackPageSurvivesShutdown(t *testing.T) {
	cases := []struct {
		name string
		path string
		want string
	}{
		{"success page", "/callback?cert=ZmFrZQ&role=default", "Login Successful!"},
		// The failure page deserves to render just as much: that is the one
		// moment the user actually needs to read what happened.
		{"failure page", "/callback", "Login Failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			resultChan := make(chan loginResult, 1)
			mux := http.NewServeMux()
			mux.HandleFunc("/callback", callbackHandler(resultChan))
			srv := &http.Server{Handler: mux}
			go srv.Serve(listener)

			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()
			fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", tc.path)

			// Wait for the handler's signal, exactly as cmdLogin does...
			var result loginResult
			select {
			case result = <-resultChan:
			case <-time.After(5 * time.Second):
				t.Fatal("handler never signalled resultChan")
			}
			// ...then shut the server down BEFORE reading a single byte of
			// the response.
			shutdownCallbackServer(srv)

			body, err := io.ReadAll(conn)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			if !strings.Contains(string(body), tc.want) {
				t.Errorf("response does not contain %q:\n%s", tc.want, body)
			}
			if !strings.Contains(string(body), "</html>") {
				t.Errorf("response truncated:\n%s", body)
			}

			// The resultChan contract is unchanged: cert+role on success, an
			// error when the certificate is missing.
			if tc.want == "Login Successful!" {
				if result.cert != "ZmFrZQ" || result.role != "default" || result.err != nil {
					t.Errorf("result = %+v, want cert/role and no error", result)
				}
			} else if result.err == nil {
				t.Error("failure path did not report an error")
			}
		})
	}
}

// runInitFunction sources the output of `vsh init` in bash and runs a script
// against a stand-in vsh binary. PATH holds that binary and nothing else —
// in particular no `which` — as on a minimal machine or in a build sandbox.
func runInitFunction(t *testing.T, stub, script string, args ...string) string {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vsh"), []byte(stub), 0700); err != nil {
		t.Fatal(err)
	}

	// cmdInit prints to stdout; borrow it for a moment.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	cmdInit()
	os.Stdout = stdout
	w.Close()
	initScript, _ := io.ReadAll(r)
	initPath := filepath.Join(dir, "init.sh")
	if err := os.WriteFile(initPath, initScript, 0600); err != nil {
		t.Fatal(err)
	}

	// A function that calls itself recurses until bash dies; do not wait.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bash, append([]string{"-c", ". \"$1\"; shift\n" + script, "bash", initPath}, args...)...)
	cmd.Env = []string{"PATH=" + dir, "BASH=" + bash, "HOME=" + dir}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shell failed: %v\n%s", err, out)
	}
	return string(out)
}

// The shell function must reach the binary and not itself, including when
// there is no `which` to ask and when it has been defined twice.
func TestInitShellFunctionReachesTheBinary(t *testing.T) {
	stub := `#!/bin/sh
case "$*" in
  "login --local") [ "$VSH_EVAL_MODE" = 1 ] && echo "export VSH_LOCAL_CERT='cert'" ;;
  *) echo "binary: $*" ;;
esac
`
	script := `
vsh ssh web1
. "$1"
vsh status
vsh login --local >/dev/null; echo "local cert: [$VSH_LOCAL_CERT]"
vsh logout
vsh logout
`
	// The script is handed the init file a second time, to define the
	// function again over itself.
	dir := t.TempDir()
	again := filepath.Join(dir, "init-again.sh")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	cmdInit()
	os.Stdout = stdout
	w.Close()
	initScript, _ := io.ReadAll(r)
	if err := os.WriteFile(again, initScript, 0600); err != nil {
		t.Fatal(err)
	}

	got := runInitFunction(t, stub, script, again)
	want := `binary: ssh web1
binary: status
local cert: [cert]
Local session cleared
binary: logout
`
	if got != want {
		t.Errorf("shell session:\n%s\nwant:\n%s", got, want)
	}
}
