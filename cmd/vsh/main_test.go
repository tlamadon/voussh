package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
