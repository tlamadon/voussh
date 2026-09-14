package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// setupAdminTest installs a config with the panel enabled for alice, plus the
// ring buffer and cookie key the handlers read.
func setupAdminTest(t *testing.T, cfg *Config) *Config {
	t.Helper()
	if cfg == nil {
		cfg = testConfig()
		cfg.Admin = &AdminConfig{Emails: []string{"alice@example.com"}}
	}
	setupDeviceTest(t, cfg)
	initAdmin(cfg)
	return cfg
}

func getAdmin(path, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: adminCookieName, Value: cookie})
	}
	rr := httptest.NewRecorder()
	switch {
	case strings.HasPrefix(path, "/admin/logs"):
		handleAdminLogs(rr, req)
	default:
		handleAdmin(rr, req)
	}
	return rr
}

// adminCookieFor runs the callback leg and extracts the session cookie it set.
func adminCookieFor(t *testing.T, email string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	rr := httptest.NewRecorder()
	handleAdminCallback(rr, req, email)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("admin callback = %d, want 303", rr.Code)
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == adminCookieName {
			return c.Value
		}
	}
	t.Fatal("callback did not set a session cookie")
	return ""
}

func TestAdminDisabledIs404(t *testing.T) {
	cfg := testConfig() // no admin block
	setupAdminTest(t, cfg)

	for _, path := range []string{"/admin", "/admin/logs"} {
		if rr := getAdmin(path, ""); rr.Code != http.StatusNotFound {
			t.Errorf("%s = %d, want 404 when the panel is disabled", path, rr.Code)
		}
	}
}

func TestAdminRedirectsToLogin(t *testing.T) {
	setupAdminTest(t, nil)

	rr := getAdmin("/admin", "")
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("unauthenticated /admin = %d, want 303", rr.Code)
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil || loc.Host != "accounts.example.com" {
		t.Fatalf("redirect target = %q, want the IdP", rr.Header().Get("Location"))
	}
	// The state must round-trip the admin marker so /callback knows where the
	// login came from.
	state, err := decodeState(loc.Query().Get("state"))
	if err != nil || state.Admin == "" {
		t.Errorf("state %+v does not carry the admin marker", state)
	}
}

func TestAdminCallbackAndPanel(t *testing.T) {
	setupAdminTest(t, nil)
	fmt.Fprintf(logBuffer, "Certificate issued: service=test, principals=[x]\n")

	cookie := adminCookieFor(t, "alice@example.com")

	rr := getAdmin("/admin", cookie)
	if rr.Code != http.StatusOK {
		t.Fatalf("/admin with session = %d, body %s", rr.Code, rr.Body.String())
	}
	page := rr.Body.String()
	for _, want := range []string{"alice@example.com", "Certificate issued: service=test"} {
		if !strings.Contains(page, want) {
			t.Errorf("panel does not show %q", want)
		}
	}
}

func TestAdminCallbackRejectsNonAdmin(t *testing.T) {
	setupAdminTest(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	rr := httptest.NewRecorder()
	handleAdminCallback(rr, req, "bob@example.com") // a valid user, but not an admin
	if rr.Code != http.StatusForbidden {
		t.Fatalf("callback for non-admin = %d, want 403", rr.Code)
	}
	if len(rr.Result().Cookies()) != 0 {
		t.Error("a non-admin was handed a session cookie")
	}
}

func TestAdminRejectsBadCookies(t *testing.T) {
	setupAdminTest(t, nil)

	cases := []struct {
		name   string
		cookie string
	}{
		{"garbage", "not-a-cookie"},
		{"forged signature", mintAdminCookie("alice@example.com", time.Now().Add(time.Hour)) + "x"},
		{"expired", mintAdminCookie("alice@example.com", time.Now().Add(-time.Minute))},
		{"admin-shaped but unlisted", mintAdminCookie("mallory@example.com", time.Now().Add(time.Hour))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if rr := getAdmin("/admin", tc.cookie); rr.Code != http.StatusSeeOther {
				t.Errorf("status = %d, want 303 (back to login)", rr.Code)
			}
		})
	}
}

// Removing an admin from the config must lock them out immediately, even
// though their cookie is still cryptographically valid.
func TestAdminRevokedByReload(t *testing.T) {
	setupAdminTest(t, nil)
	cookie := adminCookieFor(t, "alice@example.com")
	if rr := getAdmin("/admin", cookie); rr.Code != http.StatusOK {
		t.Fatalf("sanity: /admin = %d, want 200", rr.Code)
	}

	demoted := testConfig()
	demoted.Admin = &AdminConfig{Emails: []string{"someone-else@example.com"}}
	configPtr.Store(demoted)

	if rr := getAdmin("/admin", cookie); rr.Code != http.StatusSeeOther {
		t.Errorf("/admin after removal from admin.emails = %d, want 303", rr.Code)
	}
}

func TestAdminLogsFeed(t *testing.T) {
	setupAdminTest(t, nil)
	cookie := adminCookieFor(t, "alice@example.com")

	fmt.Fprintf(logBuffer, "plain line\n")
	fmt.Fprintf(logBuffer, "Certificate issued: user=a\n")
	fmt.Fprintf(logBuffer, "Sign: rejected unknown token from 1.2.3.4\n")

	rr := getAdmin("/admin/logs", cookie)
	if rr.Code != http.StatusOK {
		t.Fatalf("/admin/logs = %d", rr.Code)
	}
	var resp adminLogsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode logs response: %v", err)
	}
	if len(resp.Lines) != 3 {
		t.Fatalf("got %d lines, want 3", len(resp.Lines))
	}
	if resp.Lines[1].Kind != "issued" || resp.Lines[2].Kind != "error" || resp.Lines[0].Kind != "info" {
		t.Errorf("kinds = %s/%s/%s, want info/issued/error",
			resp.Lines[0].Kind, resp.Lines[1].Kind, resp.Lines[2].Kind)
	}

	// Incremental polling: only lines after the given seq.
	rr = getAdmin(fmt.Sprintf("/admin/logs?after=%d", resp.Lines[1].Seq), cookie)
	var tail adminLogsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &tail); err != nil {
		t.Fatalf("decode tail response: %v", err)
	}
	if len(tail.Lines) != 1 || tail.Lines[0].Seq != resp.Lines[2].Seq {
		t.Errorf("after=%d returned %d lines, want just the last", resp.Lines[1].Seq, len(tail.Lines))
	}

	// The feed is JSON-401 (not a redirect) without a session, so the poller
	// can reload the page into the login flow.
	if rr := getAdmin("/admin/logs", ""); rr.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated /admin/logs = %d, want 401", rr.Code)
	}
}

// Behind a TLS-terminating proxy the session cookie must come back Secure —
// the browser's connection is HTTPS even though voussh's side is not. And an
// untrusted peer's X-Forwarded-Proto must never flip the flag.
func TestAdminCookieSecureBehindProxy(t *testing.T) {
	cfg := testConfig()
	cfg.Admin = &AdminConfig{Emails: []string{"alice@example.com"}}
	cfg.TrustedProxies = []string{"192.0.2.1/32"} // httptest's default peer
	if err := cfg.validate(); err != nil {
		t.Fatalf("compile trusted_proxies: %v", err)
	}
	setupAdminTest(t, cfg)

	mint := func(remote, xfProto string) *http.Cookie {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/callback", nil)
		if remote != "" {
			req.RemoteAddr = remote
		}
		if xfProto != "" {
			req.Header.Set("X-Forwarded-Proto", xfProto)
		}
		rr := httptest.NewRecorder()
		handleAdminCallback(rr, req, "alice@example.com")
		for _, c := range rr.Result().Cookies() {
			if c.Name == adminCookieName {
				return c
			}
		}
		t.Fatal("callback did not set a session cookie")
		return nil
	}

	if !mint("", "https").Secure {
		t.Error("cookie not Secure though the trusted proxy reported HTTPS")
	}
	if mint("", "").Secure {
		t.Error("cookie Secure on a plain-HTTP connection with no proxy header")
	}
	if mint("203.0.113.9:1234", "https").Secure {
		t.Error("cookie Secure based on an untrusted peer's header")
	}
}

func TestLoadConfigRejectsEmptyAdminEmails(t *testing.T) {
	path := t.TempDir() + "/config.yaml"
	writeConfigFile(t, path, configFileBase+"admin:\n  emails: []\n")
	if _, err := loadConfig(path); err == nil {
		t.Fatal("loadConfig accepted an admin block with no emails")
	}
}
