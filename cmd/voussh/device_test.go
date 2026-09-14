package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
)

func testConfig() *Config {
	return &Config{
		CertValidity: "1h",
		RedirectURL:  "https://ca.example.com/callback",
		Users: map[string]map[string][]string{
			"alice@example.com": {
				"default": {"root", "admin"},
				"deploy":  {"deploy"},
			},
		},
		// A tiny interval keeps the slow_down guard from stalling the tests.
		DeviceFlow: &DeviceFlowConfig{PollInterval: "1ms"},
	}
}

// setupDeviceTest installs a fresh config, CA key and device store. Handlers
// read these through package globals, so every test starts from a clean slate.
func setupDeviceTest(t *testing.T, cfg *Config) {
	t.Helper()
	if cfg == nil {
		cfg = testConfig()
	}
	configPtr.Store(cfg)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("build CA signer: %v", err)
	}
	caSigner = signer

	// /device redirects into the IdP, so the handlers need a usable OAuth
	// config even though these tests never complete a real exchange.
	oauth2Config = &oauth2.Config{
		ClientID:    "test-client",
		RedirectURL: cfg.RedirectURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.example.com/o/oauth2/auth",
			TokenURL: "https://accounts.example.com/token",
		},
		Scopes: []string{"openid", "email"},
	}

	initDeviceFlow(cfg)
}

// testPubKey returns an authorized_keys line with the given trailing comment.
func testPubKey(t *testing.T, comment string) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap key: %v", err)
	}
	line := bytes.TrimSpace(ssh.MarshalAuthorizedKey(sshPub))
	if comment != "" {
		line = append(line, ' ')
		line = append(line, comment...)
	}
	return append(line, '\n')
}

func postForm(handler http.HandlerFunc, path string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

// startDeviceRequest runs the /device/code step and returns the parsed body.
func startDeviceRequest(t *testing.T, pubKey []byte, role string) deviceCodeResponse {
	t.Helper()
	form := url.Values{"pubkey": {base64.RawURLEncoding.EncodeToString(pubKey)}}
	if role != "" {
		form.Set("role", role)
	}
	rr := postForm(handleDeviceCode, "/device/code", form)
	if rr.Code != http.StatusOK {
		t.Fatalf("/device/code = %d, body %s", rr.Code, rr.Body.String())
	}
	var resp deviceCodeResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode /device/code response: %v", err)
	}
	return resp
}

var approvalTokenRE = regexp.MustCompile(`name="approval_token" value="([^"]+)"`)

// approvalTokenFrom pulls the hidden approval token out of a rendered page.
func approvalTokenFrom(t *testing.T, body string) string {
	t.Helper()
	m := approvalTokenRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no approval token in page: %s", body)
	}
	return m[1]
}

func pollToken(t *testing.T, deviceCode string) *httptest.ResponseRecorder {
	t.Helper()
	return postForm(handleDeviceToken, "/device/token", url.Values{"device_code": {deviceCode}})
}

func deviceErrorCode(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body %q: %v", rr.Body.String(), err)
	}
	return body.Error
}

func TestDeviceCodeIssuesCodes(t *testing.T) {
	setupDeviceTest(t, nil)

	resp := startDeviceRequest(t, testPubKey(t, "tester@laptop"), "")

	if resp.DeviceCode == "" || resp.UserCode == "" {
		t.Fatal("response is missing codes")
	}
	if resp.VerificationURI != "https://ca.example.com/device" {
		t.Errorf("verification_uri = %q, want it derived from redirect_url", resp.VerificationURI)
	}
	if !strings.Contains(resp.VerificationURIComplete, url.QueryEscape(resp.UserCode)) {
		t.Errorf("verification_uri_complete %q does not carry the user code", resp.VerificationURIComplete)
	}
	if resp.ExpiresIn <= 0 || resp.Interval <= 0 {
		t.Errorf("expires_in=%d interval=%d, want both positive", resp.ExpiresIn, resp.Interval)
	}
	// The device code must never be derivable from the user code.
	if strings.Contains(resp.DeviceCode, resp.UserCode) {
		t.Error("device code embeds the user code")
	}
}

func TestDeviceCodeRejectsBadKeys(t *testing.T) {
	setupDeviceTest(t, nil)

	t.Run("not base64", func(t *testing.T) {
		rr := postForm(handleDeviceCode, "/device/code", url.Values{"pubkey": {"!!!not base64!!!"}})
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("not a key", func(t *testing.T) {
		form := url.Values{"pubkey": {base64.RawURLEncoding.EncodeToString([]byte("hello"))}}
		rr := postForm(handleDeviceCode, "/device/code", form)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("missing", func(t *testing.T) {
		rr := postForm(handleDeviceCode, "/device/code", url.Values{})
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})

	// A certificate satisfies ssh.PublicKey, so it would otherwise be accepted
	// and re-signed as though it were a bare key.
	t.Run("certificate", func(t *testing.T) {
		pubKey, _, err := parseUserPublicKey(testPubKey(t, ""))
		if err != nil {
			t.Fatalf("parse key: %v", err)
		}
		cert, err := signCertificate(pubKey, "alice@example.com", "default", []string{"root"})
		if err != nil {
			t.Fatalf("sign cert: %v", err)
		}
		form := url.Values{"pubkey": {base64.RawURLEncoding.EncodeToString(ssh.MarshalAuthorizedKey(cert))}}
		rr := postForm(handleDeviceCode, "/device/code", form)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 (certificates must be rejected)", rr.Code)
		}
	})
}

func TestDeviceFlowEndToEnd(t *testing.T) {
	setupDeviceTest(t, nil)

	pubKey := testPubKey(t, "tester@laptop")
	resp := startDeviceRequest(t, pubKey, "deploy")

	// Nothing has been approved yet.
	if got := deviceErrorCode(t, pollToken(t, resp.DeviceCode)); got != "authorization_pending" {
		t.Fatalf("first poll error = %q, want authorization_pending", got)
	}

	// The browser completes the IdP login; /callback hands off to here.
	rr := httptest.NewRecorder()
	handleDeviceCallback(rr, resp.UserCode, "alice@example.com")
	if rr.Code != http.StatusOK {
		t.Fatalf("callback status = %d, body %s", rr.Code, rr.Body.String())
	}
	page := rr.Body.String()
	for _, want := range []string{"alice@example.com", "deploy", "SHA256:", resp.UserCode} {
		if !strings.Contains(page, want) {
			t.Errorf("approval page does not mention %q", want)
		}
	}

	// The user confirms.
	token := approvalTokenFrom(t, page)
	rr = postForm(handleDeviceApprove, "/device/approve", url.Values{
		"user_code":      {resp.UserCode},
		"approval_token": {token},
		"action":         {"approve"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("approve status = %d, body %s", rr.Code, rr.Body.String())
	}

	time.Sleep(2 * time.Millisecond) // clear the poll interval
	rr = pollToken(t, resp.DeviceCode)
	if rr.Code != http.StatusOK {
		t.Fatalf("poll after approval = %d, body %s", rr.Code, rr.Body.String())
	}
	var tok deviceTokenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &tok); err != nil {
		t.Fatalf("decode token response: %v", err)
	}

	if tok.Email != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com", tok.Email)
	}
	if tok.Role != "deploy" {
		t.Errorf("role = %q, want deploy", tok.Role)
	}

	// The certificate must be real: signed by our CA, bound to the submitted
	// key, and carrying exactly the principals the role grants.
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(tok.Certificate))
	if err != nil {
		t.Fatalf("issued certificate does not parse: %v", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatal("issued material is not a certificate")
	}
	if got := strings.Join(cert.ValidPrincipals, ","); got != "deploy" {
		t.Errorf("principals = %q, want deploy", got)
	}
	if cert.KeyId != "alice@example.com@deploy" {
		t.Errorf("key id = %q", cert.KeyId)
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), caSigner.PublicKey().Marshal()) {
		t.Error("certificate was not signed by the configured CA")
	}
	submitted, _, err := parseUserPublicKey(pubKey)
	if err != nil {
		t.Fatalf("parse submitted key: %v", err)
	}
	if !bytes.Equal(cert.Key.Marshal(), submitted.Marshal()) {
		t.Error("certificate was issued against a different key than was submitted")
	}

	// Collected exactly once.
	time.Sleep(2 * time.Millisecond)
	if got := deviceErrorCode(t, pollToken(t, resp.DeviceCode)); got != "invalid_grant" {
		t.Errorf("replayed poll error = %q, want invalid_grant", got)
	}
}

func TestDeviceApproveRejectsBadToken(t *testing.T) {
	setupDeviceTest(t, nil)

	resp := startDeviceRequest(t, testPubKey(t, ""), "")
	rr := httptest.NewRecorder()
	handleDeviceCallback(rr, resp.UserCode, "alice@example.com")
	if rr.Code != http.StatusOK {
		t.Fatalf("callback status = %d", rr.Code)
	}

	rr = postForm(handleDeviceApprove, "/device/approve", url.Values{
		"user_code":      {resp.UserCode},
		"approval_token": {"forged"},
		"action":         {"approve"},
	})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("approve with forged token = %d, want 403", rr.Code)
	}

	// The request must survive the failed attempt rather than being consumed.
	time.Sleep(2 * time.Millisecond)
	if got := deviceErrorCode(t, pollToken(t, resp.DeviceCode)); got != "authorization_pending" {
		t.Errorf("poll after forged approval = %q, want authorization_pending", got)
	}
}

func TestDeviceDeny(t *testing.T) {
	setupDeviceTest(t, nil)

	resp := startDeviceRequest(t, testPubKey(t, ""), "")
	rr := httptest.NewRecorder()
	handleDeviceCallback(rr, resp.UserCode, "alice@example.com")
	token := approvalTokenFrom(t, rr.Body.String())

	rr = postForm(handleDeviceApprove, "/device/approve", url.Values{
		"user_code":      {resp.UserCode},
		"approval_token": {token},
		"action":         {"deny"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("deny status = %d", rr.Code)
	}

	time.Sleep(2 * time.Millisecond)
	if got := deviceErrorCode(t, pollToken(t, resp.DeviceCode)); got != "access_denied" {
		t.Errorf("poll after deny = %q, want access_denied", got)
	}
}

func TestDeviceCallbackRejectsUnauthorizedUser(t *testing.T) {
	setupDeviceTest(t, nil)

	resp := startDeviceRequest(t, testPubKey(t, ""), "")

	rr := httptest.NewRecorder()
	handleDeviceCallback(rr, resp.UserCode, "mallory@example.com")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("callback for unlisted user = %d, want 403", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "approval_token") {
		t.Error("an unauthorized user was handed an approval token")
	}
}

func TestDeviceCallbackRejectsUnavailableRole(t *testing.T) {
	setupDeviceTest(t, nil)

	resp := startDeviceRequest(t, testPubKey(t, ""), "nonexistent")

	rr := httptest.NewRecorder()
	handleDeviceCallback(rr, resp.UserCode, "alice@example.com")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("callback with unavailable role = %d, want 403", rr.Code)
	}
}

func TestDeviceVerifyHidesWhichCodesExist(t *testing.T) {
	setupDeviceTest(t, nil)

	live := startDeviceRequest(t, testPubKey(t, ""), "")

	// A well-formed but unknown code and a live-but-mistyped one must produce
	// the same message, so the page cannot be used to enumerate codes.
	unknown := postForm(handleDeviceVerify, "/device", url.Values{"user_code": {"WDJB-MJHT"}})
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown code status = %d, want 404", unknown.Code)
	}
	if !strings.Contains(unknown.Body.String(), "not valid, has expired, or has already been used") {
		t.Error("unknown code did not produce the generic message")
	}

	// A real code redirects into the IdP login.
	ok := postForm(handleDeviceVerify, "/device", url.Values{"user_code": {live.UserCode}})
	if ok.Code != http.StatusSeeOther {
		t.Fatalf("valid code status = %d, want 303", ok.Code)
	}
	// The device code is the CLI's secret and must never reach the browser.
	if strings.Contains(ok.Header().Get("Location"), live.DeviceCode) {
		t.Error("redirect leaks the device code into the browser")
	}
}

func TestDeviceVerifyRateLimited(t *testing.T) {
	setupDeviceTest(t, nil)

	// The limiter allows 10 guesses per caller before it starts refusing.
	var limited bool
	for i := 0; i < 25; i++ {
		rr := postForm(handleDeviceVerify, "/device", url.Values{"user_code": {"WDJB-MJHT"}})
		if rr.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("user code guessing was never rate limited")
	}
}

// Behind a trusted proxy the limiter must key on the forwarded client, not
// the proxy: one noisy caller exhausting everyone's budget is the bug that
// trusted_proxies exists to fix.
func TestDeviceVerifyLimiterBucketsForwardedClients(t *testing.T) {
	cfg := testConfig()
	cfg.TrustedProxies = []string{"192.0.2.1/32"} // httptest's default peer
	if err := cfg.validate(); err != nil {
		t.Fatalf("compile trusted_proxies: %v", err)
	}
	setupDeviceTest(t, cfg)

	post := func(client string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/device",
			strings.NewReader(url.Values{"user_code": {"WDJB-MJHT"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Forwarded-For", client)
		rr := httptest.NewRecorder()
		handleDeviceVerify(rr, req)
		return rr
	}

	var limited bool
	for i := 0; i < 25; i++ {
		if post("10.0.0.1").Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("first forwarded client was never rate limited")
	}

	if code := post("10.0.0.2").Code; code == http.StatusTooManyRequests {
		t.Fatal("second forwarded client shares the first client's bucket")
	}
}

func TestApprovalPageEscapesKeyComment(t *testing.T) {
	setupDeviceTest(t, nil)

	// The key comment is chosen by whoever started the request, so it reaches
	// the approval page as untrusted text.
	resp := startDeviceRequest(t, testPubKey(t, "<script>alert(1)</script>"), "")

	rr := httptest.NewRecorder()
	handleDeviceCallback(rr, resp.UserCode, "alice@example.com")
	body := rr.Body.String()

	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("key comment was rendered unescaped")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("key comment does not appear escaped in page: %s", body)
	}
}

func TestDeviceTokenUnknownCode(t *testing.T) {
	setupDeviceTest(t, nil)

	rr := pollToken(t, "not-a-real-device-code")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	if got := deviceErrorCode(t, rr); got != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", got)
	}
}

func TestDeviceTokenSlowDown(t *testing.T) {
	setupDeviceTest(t, nil)

	resp := startDeviceRequest(t, testPubKey(t, ""), "")
	if got := deviceErrorCode(t, pollToken(t, resp.DeviceCode)); got != "authorization_pending" {
		t.Fatalf("first poll = %q", got)
	}
	// Immediately again, inside the 1ms interval.
	if got := deviceErrorCode(t, pollToken(t, resp.DeviceCode)); got != "slow_down" {
		t.Errorf("immediate second poll = %q, want slow_down", got)
	}
}

func TestDeviceFlowDisabled(t *testing.T) {
	cfg := testConfig()
	disabled := false
	cfg.DeviceFlow.Enabled = &disabled
	setupDeviceTest(t, cfg)

	cases := []struct {
		name    string
		handler http.HandlerFunc
		path    string
	}{
		{"code", handleDeviceCode, "/device/code"},
		{"verify", handleDeviceVerify, "/device"},
		{"approve", handleDeviceApprove, "/device/approve"},
		{"token", handleDeviceToken, "/device/token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if rr := postForm(tc.handler, tc.path, url.Values{}); rr.Code != http.StatusNotFound {
				t.Errorf("status = %d, want 404 when the flow is disabled", rr.Code)
			}
		})
	}
}

func TestDeviceBaseURL(t *testing.T) {
	cases := []struct {
		name string
		cfg  *Config
		want string
	}{
		{"explicit base_url wins", &Config{BaseURL: "https://ca.example.com", RedirectURL: "http://other/callback"}, "https://ca.example.com"},
		{"trailing slash trimmed", &Config{BaseURL: "https://ca.example.com/"}, "https://ca.example.com"},
		{"derived from redirect_url", &Config{RedirectURL: "https://ca.example.com:8443/callback"}, "https://ca.example.com:8443"},
		{"unset", &Config{}, ""},
		{"unparseable", &Config{RedirectURL: "not a url"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := deviceBaseURL(tc.cfg); got != tc.want {
				t.Errorf("deviceBaseURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolvePrincipals(t *testing.T) {
	configPtr.Store(testConfig())

	t.Run("default role", func(t *testing.T) {
		role, principals, err := resolvePrincipals("alice@example.com", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if role != "default" {
			t.Errorf("role = %q, want default", role)
		}
		if strings.Join(principals, ",") != "root,admin" {
			t.Errorf("principals = %v", principals)
		}
	})

	t.Run("named role", func(t *testing.T) {
		role, principals, err := resolvePrincipals("alice@example.com", "deploy")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if role != "deploy" || strings.Join(principals, ",") != "deploy" {
			t.Errorf("role=%q principals=%v", role, principals)
		}
	})

	t.Run("unknown user", func(t *testing.T) {
		if _, _, err := resolvePrincipals("mallory@example.com", ""); err == nil {
			t.Fatal("expected an error for an unlisted user")
		}
	})

	t.Run("unavailable role", func(t *testing.T) {
		_, _, err := resolvePrincipals("alice@example.com", "root")
		if err == nil {
			t.Fatal("expected an error for an unavailable role")
		}
		// The message should help the user pick a valid role.
		if !strings.Contains(err.Error(), "deploy") {
			t.Errorf("error %q does not list available roles", err)
		}
	})
}
