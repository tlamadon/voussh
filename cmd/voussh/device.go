package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/voussh/voussh/internal/device"
	"golang.org/x/crypto/ssh"
)

var (
	// deviceStore holds in-flight device authorizations. Always constructed,
	// even when the flow is disabled, so that flipping device_flow.enabled in
	// the config takes effect without a restart.
	deviceStore *device.Store

	// deviceVerifyLimiter blunts brute-force guessing of user codes, and
	// deviceCreateLimiter stops an unauthenticated caller from churning
	// through the pending-request cap. Both are keyed by client IP.
	deviceVerifyLimiter *device.Limiter
	deviceCreateLimiter *device.Limiter
)

// initDeviceFlow builds the device flow's state. Timing knobs are baked in at
// startup; only device_flow.enabled is re-read per request.
func initDeviceFlow(cfg *Config) {
	deviceStore = device.New(device.Options{
		TTL:      cfg.DeviceFlow.codeValidity(),
		Interval: cfg.DeviceFlow.pollInterval(),
		Max:      cfg.DeviceFlow.maxPending(),
	})
	// Ten guesses, then one more every ten seconds. A user needs two or three
	// attempts at worst; an attacker needs billions.
	deviceVerifyLimiter = device.NewLimiter(10, 10*time.Second, nil)
	deviceCreateLimiter = device.NewLimiter(20, 5*time.Second, nil)
}

// deviceFlowEnabled reports whether the flow is currently switched on.
func deviceFlowEnabled() bool {
	return currentConfig().DeviceFlow.enabled()
}

// deviceBaseURL is the externally reachable origin used to build verification
// links. It falls back to the origin of redirect_url, which by definition has
// to be reachable by the user's browser already.
func deviceBaseURL(cfg *Config) string {
	if cfg.BaseURL != "" {
		return strings.TrimRight(cfg.BaseURL, "/")
	}
	u, err := url.Parse(cfg.RedirectURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// clientIP identifies the caller for rate-limiting purposes. It deliberately
// ignores X-Forwarded-For: voussh does not know whether it sits behind a proxy
// it can trust, and honouring the header unconditionally would let any caller
// spoof their way past the limiter.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// parseUserPublicKey decodes and validates an authorized_keys line submitted
// by a client. It rejects certificates: they satisfy ssh.PublicKey, so without
// this check a caller could hand us a certificate to sign as though it were a
// bare key.
func parseUserPublicKey(raw []byte) (ssh.PublicKey, string, error) {
	pubKey, comment, _, _, err := ssh.ParseAuthorizedKey(raw)
	if err != nil {
		return nil, "", fmt.Errorf("invalid public key: %w", err)
	}
	if _, isCert := pubKey.(*ssh.Certificate); isCert {
		return nil, "", errors.New("expected a public key, got a certificate")
	}
	return pubKey, comment, nil
}

// ---------------------------------------------------------------------------
// POST /device/code — the CLI asks for a pair of codes.
// ---------------------------------------------------------------------------

type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

func handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	if !deviceFlowEnabled() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !deviceCreateLimiter.Allow(clientIP(r)) {
		writeDeviceError(w, http.StatusTooManyRequests, "slow_down", "too many requests")
		return
	}

	if err := r.ParseForm(); err != nil {
		writeDeviceError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	pubKeyB64 := r.PostForm.Get("pubkey")
	if pubKeyB64 == "" {
		writeDeviceError(w, http.StatusBadRequest, "invalid_request", "missing pubkey")
		return
	}
	pubKeyRaw, err := base64.RawURLEncoding.DecodeString(pubKeyB64)
	if err != nil {
		writeDeviceError(w, http.StatusBadRequest, "invalid_request", "pubkey is not valid base64url")
		return
	}
	pubKey, comment, err := parseUserPublicKey(pubKeyRaw)
	if err != nil {
		writeDeviceError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	base := deviceBaseURL(currentConfig())
	if base == "" {
		log.Printf("Device flow: cannot derive a verification URL; set base_url in the config")
		writeDeviceError(w, http.StatusInternalServerError, "server_error", "device flow is misconfigured")
		return
	}

	req, err := deviceStore.Create(pubKeyRaw, ssh.FingerprintSHA256(pubKey), r.PostForm.Get("role"))
	if err != nil {
		if errors.Is(err, device.ErrFull) {
			writeDeviceError(w, http.StatusServiceUnavailable, "slow_down", "too many pending requests")
			return
		}
		log.Printf("Device flow: failed to create request: %v", err)
		writeDeviceError(w, http.StatusInternalServerError, "server_error", "could not create request")
		return
	}

	log.Printf("Device flow: request %s created (key=%s comment=%q role=%q)",
		req.UserCode, req.Fingerprint, comment, req.Role)

	// Both fields are whole seconds on the wire. Round the interval up and
	// floor it at one second, so a sub-second configured interval cannot be
	// advertised as 0 and invite a client to poll flat out.
	interval := int(math.Ceil(deviceStore.Interval().Seconds()))
	if interval < 1 {
		interval = 1
	}

	verificationURI := base + "/device"
	writeJSON(w, http.StatusOK, deviceCodeResponse{
		DeviceCode:              req.DeviceCode,
		UserCode:                req.UserCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: verificationURI + "?user_code=" + url.QueryEscape(req.UserCode),
		ExpiresIn:               int(math.Round(time.Until(req.ExpiresAt).Seconds())),
		Interval:                interval,
	})
}

// ---------------------------------------------------------------------------
// GET/POST /device — the human enters the user code.
// ---------------------------------------------------------------------------

func handleDeviceVerify(w http.ResponseWriter, r *http.Request) {
	if !deviceFlowEnabled() {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// The code is only prefilled, never looked up, so this page reveals
		// nothing about which codes exist.
		renderDevicePrompt(w, http.StatusOK, r.URL.Query().Get("user_code"), "")

	case http.MethodPost:
		if !deviceVerifyLimiter.Allow(clientIP(r)) {
			renderDevicePrompt(w, http.StatusTooManyRequests, "",
				"Too many attempts. Wait a moment and try again.")
			return
		}
		if err := r.ParseForm(); err != nil {
			renderDevicePrompt(w, http.StatusBadRequest, "", "Malformed request.")
			return
		}

		entered := r.PostForm.Get("user_code")
		normalised := device.NormalizeUserCode(entered)
		if normalised == "" {
			renderDevicePrompt(w, http.StatusBadRequest, entered,
				"That does not look like a valid code.")
			return
		}
		if _, err := deviceStore.Lookup(normalised); err != nil {
			// One message for every failure mode, so the page cannot be used
			// to enumerate which codes are live.
			renderDevicePrompt(w, http.StatusNotFound, entered,
				"That code is not valid, has expired, or has already been used.")
			return
		}

		// Hand off to the ordinary web login; /callback picks the request back
		// up by user code. The device code never enters the browser.
		state, err := encodeState(StateData{Device: normalised})
		if err != nil {
			renderDevicePrompt(w, http.StatusInternalServerError, "", "Could not start login.")
			return
		}
		http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusSeeOther)

	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleDeviceCallback continues /callback when the login was started from the
// device page. The caller has already verified the ID token.
func handleDeviceCallback(w http.ResponseWriter, userCode, email string) {
	req, err := deviceStore.Lookup(userCode)
	if err != nil {
		renderDeviceResult(w, http.StatusNotFound, "Request unavailable",
			"That code is not valid, has expired, or has already been used.", false)
		return
	}

	role, principals, err := resolvePrincipals(email, req.Role)
	if err != nil {
		renderDeviceResult(w, http.StatusForbidden, "Not authorized", err.Error(), false)
		return
	}

	req, err = deviceStore.Authenticate(userCode, email, role, principals)
	if err != nil {
		renderDeviceResult(w, http.StatusConflict, "Request unavailable",
			"That request is no longer awaiting approval.", false)
		return
	}

	renderDeviceApproval(w, req)
}

// ---------------------------------------------------------------------------
// POST /device/approve — the human confirms or rejects.
// ---------------------------------------------------------------------------

func handleDeviceApprove(w http.ResponseWriter, r *http.Request) {
	if !deviceFlowEnabled() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		renderDeviceResult(w, http.StatusBadRequest, "Error", "Malformed request.", false)
		return
	}

	userCode := device.NormalizeUserCode(r.PostForm.Get("user_code"))
	token := r.PostForm.Get("approval_token")

	// Validate the token before doing any work, so a bad token cannot make the
	// server sign anything.
	req, err := deviceStore.Prepare(userCode, token)
	if err != nil {
		renderDeviceResult(w, http.StatusForbidden, "Request unavailable",
			"That request is no longer awaiting approval.", false)
		return
	}

	if r.PostForm.Get("action") != "approve" {
		if _, err := deviceStore.Deny(userCode, token); err != nil {
			renderDeviceResult(w, http.StatusConflict, "Request unavailable",
				"That request is no longer awaiting approval.", false)
			return
		}
		log.Printf("Device flow: request %s denied by %s", userCode, req.Email)
		renderDeviceResult(w, http.StatusOK, "Request denied",
			"No certificate was issued. You can close this window.", false)
		return
	}

	pubKey, _, err := parseUserPublicKey(req.PubKey)
	if err != nil {
		renderDeviceResult(w, http.StatusBadRequest, "Error", "The requested key is not usable.", false)
		return
	}

	cert, err := signCertificate(pubKey, req.Email, req.Role, req.Principals)
	if err != nil {
		log.Printf("Device flow: failed to sign certificate for %s: %v", req.Email, err)
		renderDeviceResult(w, http.StatusInternalServerError, "Error",
			"Failed to issue the certificate.", false)
		return
	}

	if _, err := deviceStore.Approve(userCode, token, ssh.MarshalAuthorizedKey(cert)); err != nil {
		renderDeviceResult(w, http.StatusConflict, "Request unavailable",
			"That request is no longer awaiting approval.", false)
		return
	}

	logCertificateIssued(cert, req.Email, req.Role, req.Principals, "device")
	renderDeviceResult(w, http.StatusOK, "Device approved",
		"The certificate has been sent to your terminal. You can close this window.", true)
}

// ---------------------------------------------------------------------------
// POST /device/token — the CLI polls for its certificate.
// ---------------------------------------------------------------------------

type deviceTokenResponse struct {
	Certificate string   `json:"certificate"`
	Email       string   `json:"email"`
	Role        string   `json:"role"`
	Principals  []string `json:"principals"`
}

func handleDeviceToken(w http.ResponseWriter, r *http.Request) {
	if !deviceFlowEnabled() {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		writeDeviceError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}

	deviceCode := r.PostForm.Get("device_code")
	if deviceCode == "" {
		writeDeviceError(w, http.StatusBadRequest, "invalid_request", "missing device_code")
		return
	}

	// The device code carries 256 bits of entropy, so unlike the user code it
	// needs no guessing limiter; slow_down covers abuse of a code the caller
	// legitimately holds.
	req, err := deviceStore.Poll(deviceCode)
	if err != nil {
		// RFC 8628 §3.5 returns these as ordinary OAuth error responses.
		writeDeviceError(w, http.StatusBadRequest, err.Error(), "")
		return
	}

	writeJSON(w, http.StatusOK, deviceTokenResponse{
		Certificate: strings.TrimSpace(string(req.Cert)),
		Email:       req.Email,
		Role:        req.Role,
		Principals:  req.Principals,
	})
}

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("Device flow: failed to write response: %v", err)
	}
}

func writeDeviceError(w http.ResponseWriter, status int, code, description string) {
	body := map[string]string{"error": code}
	if description != "" {
		body["error_description"] = description
	}
	writeJSON(w, status, body)
}

// ---------------------------------------------------------------------------
// Pages. html/template escapes everything, which matters because the key
// comment and role are supplied by whoever started the request.
// ---------------------------------------------------------------------------

const devicePageLayout = `<!DOCTYPE html>
<html>
<head><title>{{.Title}} — VouSSH</title><meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="font-family: system-ui, sans-serif; max-width: 560px; margin: 50px auto; padding: 20px; line-height: 1.5;">
{{template "body" .}}
</body>
</html>`

var devicePromptTmpl = template.Must(template.New("layout").Parse(devicePageLayout))
var deviceApprovalTmpl = template.Must(template.New("layout").Parse(devicePageLayout))
var deviceResultTmpl = template.Must(template.New("layout").Parse(devicePageLayout))

func init() {
	template.Must(devicePromptTmpl.New("body").Parse(`
<h2>Authorize a device</h2>
<p>Enter the code shown in your terminal.</p>
{{if .Error}}<p style="color: #c00;">{{.Error}}</p>{{end}}
<form method="POST" action="/device">
<input name="user_code" value="{{.UserCode}}" placeholder="XXXX-XXXX" autofocus autocapitalize="characters"
 autocomplete="off" spellcheck="false"
 style="font-family: monospace; font-size: 24px; padding: 10px; width: 100%; box-sizing: border-box;">
<button type="submit" style="margin-top: 15px; padding: 10px 20px; font-size: 16px;">Continue</button>
</form>`))

	template.Must(deviceApprovalTmpl.New("body").Parse(`
<h2>Approve this device?</h2>
<p>Signed in as <strong>{{.Email}}</strong>.</p>
<table style="border-collapse: collapse; margin: 20px 0; width: 100%;">
<tr><td style="padding: 6px 12px 6px 0; color: #666;">Role</td><td><strong>{{.Role}}</strong></td></tr>
<tr><td style="padding: 6px 12px 6px 0; color: #666;">Principals</td><td>{{.Principals}}</td></tr>
<tr><td style="padding: 6px 12px 6px 0; color: #666;">SSH key</td>
    <td style="font-family: monospace; font-size: 13px; word-break: break-all;">{{.Fingerprint}}</td></tr>
{{if .Comment}}<tr><td style="padding: 6px 12px 6px 0; color: #666;">Key comment</td>
    <td style="font-family: monospace; font-size: 13px;">{{.Comment}}</td></tr>{{end}}
<tr><td style="padding: 6px 12px 6px 0; color: #666;">Code</td>
    <td style="font-family: monospace;">{{.UserCode}}</td></tr>
</table>
<p style="background: #fff8e1; border-left: 3px solid #f0ad4e; padding: 12px; font-size: 14px;">
Approving issues a certificate for your principals to the machine holding that SSH key.
If you did not start this login, or the fingerprint does not match the machine you are
sitting at, choose Reject.</p>
<form method="POST" action="/device/approve">
<input type="hidden" name="user_code" value="{{.UserCode}}">
<input type="hidden" name="approval_token" value="{{.ApprovalToken}}">
<button type="submit" name="action" value="approve"
 style="padding: 10px 20px; font-size: 16px; margin-right: 10px;">Approve</button>
<button type="submit" name="action" value="deny"
 style="padding: 10px 20px; font-size: 16px;">Reject</button>
</form>`))

	template.Must(deviceResultTmpl.New("body").Parse(`
<h2 style="color: {{if .OK}}#0a0{{else}}#c00{{end}};">{{.Title}}</h2>
<p>{{.Message}}</p>`))
}

type devicePromptData struct {
	Title    string
	UserCode string
	Error    string
}

func renderDevicePrompt(w http.ResponseWriter, status int, userCode, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	data := devicePromptData{Title: "Authorize a device", UserCode: userCode, Error: errMsg}
	if err := devicePromptTmpl.Execute(w, data); err != nil {
		log.Printf("Device flow: failed to render prompt: %v", err)
	}
}

type deviceApprovalData struct {
	Title         string
	Email         string
	Role          string
	Principals    string
	Fingerprint   string
	Comment       string
	UserCode      string
	ApprovalToken string
}

func renderDeviceApproval(w http.ResponseWriter, req device.Request) {
	_, comment, err := parseUserPublicKey(req.PubKey)
	if err != nil {
		renderDeviceResult(w, http.StatusBadRequest, "Error", "The requested key is not usable.", false)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	data := deviceApprovalData{
		Title:         "Approve this device",
		Email:         req.Email,
		Role:          req.Role,
		Principals:    strings.Join(req.Principals, ", "),
		Fingerprint:   req.Fingerprint,
		Comment:       comment,
		UserCode:      req.UserCode,
		ApprovalToken: req.ApprovalToken,
	}
	if err := deviceApprovalTmpl.Execute(w, data); err != nil {
		log.Printf("Device flow: failed to render approval page: %v", err)
	}
}

type deviceResultData struct {
	Title   string
	Message string
	OK      bool
}

func renderDeviceResult(w http.ResponseWriter, status int, title, message string, ok bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := deviceResultTmpl.Execute(w, deviceResultData{Title: title, Message: message, OK: ok}); err != nil {
		log.Printf("Device flow: failed to render result page: %v", err)
	}
}

// logCertificateIssued records an issuance in a single consistent format,
// shared by the browser and device flows.
func logCertificateIssued(cert *ssh.Certificate, email, role string, principals []string, via string) {
	validUntil := time.Unix(int64(cert.ValidBefore), 0)
	exts := make([]string, 0, len(cert.Permissions.Extensions))
	for name := range cert.Permissions.Extensions {
		exts = append(exts, name)
	}
	sort.Strings(exts)
	log.Printf("Certificate issued: user=%s, role=%s, principals=[%s], validity=%s (until %s), extensions=[%s], via=%s",
		email, role, strings.Join(principals, ", "),
		time.Until(validUntil).Round(time.Second), validUntil.Format(time.RFC3339),
		strings.Join(exts, ", "), via)
}
