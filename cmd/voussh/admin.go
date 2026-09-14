package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/voussh/voussh/internal/logbuf"
	"github.com/voussh/voussh/internal/version"
)

// AdminConfig switches on the read-only web admin panel at /admin, which
// shows the server's recent log lines. Access requires completing the
// ordinary Google login as one of the listed emails.
type AdminConfig struct {
	Emails   []string `yaml:"emails"`              // who may view the panel
	LogLines int      `yaml:"log_lines,omitempty"` // ring buffer capacity; default 1000; read at startup
}

func (a *AdminConfig) enabled() bool { return a != nil && len(a.Emails) > 0 }

func (a *AdminConfig) logLines() int {
	if a == nil || a.LogLines <= 0 {
		return 1000
	}
	return a.LogLines
}

// adminEnabled reports whether the panel is currently switched on. The email
// list is read per request, so it hot-reloads.
func adminEnabled() bool { return currentConfig().Admin.enabled() }

func isAdminEmail(email string) bool {
	cfg := currentConfig()
	if cfg.Admin == nil {
		return false
	}
	for _, e := range cfg.Admin.Emails {
		if strings.EqualFold(e, email) {
			return true
		}
	}
	return false
}

var (
	// logBuffer captures every line the standard logger writes; the panel
	// reads it. Always constructed (main tees the logger into it at startup)
	// so enabling `admin:` via config reload works without a restart.
	logBuffer *logbuf.Buffer

	// adminCookieKey signs session cookies. Generated per process, so a
	// restart invalidates every session — consistent with keeping the server
	// stateless.
	adminCookieKey []byte

	serverStart time.Time
)

const (
	adminCookieName = "voussh_admin"
	adminSessionTTL = 12 * time.Hour
)

// initAdmin builds the admin panel's state. The ring capacity is baked in at
// startup; only admin.emails is re-read per request.
func initAdmin(cfg *Config) {
	logBuffer = logbuf.New(cfg.Admin.logLines())
	adminCookieKey = make([]byte, 32)
	if _, err := rand.Read(adminCookieKey); err != nil {
		log.Fatal("Failed to generate admin cookie key:", err)
	}
	serverStart = time.Now()
}

// ---------------------------------------------------------------------------
// Session cookie: base64(email|expiresUnix) + "." + HMAC. Carrying the whole
// session in the cookie keeps the server stateless.
// ---------------------------------------------------------------------------

func adminCookieMAC(payload string) string {
	mac := hmac.New(sha256.New, adminCookieKey)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func mintAdminCookie(email string, expires time.Time) string {
	payload := base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, "%s|%d", email, expires.Unix()))
	return payload + "." + adminCookieMAC(payload)
}

// parseAdminCookie verifies the signature and expiry and returns the email.
func parseAdminCookie(value string) (string, bool) {
	payload, sig, ok := strings.Cut(value, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(adminCookieMAC(payload))) {
		return "", false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", false
	}
	email, expStr, ok := strings.Cut(string(decoded), "|")
	if !ok {
		return "", false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	return email, true
}

// adminSession returns the authenticated admin email for the request, if any.
// The email must still be in admin.emails at request time, so removing an
// admin from the config locks them out immediately, live cookie or not.
func adminSession(r *http.Request) (string, bool) {
	c, err := r.Cookie(adminCookieName)
	if err != nil {
		return "", false
	}
	email, ok := parseAdminCookie(c.Value)
	if !ok || !isAdminEmail(email) {
		return "", false
	}
	return email, true
}

// handleAdminCallback continues /callback when the login was started from the
// admin panel. The caller has already verified the ID token.
func handleAdminCallback(w http.ResponseWriter, r *http.Request, email string) {
	if !adminEnabled() {
		http.NotFound(w, r)
		return
	}
	if !isAdminEmail(email) {
		log.Printf("Admin: rejected login by %s from %s (not in admin.emails)", email, clientIP(r))
		http.Error(w, "Not authorized for the admin panel", http.StatusForbidden)
		return
	}

	cfg := currentConfig()
	expires := time.Now().Add(adminSessionTTL)
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    mintAdminCookie(email, expires),
		Path:     "/admin",
		Expires:  expires,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   cfg.TLS != nil && cfg.TLS.CertFile != "" && cfg.TLS.KeyFile != "",
	})
	log.Printf("Admin: login by %s from %s", email, clientIP(r))
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// GET /admin — the panel page. Recent lines are rendered server-side; a small
// script then polls /admin/logs for anything newer.
// ---------------------------------------------------------------------------

func handleAdmin(w http.ResponseWriter, r *http.Request) {
	if !adminEnabled() {
		http.NotFound(w, r)
		return
	}
	email, ok := adminSession(r)
	if !ok {
		state, err := encodeState(StateData{Admin: "1"})
		if err != nil {
			http.Error(w, "Failed to encode state", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, oauth2Config.AuthCodeURL(state), http.StatusSeeOther)
		return
	}

	cfg := currentConfig()
	data := adminPageData{
		Email:      email,
		Version:    version.String(),
		Uptime:     time.Since(serverStart).Round(time.Second).String(),
		Users:      len(cfg.Users),
		Roles:      len(cfg.Roles),
		Services:   len(cfg.Services),
		DeviceFlow: map[bool]string{true: "on", false: "off"}[cfg.DeviceFlow.enabled()],
		Lines:      adminLogLines(0),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := adminPageTmpl.Execute(w, data); err != nil {
		log.Printf("Admin: failed to render panel: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GET /admin/logs — JSON feed the panel polls. ?after=<seq> returns only
// newer lines.
// ---------------------------------------------------------------------------

type adminLogLine struct {
	Seq  uint64 `json:"seq"`
	Text string `json:"text"`
	Kind string `json:"kind"`
}

type adminLogsResponse struct {
	Lines []adminLogLine `json:"lines"`
}

func handleAdminLogs(w http.ResponseWriter, r *http.Request) {
	if !adminEnabled() {
		http.NotFound(w, r)
		return
	}
	if _, ok := adminSession(r); !ok {
		// A JSON 401 rather than a redirect: the poller reloads the page,
		// which walks back through the OAuth login.
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	writeJSON(w, http.StatusOK, adminLogsResponse{Lines: adminLogLines(after)})
}

func adminLogLines(after uint64) []adminLogLine {
	if logBuffer == nil {
		return nil
	}
	lines := logBuffer.Since(after)
	out := make([]adminLogLine, len(lines))
	for i, l := range lines {
		out[i] = adminLogLine{Seq: l.Seq, Text: l.Text, Kind: classifyLogLine(l.Text)}
	}
	return out
}

// classifyLogLine buckets a line for colour-coding. Purely cosmetic, so
// substring matching is good enough.
func classifyLogLine(text string) string {
	switch {
	case strings.Contains(text, "Certificate issued"):
		return "issued"
	case strings.Contains(text, "rejected"), strings.Contains(text, "failed"),
		strings.Contains(text, "Failed"), strings.Contains(text, "denied"),
		strings.Contains(text, "WARNING"), strings.Contains(text, "invalid"):
		return "error"
	case strings.Contains(text, "Config reload"):
		return "config"
	default:
		return "info"
	}
}

type adminPageData struct {
	Email      string
	Version    string
	Uptime     string
	Users      int
	Roles      int
	Services   int
	DeviceFlow string
	Lines      []adminLogLine
}

var adminPageTmpl = template.Must(template.New("admin").Parse(`<!DOCTYPE html>
<html>
<head><title>voussh admin</title><meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body { font-family: system-ui, sans-serif; max-width: 1000px; margin: 30px auto; padding: 0 20px; line-height: 1.5; }
h2 { margin-bottom: 5px; }
table.meta { border-collapse: collapse; margin: 10px 0 15px; font-size: 14px; }
table.meta td { padding: 2px 18px 2px 0; color: #666; }
table.meta td.v { color: #000; font-weight: 600; padding-right: 30px; }
.controls { display: flex; gap: 15px; align-items: center; margin: 10px 0; }
.controls input[type=text] { flex: 1; padding: 6px 8px; font-size: 14px; }
.controls label { font-size: 14px; color: #444; white-space: nowrap; }
#log { background: #1c1e22; color: #c8cdd4; border-radius: 6px; padding: 8px 0; height: 65vh; overflow-y: auto; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
#log .line { padding: 1px 12px; white-space: pre-wrap; word-break: break-all; border-left: 3px solid transparent; }
#log .issued { border-left-color: #2da44e; color: #7ee2a8; }
#log .error  { border-left-color: #cf222e; color: #ff8182; }
#log .config { border-left-color: #54aeff; color: #9cd0ff; }
#log .hidden { display: none; }
</style></head>
<body>
<h2>voussh admin</h2>
<table class="meta">
<tr><td>Signed in as</td><td class="v">{{.Email}}</td><td>Version</td><td class="v">{{.Version}}</td><td>Uptime</td><td class="v">{{.Uptime}}</td></tr>
<tr><td>Users</td><td class="v">{{.Users}}</td><td>Roles</td><td class="v">{{.Roles}}</td><td>Services</td><td class="v">{{.Services}}</td><td>Device flow</td><td class="v">{{.DeviceFlow}}</td></tr>
</table>
<div class="controls">
<input type="text" id="filter" placeholder="Filter lines&hellip;">
<label><input type="checkbox" id="follow" checked> Follow</label>
</div>
<div id="log">{{range .Lines}}<div class="line {{.Kind}}" data-seq="{{.Seq}}">{{.Text}}</div>{{end}}</div>
<script>
const logBox = document.getElementById('log');
const filter = document.getElementById('filter');
const follow = document.getElementById('follow');
let after = 0;
for (const el of logBox.children) after = Math.max(after, +el.dataset.seq);

function applyFilter() {
  const q = filter.value.toLowerCase();
  for (const el of logBox.children)
    el.classList.toggle('hidden', q !== '' && !el.textContent.toLowerCase().includes(q));
}
filter.addEventListener('input', applyFilter);

async function poll() {
  try {
    const resp = await fetch('/admin/logs?after=' + after);
    if (resp.status === 401) { location.reload(); return; }
    if (!resp.ok) return;
    const data = await resp.json();
    for (const line of (data.lines || [])) {
      after = Math.max(after, line.seq);
      const el = document.createElement('div');
      el.className = 'line ' + line.kind;
      el.dataset.seq = line.seq;
      el.textContent = line.text;
      logBox.appendChild(el);
    }
    if (data.lines && data.lines.length) {
      while (logBox.childElementCount > 5000) logBox.removeChild(logBox.firstChild);
      applyFilter();
      if (follow.checked) logBox.scrollTop = logBox.scrollHeight;
    }
  } catch (e) { /* transient network error: keep polling */ }
}
setInterval(poll, 3000);
logBox.scrollTop = logBox.scrollHeight;
</script>
</body>
</html>`))
