package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// trustedConfig installs a config whose trusted_proxies list is compiled the
// same way loadConfig would.
func trustedConfig(t *testing.T, entries ...string) {
	t.Helper()
	cfg := testConfig()
	cfg.TrustedProxies = entries
	if err := cfg.validate(); err != nil {
		t.Fatalf("compile trusted_proxies %v: %v", entries, err)
	}
	configPtr.Store(cfg)
}

func proxyRequest(remoteAddr, xff string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	return req
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		name    string
		trusted []string
		remote  string
		xff     string
		want    string
	}{
		// The default path: no trusted proxies means the header is never
		// consulted, byte-for-byte the old behaviour.
		{"no proxies configured", nil, "203.0.113.9:1234", "1.2.3.4", "203.0.113.9"},
		{"untrusted peer ignores header", []string{"172.17.0.1/32"}, "203.0.113.9:1234", "1.2.3.4", "203.0.113.9"},
		{"no header from untrusted peer", nil, "203.0.113.9:1234", "", "203.0.113.9"},

		{"trusted peer takes forwarded client", []string{"192.0.2.1/32"}, "192.0.2.1:1234", "10.0.0.7", "10.0.0.7"},

		// The security-critical case: proxies APPEND the real peer, so a
		// client-chosen prefix must never win. "1.2.3.4" is what the caller
		// sent; "10.0.0.7" is what the proxy appended.
		{"spoofed prefix is ignored", []string{"192.0.2.1/32"}, "192.0.2.1:1234", "1.2.3.4, 10.0.0.7", "10.0.0.7"},

		// Chained proxies: skip every trusted hop, right to left.
		{"chained trusted proxies", []string{"192.0.2.1/32", "172.16.0.0/12"}, "192.0.2.1:1234", "10.0.0.7, 172.16.1.1, 172.16.1.2", "10.0.0.7"},

		// Nothing usable in the header: fall back to the peer.
		{"every entry trusted", []string{"192.0.2.1/32", "172.16.0.0/12"}, "192.0.2.1:1234", "172.16.1.1, 172.16.1.2", "192.0.2.1"},
		{"absent header from trusted peer", []string{"192.0.2.1/32"}, "192.0.2.1:1234", "", "192.0.2.1"},
		{"garbage header", []string{"192.0.2.1/32"}, "192.0.2.1:1234", "not-an-ip, ???", "192.0.2.1"},
		{"garbage entries skipped", []string{"192.0.2.1/32"}, "192.0.2.1:1234", "10.0.0.7, garbage", "10.0.0.7"},

		// IPv6 peers and entries, and a bare-IP trusted_proxies entry
		// (treated as a single-address prefix).
		{"ipv6 with bare-ip entry", []string{"2001:db8::1"}, "[2001:db8::1]:9999", "2001:db8::aa", "2001:db8::aa"},
		{"bare ipv4 entry", []string{"192.0.2.1"}, "192.0.2.1:5", "10.0.0.7", "10.0.0.7"},

		// A dual-stack listener hands IPv4 peers over as v4-mapped IPv6;
		// they must still match an IPv4 prefix.
		{"v4-mapped peer", []string{"192.0.2.1/32"}, "[::ffff:192.0.2.1]:80", "10.0.0.7", "10.0.0.7"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trustedConfig(t, tc.trusted...)
			if got := clientIP(proxyRequest(tc.remote, tc.xff)); got != tc.want {
				t.Errorf("clientIP() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseProxyPrefixRejectsGarbage(t *testing.T) {
	for _, entry := range []string{"not-an-ip", "10.0.0.0/99", "", "10.0.0.1/-1"} {
		if _, err := parseProxyPrefix(entry); err == nil {
			t.Errorf("parseProxyPrefix(%q) accepted an invalid entry", entry)
		}
	}
}

func TestRequestScheme(t *testing.T) {
	t.Run("trusted proxy header wins", func(t *testing.T) {
		trustedConfig(t, "192.0.2.1/32")
		req := proxyRequest("192.0.2.1:1234", "")
		req.Header.Set("X-Forwarded-Proto", "https")
		if got := requestScheme(req); got != "https" {
			t.Errorf("scheme = %q, want https", got)
		}
		req.Header.Set("X-Forwarded-Proto", "http")
		if got := requestScheme(req); got != "http" {
			t.Errorf("scheme = %q, want http", got)
		}
	})

	t.Run("untrusted peer's header is ignored", func(t *testing.T) {
		trustedConfig(t) // nothing trusted
		req := proxyRequest("203.0.113.9:1234", "")
		req.Header.Set("X-Forwarded-Proto", "https")
		if got := requestScheme(req); got != "http" {
			t.Errorf("scheme = %q, want http (header must not be believed)", got)
		}
	})

	t.Run("direct TLS", func(t *testing.T) {
		trustedConfig(t)
		req := proxyRequest("203.0.113.9:1234", "")
		req.TLS = &tls.ConnectionState{}
		if got := requestScheme(req); got != "https" {
			t.Errorf("scheme = %q, want https", got)
		}
	})

	t.Run("plain HTTP", func(t *testing.T) {
		trustedConfig(t)
		if got := requestScheme(proxyRequest("203.0.113.9:1234", "")); got != "http" {
			t.Errorf("scheme = %q, want http", got)
		}
	})
}

func TestListensBeyondLoopback(t *testing.T) {
	cases := map[string]bool{
		":8080":           true,
		"0.0.0.0:8080":    true,
		"10.0.0.5:8080":   true,
		"[::]:8080":       true,
		"127.0.0.1:8080":  false,
		"[::1]:8080":      false,
		"localhost:8080":  false,
		"127.0.0.53:8080": false,
	}
	for addr, want := range cases {
		if got := listensBeyondLoopback(addr); got != want {
			t.Errorf("listensBeyondLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}
