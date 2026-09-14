package main

// Reverse-proxy awareness. voussh normally identifies a caller by the socket
// peer address, which behind a proxy is always the proxy itself — collapsing
// the rate limiters into one bucket and filling the audit log with the
// proxy's address. When the peer is listed in trusted_proxies, the
// X-Forwarded-* headers it sets are believed instead. Trust is explicit and
// off by default: honouring the headers from an arbitrary peer would let any
// caller forge their source address.

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// parseProxyPrefix reads one trusted_proxies entry: a CIDR, or a bare IP
// treated as a single-address prefix.
func parseProxyPrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	if addr, err := netip.ParseAddr(s); err == nil {
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	return netip.Prefix{}, fmt.Errorf("invalid trusted_proxies entry %q: want a CIDR (a.b.c.d/nn) or a bare IP", s)
}

// trustedProxy reports whether addr is covered by trusted_proxies. Addresses
// are unmapped first so an IPv4 peer on a dual-stack listener
// (::ffff:172.17.0.1) still matches an IPv4 prefix.
func trustedProxy(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range currentConfig().trustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// trustedPeer reports whether the request's socket peer is a trusted proxy.
func trustedPeer(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && trustedProxy(addr)
}

// clientIP identifies the caller for rate limiting and the audit log.
//
// X-Forwarded-For is only believed when the socket peer is listed in
// trusted_proxies: honouring it from an arbitrary peer would let any caller
// spoof their way past the limiter. When the peer is trusted the header is
// walked right to left — proxies append the real peer address, so the
// right-most entry that is not itself a trusted proxy is the closest address
// the caller could not choose. A client-supplied value ("X-Forwarded-For:
// 1.2.3.4" arrives as "1.2.3.4, <real-ip>") is thereby never returned.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !trustedProxy(peer) {
		return host
	}

	forwarded := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	entries := strings.Split(forwarded, ",")
	for i := len(entries) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(entries[i]))
		if err != nil {
			continue // not an address; a bad header must not fail the request
		}
		if !trustedProxy(addr) {
			return addr.Unmap().String()
		}
	}
	// Every entry was itself a trusted proxy, or the header was absent or
	// garbage: the peer is the most honest answer left.
	return host
}

// requestScheme reports the scheme the client actually used: the trusted
// proxy's X-Forwarded-Proto when present, otherwise the connection itself.
// The admin cookie's Secure flag depends on this — behind a TLS-terminating
// proxy the connection to voussh is plain HTTP even though the browser's is
// not.
func requestScheme(r *http.Request) string {
	if trustedPeer(r) {
		if proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); proto != "" {
			if strings.EqualFold(proto, "https") {
				return "https"
			}
			return "http"
		}
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

// listensBeyondLoopback reports whether addr accepts connections from other
// hosts (":8080" and "0.0.0.0:8080" do; "127.0.0.1:8080" does not). Used
// only for the startup warning about plaintext exposure.
func listensBeyondLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return true // ":8080" binds every interface
	}
	if host == "localhost" {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return true // a hostname; assume it resolves somewhere reachable
	}
	return !ip.IsLoopback()
}
