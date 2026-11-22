package main

// vsh http makes one HTTP request authenticated with a stored credential. It
// attaches the access token and a freshly signed DPoP proof (RFC 9449) for
// exactly that method and URL, so neither ever has to be handled by the
// caller, pasted into a shell, or written to a script.

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/tlamadon/voussh/httpcred"
	"github.com/tlamadon/voussh/internal/keyfile"
)

// headerList collects repeated -H flags.
type headerList []string

func (h *headerList) String() string     { return strings.Join(*h, ", ") }
func (h *headerList) Set(v string) error { *h = append(*h, v); return nil }

func cmdHTTP(args []string) {
	fs := flag.NewFlagSet("http", flag.ExitOnError)
	audience := fs.String("audience", "", "Credential to use (optional when only one is stored)")
	var method, data, output string
	var headers headerList
	var include bool
	fs.StringVar(&method, "method", "", "HTTP method (default: GET, or POST with --data)")
	fs.StringVar(&method, "X", "", "Shorthand for --method")
	fs.StringVar(&data, "data", "", "Request body; @file reads a file, @- reads stdin")
	fs.StringVar(&data, "d", "", "Shorthand for --data")
	fs.Var(&headers, "header", "Extra request header \"Name: value\" (repeatable)")
	fs.Var(&headers, "H", "Shorthand for --header")
	fs.StringVar(&output, "output", "", "Write the response body to this file instead of stdout")
	fs.StringVar(&output, "o", "", "Shorthand for --output")
	fs.BoolVar(&include, "include", false, "Print the response status line and headers before the body")
	fs.BoolVar(&include, "i", false, "Shorthand for --include")
	allowHTTP := fs.Bool("allow-http", false, "Permit plain http:// to a host other than localhost")
	timeout := fs.Duration("timeout", 60*time.Second, "Overall request timeout")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: vsh http [options] <url>")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "Sends the request with `Authorization: DPoP <token>` and a single-use DPoP proof.")
		fmt.Fprintln(os.Stderr, "The response body goes to stdout; a status of 400 or above exits non-zero.")
		fmt.Fprintln(os.Stderr)
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}
	target := fs.Arg(0)

	if err := checkRequestURL(target, *allowHTTP); err != nil {
		fatalf("%v", err)
	}
	body, err := readRequestBody(data)
	if err != nil {
		fatalf("%v", err)
	}
	if method == "" {
		method = http.MethodGet
		if data != "" {
			method = http.MethodPost
		}
	}
	method = strings.ToUpper(method)
	extra, err := parseHeaders(headers)
	if err != nil {
		fatalf("%v", err)
	}

	rec, err := usableToken(*audience)
	if err != nil {
		fatalf("%v", err)
	}
	key, err := keyfile.LoadPrivate(rec.KeyPath)
	if err != nil {
		fatalf("failed to load key: %v", err)
	}

	resp, err := signedRequest(newRequestClient(*timeout), key, rec.AccessToken, method, target, extra, body)
	if err != nil {
		fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	failed := resp.StatusCode >= 400
	if location := resp.Header.Get("Location"); resp.StatusCode >= 300 && resp.StatusCode < 400 && location != "" {
		fmt.Fprintf(os.Stderr, "Redirect to %s not followed: a DPoP proof covers only the URL it was made for\n", location)
		failed = true
	}

	// On failure everything goes to stderr, so a script capturing stdout
	// never mistakes an error body for the data it asked for.
	out := io.Writer(os.Stdout)
	if failed {
		out = os.Stderr
		fmt.Fprintf(os.Stderr, "HTTP %s\n", resp.Status)
	} else if output != "" {
		file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			fatalf("%v", err)
		}
		defer file.Close()
		out = file
	}
	if include && !failed {
		writeResponseHead(os.Stdout, resp)
	}
	if _, err := io.Copy(out, resp.Body); err != nil {
		fatalf("failed to read response: %v", err)
	}
	if failed {
		os.Exit(1)
	}
}

// newRequestClient builds the HTTP client credentials are sent with. It never
// follows redirects: a proof names one URL, and following a redirect would
// send the token to a URL the proof does not cover — possibly on another
// host.
func newRequestClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// signedRequest sends one request with the access token and a matching DPoP
// proof. If the server answers with a DPoP-Nonce challenge (RFC 9449 §9) the
// request is repeated once with a new proof carrying that nonce.
func signedRequest(client *http.Client, key ed25519.PrivateKey, token, method, target string, extra http.Header, body []byte) (*http.Response, error) {
	nonce := ""
	for attempt := 0; ; attempt++ {
		proof, err := httpcred.NewProof(key, httpcred.ProofParams{
			Method:      method,
			URL:         target,
			AccessToken: token,
			Nonce:       nonce,
		})
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequest(method, target, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		for name, values := range extra {
			req.Header[name] = values
		}
		req.Header.Set("Authorization", httpcred.AuthScheme+" "+token)
		req.Header.Set("DPoP", proof)

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		challenge := resp.Header.Get("DPoP-Nonce")
		if attempt == 0 && resp.StatusCode == http.StatusUnauthorized && challenge != "" &&
			strings.Contains(resp.Header.Get("WWW-Authenticate"), "use_dpop_nonce") {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			nonce = challenge
			continue
		}
		return resp, nil
	}
}

// checkRequestURL refuses targets a credential should not be sent to.
func checkRequestURL(target string, allowHTTP bool) error {
	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if allowHTTP || isLoopbackHost(u.Hostname()) {
			return nil
		}
		return errors.New("refusing to send a credential over plain http:// (use https://, or --allow-http to override)")
	default:
		return errors.New("an absolute http:// or https:// URL is required")
	}
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// readRequestBody resolves --data: a literal, @file, or @- for stdin.
func readRequestBody(data string) ([]byte, error) {
	switch {
	case data == "":
		return nil, nil
	case data == "@-":
		return io.ReadAll(os.Stdin)
	case strings.HasPrefix(data, "@"):
		body, err := os.ReadFile(data[1:])
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		return body, nil
	default:
		return []byte(data), nil
	}
}

// parseHeaders turns "Name: value" flags into headers. The two headers that
// carry the credential are vsh's to set, not the caller's.
func parseHeaders(list []string) (http.Header, error) {
	headers := http.Header{}
	for _, entry := range list {
		name, value, ok := strings.Cut(entry, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" {
			return nil, fmt.Errorf("invalid header %q: want \"Name: value\"", entry)
		}
		canonical := http.CanonicalHeaderKey(name)
		if canonical == "Authorization" || canonical == "Dpop" {
			return nil, fmt.Errorf("the %s header is set by vsh and cannot be overridden", name)
		}
		headers.Add(canonical, strings.TrimSpace(value))
	}
	return headers, nil
}

func writeResponseHead(w io.Writer, resp *http.Response) {
	fmt.Fprintf(w, "%s %s\n", resp.Proto, resp.Status)
	names := make([]string, 0, len(resp.Header))
	for name := range resp.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, value := range resp.Header[name] {
			fmt.Fprintf(w, "%s: %s\n", name, value)
		}
	}
	fmt.Fprintln(w)
}
