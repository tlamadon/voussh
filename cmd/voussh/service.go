package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// maxSignBodySize bounds the /sign request body. An authorized_keys line is a
// few hundred bytes; 8 KiB leaves room for large RSA keys and long comments.
const maxSignBodySize = 8 << 10

// ServiceConfig describes one non-interactive client of POST /sign. The token
// is the whole credential: whoever holds it can obtain certificates for the
// listed principals, so it deserves the same care as the CA key itself.
type ServiceConfig struct {
	TokenFile     string   `yaml:"token_file,omitempty"`     // token read (and trimmed) from this file at request time
	TokenSHA256   string   `yaml:"token_sha256,omitempty"`   // hex SHA-256 digest of the token
	Principals    []string `yaml:"principals"`               // principals the certificate carries
	Validity      string   `yaml:"validity,omitempty"`       // falls back to cert_validity
	Extensions    []string `yaml:"extensions,omitempty"`     // defaults to EMPTY, unlike interactive certs
	SourceAddress string   `yaml:"source_address,omitempty"` // source-address critical option: CIDRs the cert may be used from
}

func (s ServiceConfig) validate() error {
	switch {
	case s.TokenFile == "" && s.TokenSHA256 == "":
		return errors.New("one of token_file or token_sha256 is required")
	case s.TokenFile != "" && s.TokenSHA256 != "":
		return errors.New("token_file and token_sha256 are mutually exclusive")
	}
	if s.TokenSHA256 != "" {
		digest, err := hex.DecodeString(s.TokenSHA256)
		if err != nil || len(digest) != sha256.Size {
			return errors.New("token_sha256 must be 64 hex characters")
		}
	}
	if len(s.Principals) == 0 {
		return errors.New("principals must not be empty")
	}
	if s.Validity != "" {
		if _, err := time.ParseDuration(s.Validity); err != nil {
			return fmt.Errorf("invalid validity %q: %w", s.Validity, err)
		}
	}
	return validateSourceAddress(s.SourceAddress)
}

// validateSourceAddress checks a source-address value: one or more
// comma-separated CIDR blocks or plain addresses, exactly as sshd will later
// parse them out of the certificate. Entries are deliberately not trimmed —
// the string goes into the certificate verbatim, and sshd rejects spaces.
func validateSourceAddress(value string) error {
	if value == "" {
		return nil
	}
	for _, part := range strings.Split(value, ",") {
		if _, _, err := net.ParseCIDR(part); err == nil {
			continue
		}
		if net.ParseIP(part) != nil {
			continue
		}
		return fmt.Errorf("invalid source_address entry %q: want CIDR (a.b.c.d/nn) or a plain address, no spaces", part)
	}
	return nil
}

// serviceTokenDigest returns the SHA-256 digest a presented token must match.
// Reading token_file at request time (rather than at load) means rotating the
// token needs no reload, and a file that appears after startup just works.
func serviceTokenDigest(svc ServiceConfig) ([]byte, error) {
	if svc.TokenSHA256 != "" {
		return hex.DecodeString(svc.TokenSHA256)
	}
	raw, err := os.ReadFile(svc.TokenFile)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(strings.TrimSpace(string(raw))))
	return digest[:], nil
}

// authenticateService maps a presented bearer token onto the service it
// belongs to. Every comparison runs over SHA-256 digests in constant time, so
// token_file and token_sha256 entries take the same code path and neither
// leaks how much of a token matched.
func authenticateService(cfg *Config, token string) (string, ServiceConfig, bool) {
	presented := sha256.Sum256([]byte(token))
	for name, svc := range cfg.Services {
		expected, err := serviceTokenDigest(svc)
		if err != nil {
			log.Printf("Sign: cannot load token for service %q: %v", name, err)
			continue
		}
		if subtle.ConstantTimeCompare(presented[:], expected) == 1 {
			return name, svc, true
		}
	}
	return "", ServiceConfig{}, false
}

// bearerToken extracts the token from an Authorization: Bearer header.
func bearerToken(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(auth[len(prefix):])
	return token, token != ""
}

// signServiceCertificate issues a certificate for a configured service. Unlike
// interactive certificates, extensions default to empty — a daemon running
// non-interactive commands needs no pty and no agent forwarding, so anything
// beyond plain exec must be opted into in the service's config.
func signServiceCertificate(name string, svc ServiceConfig, pubKey ssh.PublicKey) (*ssh.Certificate, error) {
	validity := svc.Validity
	if validity == "" {
		validity = currentConfig().CertValidity
	}
	duration, err := time.ParseDuration(validity)
	if err != nil {
		duration = 8 * time.Hour
	}

	var extensions map[string]string
	if len(svc.Extensions) > 0 {
		extensions = make(map[string]string, len(svc.Extensions))
		for _, ext := range svc.Extensions {
			extensions[ext] = ""
		}
	}

	// The "@service" suffix keeps machine certificates distinguishable from
	// interactive ones (<email>@<role>) in sshd's auth log.
	return signPolicyCertificate(pubKey, name+"@service", svc.Principals, duration, extensions, criticalOptions(svc.SourceAddress))
}

// handleSign is the non-interactive counterpart to /login + /callback: a
// service authenticates with a bearer token and posts a public key in
// authorized_keys format; the response is the signed certificate in the same
// format, ready to be written to id_ed25519-cert.pub.
func handleSign(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// The error body is a fixed string on every auth failure: it must never
	// echo the header back, and one message for absent, malformed and unknown
	// tokens gives an attacker nothing to distinguish.
	token, ok := bearerToken(r)
	if !ok {
		log.Printf("Sign: request without a bearer token from %s", clientIP(r))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	name, svc, ok := authenticateService(currentConfig(), token)
	if !ok {
		log.Printf("Sign: rejected unknown token from %s", clientIP(r))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSignBodySize))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "Public key too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	pubKey, _, err := parseUserPublicKey(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cert, err := signServiceCertificate(name, svc, pubKey)
	if err != nil {
		log.Printf("Sign: failed to sign certificate for service %q: %v", name, err)
		http.Error(w, "Failed to sign certificate", http.StatusInternalServerError)
		return
	}

	log.Printf("Certificate issued: service=%s, principals=[%s], serial=%d, key=%s, valid=%s to %s, source_ip=%s",
		name, strings.Join(cert.ValidPrincipals, ", "), cert.Serial, ssh.FingerprintSHA256(pubKey),
		time.Unix(int64(cert.ValidAfter), 0).Format(time.RFC3339),
		time.Unix(int64(cert.ValidBefore), 0).Format(time.RFC3339),
		clientIP(r))

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(ssh.MarshalAuthorizedKey(cert))
}
