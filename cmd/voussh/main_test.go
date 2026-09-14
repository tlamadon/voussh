package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const testServiceToken = "3c50f34a1f6f4f6b-not-a-real-token"

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// signTestConfig returns a config with one machine service. The global
// extensions are deliberately non-empty so the tests can prove that services
// do NOT inherit them.
func signTestConfig() *Config {
	cfg := testConfig()
	cfg.Extensions = []string{"permit-pty", "permit-agent-forwarding"}
	cfg.Services = map[string]ServiceConfig{
		"herdr-hq": {
			TokenSHA256:   sha256Hex(testServiceToken),
			Principals:    []string{"tlamadon"},
			Validity:      "12h",
			SourceAddress: "100.88.151.28/32",
		},
	}
	return cfg
}

func postSign(token string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/sign", bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	handleSign(rr, req)
	return rr
}

// signedCertFrom parses the /sign response body as a certificate.
func signedCertFrom(t *testing.T, rr *httptest.ResponseRecorder) *ssh.Certificate {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("/sign = %d, body %s", rr.Code, rr.Body.String())
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(rr.Body.Bytes())
	if err != nil {
		t.Fatalf("issued certificate does not parse: %v", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatal("issued material is not a certificate")
	}
	return cert
}

func TestSignIssuesServiceCertificate(t *testing.T) {
	setupDeviceTest(t, signTestConfig())

	pubKey := testPubKey(t, "herdr@nixbox")
	rr := postSign(testServiceToken, pubKey)
	cert := signedCertFrom(t, rr)

	if ct := rr.Header().Get("Content-Type"); ct != "text/plain" {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
	if cert.KeyId != "herdr-hq@service" {
		t.Errorf("key id = %q, want herdr-hq@service", cert.KeyId)
	}
	if got := strings.Join(cert.ValidPrincipals, ","); got != "tlamadon" {
		t.Errorf("principals = %q, want tlamadon", got)
	}
	if cert.CertType != ssh.UserCert {
		t.Errorf("cert type = %d, want UserCert", cert.CertType)
	}
	if got := cert.CriticalOptions["source-address"]; got != "100.88.151.28/32" {
		t.Errorf("source-address = %q, want 100.88.151.28/32", got)
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

	// Validity: 12h from the service config, plus the 5m clock-skew backdate.
	now := time.Now()
	validAfter := time.Unix(int64(cert.ValidAfter), 0)
	validBefore := time.Unix(int64(cert.ValidBefore), 0)
	if d := now.Add(-5 * time.Minute).Sub(validAfter); d < -2*time.Second || d > 2*time.Second {
		t.Errorf("valid_after = %s, want ~5m before now", validAfter)
	}
	if d := now.Add(12 * time.Hour).Sub(validBefore); d < -2*time.Second || d > 2*time.Second {
		t.Errorf("valid_before = %s, want ~12h from now", validBefore)
	}
}

// A service that omits extensions must get an empty extension set — not
// defaultExtensions, and not the global extensions (which signTestConfig sets
// on purpose). A daemon needs no pty; permit-pty is opt-in.
func TestSignServiceExtensionsDefaultToEmpty(t *testing.T) {
	setupDeviceTest(t, signTestConfig())

	cert := signedCertFrom(t, postSign(testServiceToken, testPubKey(t, "")))
	if len(cert.Extensions) != 0 {
		t.Errorf("extensions = %v, want none", cert.Extensions)
	}
}

func TestSignServiceExtensionsOptIn(t *testing.T) {
	cfg := signTestConfig()
	svc := cfg.Services["herdr-hq"]
	svc.Extensions = []string{"permit-pty"}
	cfg.Services["herdr-hq"] = svc
	setupDeviceTest(t, cfg)

	cert := signedCertFrom(t, postSign(testServiceToken, testPubKey(t, "")))
	if _, ok := cert.Extensions["permit-pty"]; !ok || len(cert.Extensions) != 1 {
		t.Errorf("extensions = %v, want exactly permit-pty", cert.Extensions)
	}
}

func TestSignValidityFallsBackToCertValidity(t *testing.T) {
	cfg := signTestConfig()
	svc := cfg.Services["herdr-hq"]
	svc.Validity = ""
	cfg.Services["herdr-hq"] = svc
	setupDeviceTest(t, cfg) // testConfig sets cert_validity: 1h

	cert := signedCertFrom(t, postSign(testServiceToken, testPubKey(t, "")))
	validBefore := time.Unix(int64(cert.ValidBefore), 0)
	if d := time.Now().Add(time.Hour).Sub(validBefore); d < -2*time.Second || d > 2*time.Second {
		t.Errorf("valid_before = %s, want ~1h from now (cert_validity)", validBefore)
	}
}

func TestSignRejectsBadTokens(t *testing.T) {
	setupDeviceTest(t, signTestConfig())
	pubKey := testPubKey(t, "")

	cases := []struct {
		name  string
		token string
	}{
		{"wrong token", "wrong-token"},
		{"missing header", ""},
		{"empty bearer", " "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := postSign(tc.token, pubKey)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rr.Code)
			}
			body := rr.Body.String()
			if trimmed := strings.TrimSpace(tc.token); trimmed != "" && strings.Contains(body, trimmed) {
				t.Error("error body echoes the presented token")
			}
			if strings.Contains(body, "ssh-") {
				t.Error("a certificate was issued despite the bad token")
			}
		})
	}

	t.Run("non-bearer scheme", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/sign", bytes.NewReader(pubKey))
		req.Header.Set("Authorization", "Basic "+testServiceToken)
		rr := httptest.NewRecorder()
		handleSign(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rr.Code)
		}
	})
}

// token_file and token_sha256 must be equivalent: the same token authenticates
// the same way whichever form the config uses, and file contents are trimmed.
func TestSignTokenFileEquivalentToDigest(t *testing.T) {
	fileToken := "file-token-5d41402abc4b2a76"
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("  "+fileToken+"\n"), 0600); err != nil {
		t.Fatalf("write token file: %v", err)
	}

	cfg := signTestConfig()
	cfg.Services["file-svc"] = ServiceConfig{
		TokenFile:  tokenPath,
		Principals: []string{"tlamadon"},
	}
	setupDeviceTest(t, cfg)

	byFile := signedCertFrom(t, postSign(fileToken, testPubKey(t, "")))
	if byFile.KeyId != "file-svc@service" {
		t.Errorf("token_file auth resolved to %q, want file-svc@service", byFile.KeyId)
	}
	byDigest := signedCertFrom(t, postSign(testServiceToken, testPubKey(t, "")))
	if byDigest.KeyId != "herdr-hq@service" {
		t.Errorf("token_sha256 auth resolved to %q, want herdr-hq@service", byDigest.KeyId)
	}

	// A missing token file must fail closed, not crash or match.
	os.Remove(tokenPath)
	if rr := postSign(fileToken, testPubKey(t, "")); rr.Code != http.StatusUnauthorized {
		t.Errorf("auth against a missing token file = %d, want 401", rr.Code)
	}
}

func TestSignRejectsBadRequests(t *testing.T) {
	setupDeviceTest(t, signTestConfig())

	t.Run("garbage body", func(t *testing.T) {
		if rr := postSign(testServiceToken, []byte("not a key")); rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rr.Code)
		}
	})

	// A certificate satisfies ssh.PublicKey, so without the explicit check it
	// would be re-signed as though it were a bare key.
	t.Run("certificate as key", func(t *testing.T) {
		pubKey, _, err := parseUserPublicKey(testPubKey(t, ""))
		if err != nil {
			t.Fatalf("parse key: %v", err)
		}
		cert, err := signCertificate(pubKey, "alice@example.com", "default", []string{"root"})
		if err != nil {
			t.Fatalf("sign cert: %v", err)
		}
		if rr := postSign(testServiceToken, ssh.MarshalAuthorizedKey(cert)); rr.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rr.Code)
		}
	})

	t.Run("oversized body", func(t *testing.T) {
		if rr := postSign(testServiceToken, bytes.Repeat([]byte("A"), maxSignBodySize+1)); rr.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("status = %d, want 413", rr.Code)
		}
	})

	t.Run("non-POST", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/sign", nil)
		rr := httptest.NewRecorder()
		handleSign(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want 405", rr.Code)
		}
	})
}

// source_address on a role flows into the interactive certificate too, and a
// role without one keeps issuing certificates with no critical options — the
// OAuth flow's wire format must not change behind users' backs.
func TestRoleSourceAddress(t *testing.T) {
	cfg := testConfig()
	cfg.Roles = map[string]Role{"deploy": {SourceAddress: "192.0.2.0/24"}}
	setupDeviceTest(t, cfg)

	pubKey, _, err := parseUserPublicKey(testPubKey(t, ""))
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	cert, err := signCertificate(pubKey, "alice@example.com", "deploy", []string{"deploy"})
	if err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	if got := cert.CriticalOptions["source-address"]; got != "192.0.2.0/24" {
		t.Errorf("source-address = %q, want 192.0.2.0/24", got)
	}

	plain, err := signCertificate(pubKey, "alice@example.com", "default", []string{"root"})
	if err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	if len(plain.CriticalOptions) != 0 {
		t.Errorf("critical options = %v, want none for a role without source_address", plain.CriticalOptions)
	}
}

const configFileBase = `addr: ":8080"
cert_validity: 1h
redirect_url: "https://ca.example.com/callback"
users:
  alice@example.com:
    default: [root]
`

func writeConfigFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func TestLoadConfigRejectsBadServices(t *testing.T) {
	cases := []struct {
		name    string
		service string
	}{
		{"neither token field", "principals: [tlamadon]"},
		{"both token fields", fmt.Sprintf("token_file: /nonexistent\n    token_sha256: %q\n    principals: [tlamadon]", sha256Hex("x"))},
		{"bad digest", "token_sha256: \"zzzz\"\n    principals: [tlamadon]"},
		{"empty principals", fmt.Sprintf("token_sha256: %q\n    principals: []", sha256Hex("x"))},
		{"bad validity", fmt.Sprintf("token_sha256: %q\n    principals: [tlamadon]\n    validity: soon", sha256Hex("x"))},
		{"bad source_address", fmt.Sprintf("token_sha256: %q\n    principals: [tlamadon]\n    source_address: not-an-ip", sha256Hex("x"))},
		{"source_address with space", fmt.Sprintf("token_sha256: %q\n    principals: [tlamadon]\n    source_address: \"10.0.0.0/8, 10.1.0.0/16\"", sha256Hex("x"))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			writeConfigFile(t, path, configFileBase+"services:\n  svc:\n    "+tc.service+"\n")
			if _, err := loadConfig(path); err == nil {
				t.Fatal("loadConfig accepted an invalid services block")
			}
		})
	}

	t.Run("bad role source_address", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		writeConfigFile(t, path, configFileBase+"roles:\n  deploy:\n    source_address: 10.0.0.0/99\n")
		if _, err := loadConfig(path); err == nil {
			t.Fatal("loadConfig accepted an invalid role source_address")
		}
	})
}

// A config reload must make a newly added service usable without a restart,
// and a broken edit must keep the previous (working) config.
func TestReloadPicksUpNewService(t *testing.T) {
	setupDeviceTest(t, nil) // installs the CA signer the handlers read

	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfigFile(t, path, configFileBase)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("load initial config: %v", err)
	}
	configPtr.Store(cfg)

	if rr := postSign(testServiceToken, testPubKey(t, "")); rr.Code != http.StatusUnauthorized {
		t.Fatalf("sign before the service exists = %d, want 401", rr.Code)
	}

	serviceBlock := fmt.Sprintf("services:\n  herdr-hq:\n    token_sha256: %q\n    principals: [tlamadon]\n    validity: 12h\n", sha256Hex(testServiceToken))
	writeConfigFile(t, path, configFileBase+serviceBlock)
	reloadConfig(path)

	cert := signedCertFrom(t, postSign(testServiceToken, testPubKey(t, "")))
	if cert.KeyId != "herdr-hq@service" {
		t.Errorf("key id = %q after reload", cert.KeyId)
	}

	// Break the services block: the reload must be refused and the working
	// config kept, so the service keeps signing.
	writeConfigFile(t, path, configFileBase+"services:\n  herdr-hq:\n    principals: []\n")
	reloadConfig(path)
	if rr := postSign(testServiceToken, testPubKey(t, "")); rr.Code != http.StatusOK {
		t.Errorf("sign after a broken reload = %d, want 200 (previous config kept)", rr.Code)
	}
}
