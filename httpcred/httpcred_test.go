package httpcred

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// The keys below are derived from fixed, public strings. They exist so that
// tests and the published vectors are reproducible; they protect nothing.
func testKey(label string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("voussh test vector key: " + label))
	return ed25519.NewKeyFromSeed(seed[:])
}

const (
	testIssuer   = "https://auth.example.com"
	testAudience = "secret-broker"
	testOrigin   = "https://broker.example.com"
	testURL      = testOrigin + "/v1/secrets/db-password"
)

// testNow is the fixed instant every test and vector is evaluated at.
var testNow = time.Unix(1790000000, 0).UTC()

type fixture struct {
	t        *testing.T
	issuer   *Issuer
	client   ed25519.PrivateKey
	now      time.Time
	verifier *Verifier
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	issuer, err := NewIssuer(testIssuer, testKey("issuer"), "")
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	f := &fixture{t: t, issuer: issuer, client: testKey("client"), now: testNow}
	f.verifier = f.newVerifier(issuer.Keys())
	return f
}

func (f *fixture) newVerifier(keys []VerificationKey) *Verifier {
	f.t.Helper()
	v, err := NewVerifier(VerifierConfig{
		Issuer:   testIssuer,
		Audience: testAudience,
		Keys:     keys,
		Origin:   testOrigin,
		Now:      func() time.Time { return f.now },
	})
	if err != nil {
		f.t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func (f *fixture) clientPub() ed25519.PublicKey { return f.client.Public().(ed25519.PublicKey) }

// token issues a token, letting the caller adjust the request first.
func (f *fixture) token(adjust func(*TokenRequest)) string {
	f.t.Helper()
	req := TokenRequest{
		Subject:     "alice@example.com",
		SubjectType: SubjectUser,
		Audience:    testAudience,
		Role:        "default",
		Key:         f.clientPub(),
		Validity:    15 * time.Minute,
		Now:         f.now,
	}
	if adjust != nil {
		adjust(&req)
	}
	token, _, err := f.issuer.Issue(req)
	if err != nil {
		f.t.Fatalf("Issue: %v", err)
	}
	return token
}

// proof signs a proof for the standard request, letting the caller adjust it.
func (f *fixture) proof(token string, adjust func(*ProofParams)) string {
	f.t.Helper()
	params := ProofParams{Method: "GET", URL: testURL, AccessToken: token, Now: f.now}
	if adjust != nil {
		adjust(&params)
	}
	proof, err := NewProof(f.client, params)
	if err != nil {
		f.t.Fatalf("NewProof: %v", err)
	}
	return proof
}

func (f *fixture) request(token, proof string) Request {
	return Request{Method: "GET", URL: testURL, Authorization: "DPoP " + token, DPoP: []string{proof}}
}

func wantError(t *testing.T, err error, want *Error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %s", err, want.Code)
	}
}

// craftJWS assembles a compact JWS from arbitrary parts, for the tokens and
// proofs a correct implementation would never produce.
func craftJWS(t *testing.T, header map[string]any, payload any, sign func(signingInput []byte) []byte) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	p, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	return input + "." + base64.RawURLEncoding.EncodeToString(sign([]byte(input)))
}

func edSigner(key ed25519.PrivateKey) func([]byte) []byte {
	return func(input []byte) []byte { return ed25519.Sign(key, input) }
}

// tokenPayload returns the standard claims as a map, for hand-built tokens.
func (f *fixture) tokenPayload() map[string]any {
	return map[string]any{
		"iss": testIssuer, "sub": "alice@example.com", "sub_type": "user", "aud": testAudience,
		"iat": f.now.Unix(), "nbf": f.now.Unix(), "exp": f.now.Add(15 * time.Minute).Unix(),
		"jti": "hand-built", "role": "default",
		"cnf": map[string]any{"jkt": Thumbprint(f.clientPub())},
	}
}

func (f *fixture) proofPayload(token string) map[string]any {
	return map[string]any{
		"jti": "hand-built-proof", "htm": "GET", "htu": testURL, "iat": f.now.Unix(), "ath": TokenHash(token),
	}
}

func publicJWKMap(pub ed25519.PublicKey) map[string]any {
	return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)}
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

// RFC 8037 Appendix A.3 gives the thumbprint of a known Ed25519 key.
func TestThumbprintMatchesRFC8037(t *testing.T) {
	x, err := base64.RawURLEncoding.DecodeString("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := Thumbprint(ed25519.PublicKey(x)), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"; got != want {
		t.Errorf("thumbprint = %s, want %s", got, want)
	}
}

// The hand-rolled thumbprint must agree with the JOSE library's.
func TestThumbprintMatchesGoJose(t *testing.T) {
	pub := testKey("client").Public().(ed25519.PublicKey)
	sum, err := (&jose.JSONWebKey{Key: pub}).Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := Thumbprint(pub), base64.RawURLEncoding.EncodeToString(sum); got != want {
		t.Errorf("thumbprint = %s, go-jose says %s", got, want)
	}
}

func TestParsePublicJWK(t *testing.T) {
	key := testKey("client")
	pub := key.Public().(ed25519.PublicKey)
	x := base64.RawURLEncoding.EncodeToString(pub)

	got, err := ParsePublicJWK(MarshalPublicJWK(pub))
	if err != nil || !bytes.Equal(got, pub) {
		t.Fatalf("round trip failed: %v", err)
	}

	bad := map[string]string{
		"empty":             ``,
		"not json":          `not json`,
		"private key":       fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q,"d":%q}`, x, base64.RawURLEncoding.EncodeToString(key.Seed())),
		"symmetric key":     `{"kty":"oct","k":"c2VjcmV0"}`,
		"rsa key":           `{"kty":"RSA","n":"AQAB","e":"AQAB"}`,
		"wrong curve":       fmt.Sprintf(`{"kty":"OKP","crv":"X25519","x":%q}`, x),
		"short x":           `{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`,
		"x not base64url":   `{"kty":"OKP","crv":"Ed25519","x":"!!!"}`,
		"x with padding":    fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, x+"="),
		"oversized":         `{"kty":"OKP","crv":"Ed25519","x":"` + strings.Repeat("A", maxJWKSize) + `"}`,
		"array, not object": `[]`,
	}
	for name, input := range bad {
		if _, err := ParsePublicJWK([]byte(input)); err == nil {
			t.Errorf("%s: accepted %q", name, input)
		}
	}
}

func TestJWKSPublishesOnlyPublicMetadata(t *testing.T) {
	f := newFixture(t)
	raw := f.issuer.JWKS()

	var set struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatalf("JWKS is not JSON: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(set.Keys))
	}
	want := map[string]string{
		"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
		"kid": f.issuer.KeyID(),
		"x":   base64.RawURLEncoding.EncodeToString(testKey("issuer").Public().(ed25519.PublicKey)),
	}
	for k, v := range want {
		if set.Keys[0][k] != v {
			t.Errorf("%s = %q, want %q", k, set.Keys[0][k], v)
		}
	}
	// Exactly the public members and nothing else — in particular no "d".
	if len(set.Keys[0]) != len(want) {
		t.Errorf("JWKS key has unexpected members: %v", set.Keys[0])
	}
	if seed := base64.RawURLEncoding.EncodeToString(testKey("issuer").Seed()); bytes.Contains(raw, []byte(seed)) {
		t.Fatal("JWKS contains the private seed")
	}

	// What is published must be exactly what a relying service can pin.
	keys, err := ParseJWKS(raw)
	if err != nil {
		t.Fatalf("ParseJWKS: %v", err)
	}
	if len(keys) != 1 || keys[0].KeyID != f.issuer.KeyID() {
		t.Errorf("ParseJWKS = %+v", keys)
	}
}

func TestParseJWKSRejectsUnusableSets(t *testing.T) {
	x := base64.RawURLEncoding.EncodeToString(testKey("issuer").Public().(ed25519.PublicKey))
	good := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q,"kid":"a"}`, x)
	bad := map[string]string{
		"no keys":       `{"keys":[]}`,
		"not json":      `nope`,
		"private key":   fmt.Sprintf(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":%q,"d":"AAAA"}]}`, x),
		"wrong alg":     fmt.Sprintf(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":%q,"alg":"ES256"}]}`, x),
		"wrong use":     fmt.Sprintf(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":%q,"use":"enc"}]}`, x),
		"duplicate kid": fmt.Sprintf(`{"keys":[%s,%s]}`, good, good),
	}
	for name, input := range bad {
		if _, err := ParseJWKS([]byte(input)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Issuance
// ---------------------------------------------------------------------------

func TestIssueSetsEveryClaim(t *testing.T) {
	f := newFixture(t)
	token, claims, err := f.issuer.Issue(TokenRequest{
		Subject: "alice@example.com", SubjectType: SubjectUser, Audience: testAudience,
		Role: "admin", Key: f.clientPub(), Validity: 15 * time.Minute, Now: f.now,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Read the wire form directly, independent of this package's decoder.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}
	var header map[string]any
	var payload map[string]any
	for i, dst := range []*map[string]any{&header, &payload} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			t.Fatal(err)
		}
	}

	if header["alg"] != "EdDSA" || header["typ"] != TokenType || header["kid"] != f.issuer.KeyID() {
		t.Errorf("header = %v", header)
	}
	wantPayload := map[string]any{
		"iss": testIssuer, "sub": "alice@example.com", "sub_type": "user", "aud": testAudience,
		"role": "admin", "iat": float64(f.now.Unix()), "nbf": float64(f.now.Unix()),
		"exp": float64(f.now.Add(15 * time.Minute).Unix()),
	}
	for k, v := range wantPayload {
		if payload[k] != v {
			t.Errorf("%s = %v, want %v", k, payload[k], v)
		}
	}
	if jti, _ := payload["jti"].(string); len(jti) < 16 || jti != claims.ID {
		t.Errorf("jti = %v", payload["jti"])
	}
	cnf, _ := payload["cnf"].(map[string]any)
	if cnf["jkt"] != Thumbprint(f.clientPub()) {
		t.Errorf("cnf = %v, want the client key thumbprint", payload["cnf"])
	}
	// Nothing beyond the documented claims, so there is no place for a
	// client-supplied value to hide.
	if len(payload) != 10 {
		t.Errorf("payload has %d claims, want 10: %v", len(payload), payload)
	}

	other, _, err := f.issuer.Issue(TokenRequest{
		Subject: "alice@example.com", Audience: testAudience, Role: "admin",
		Key: f.clientPub(), Validity: time.Minute, Now: f.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	otherClaims, _ := ParseUnverified(other)
	if otherClaims.ID == claims.ID {
		t.Error("two tokens share a jti")
	}
}

func TestIssueRejectsIncompleteRequests(t *testing.T) {
	f := newFixture(t)
	base := TokenRequest{
		Subject: "alice@example.com", Audience: testAudience, Role: "default",
		Key: f.clientPub(), Validity: time.Minute,
	}
	cases := map[string]func(*TokenRequest){
		"no subject":   func(r *TokenRequest) { r.Subject = "" },
		"no audience":  func(r *TokenRequest) { r.Audience = "" },
		"no role":      func(r *TokenRequest) { r.Role = "" },
		"no key":       func(r *TokenRequest) { r.Key = nil },
		"no validity":  func(r *TokenRequest) { r.Validity = 0 },
		"neg validity": func(r *TokenRequest) { r.Validity = -time.Minute },
	}
	for name, mutate := range cases {
		req := base
		mutate(&req)
		if _, _, err := f.issuer.Issue(req); err == nil {
			t.Errorf("%s: issued a token", name)
		}
	}
}

// ---------------------------------------------------------------------------
// Token verification
// ---------------------------------------------------------------------------

func TestVerifyAcceptsValidRequest(t *testing.T) {
	f := newFixture(t)
	token := f.token(nil)
	claims, err := f.verifier.Verify(f.request(token, f.proof(token, nil)))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "alice@example.com" || claims.Role != "default" || claims.SubjectType != SubjectUser {
		t.Errorf("claims = %+v", claims)
	}
	if claims.KeyThumbprint != Thumbprint(f.clientPub()) || !claims.Expiry.Equal(f.now.Add(15*time.Minute)) {
		t.Errorf("claims = %+v", claims)
	}
}

func TestVerifyHTTP(t *testing.T) {
	f := newFixture(t)
	token := f.token(nil)

	// The broker sees a path and an untrustworthy Host header; the URL the
	// proof must match comes from the configured origin.
	r := httptest.NewRequest("GET", "/v1/secrets/db-password?version=3", nil)
	r.Host = "attacker.example"
	r.Header.Set("Authorization", "DPoP "+token)
	r.Header.Set("DPoP", f.proof(token, nil))
	if _, err := f.verifier.VerifyHTTP(r); err != nil {
		t.Fatalf("VerifyHTTP: %v", err)
	}

	// Two DPoP headers are refused rather than one being picked.
	r = httptest.NewRequest("GET", "/v1/secrets/db-password", nil)
	r.Header.Set("Authorization", "DPoP "+token)
	r.Header.Add("DPoP", f.proof(token, nil))
	r.Header.Add("DPoP", f.proof(token, nil))
	_, err := f.verifier.VerifyHTTP(r)
	wantError(t, err, ErrMalformedProof)

	// Without an origin there is nothing trustworthy to compare htu with.
	noOrigin, err := NewVerifier(VerifierConfig{Issuer: testIssuer, Audience: testAudience, Keys: f.issuer.Keys()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noOrigin.VerifyHTTP(r); err == nil {
		t.Error("VerifyHTTP worked without a configured origin")
	}
}

func TestVerifyRejectsBadTokenSignatures(t *testing.T) {
	f := newFixture(t)
	kid := f.issuer.KeyID()
	issuerPub := testKey("issuer").Public().(ed25519.PublicKey)
	edHeader := map[string]any{"alg": "EdDSA", "typ": TokenType, "kid": kid}

	t.Run("payload altered after signing", func(t *testing.T) {
		parts := strings.Split(f.token(nil), ".")
		payload := f.tokenPayload()
		payload["role"] = "admin"
		raw, _ := json.Marshal(payload)
		forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(raw) + "." + parts[2]
		_, err := f.verifier.Verify(f.request(forged, f.proof(forged, nil)))
		wantError(t, err, ErrTokenSignature)
	})

	t.Run("signature bytes altered", func(t *testing.T) {
		token := f.token(nil)
		parts := strings.Split(token, ".")
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		sig[0] ^= 0x01
		forged := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
		_, err := f.verifier.Verify(f.request(forged, f.proof(forged, nil)))
		wantError(t, err, ErrTokenSignature)
	})

	t.Run("signed by another key under a pinned kid", func(t *testing.T) {
		forged := craftJWS(t, edHeader, f.tokenPayload(), edSigner(testKey("attacker")))
		_, err := f.verifier.Verify(f.request(forged, f.proof(forged, nil)))
		wantError(t, err, ErrTokenSignature)
	})

	t.Run("unknown kid", func(t *testing.T) {
		header := map[string]any{"alg": "EdDSA", "typ": TokenType, "kid": "not-pinned"}
		forged := craftJWS(t, header, f.tokenPayload(), edSigner(testKey("attacker")))
		_, err := f.verifier.Verify(f.request(forged, f.proof(forged, nil)))
		wantError(t, err, ErrUnknownKey)
	})

	t.Run("no kid", func(t *testing.T) {
		header := map[string]any{"alg": "EdDSA", "typ": TokenType}
		forged := craftJWS(t, header, f.tokenPayload(), edSigner(testKey("issuer")))
		_, err := f.verifier.Verify(f.request(forged, f.proof(forged, nil)))
		wantError(t, err, ErrUnknownKey)
	})

	t.Run("alg none", func(t *testing.T) {
		header := map[string]any{"alg": "none", "typ": TokenType, "kid": kid}
		forged := craftJWS(t, header, f.tokenPayload(), func([]byte) []byte { return nil })
		_, err := f.verifier.Verify(f.request(forged, f.proof(forged, nil)))
		wantError(t, err, ErrMalformedToken)
	})

	// The classic confusion attack: an HMAC keyed with the public key, which
	// a verifier that trusted the header's alg would accept.
	t.Run("HS256 keyed with the public key", func(t *testing.T) {
		header := map[string]any{"alg": "HS256", "typ": TokenType, "kid": kid}
		forged := craftJWS(t, header, f.tokenPayload(), func(input []byte) []byte {
			mac := hmac.New(sha256.New, issuerPub)
			mac.Write(input)
			return mac.Sum(nil)
		})
		_, err := f.verifier.Verify(f.request(forged, f.proof(forged, nil)))
		wantError(t, err, ErrMalformedToken)
	})

	// A token that brings its own key must not have that key believed.
	t.Run("embedded jwk", func(t *testing.T) {
		attacker := testKey("attacker")
		header := map[string]any{
			"alg": "EdDSA", "typ": TokenType, "kid": kid,
			"jwk": publicJWKMap(attacker.Public().(ed25519.PublicKey)),
		}
		forged := craftJWS(t, header, f.tokenPayload(), edSigner(attacker))
		_, err := f.verifier.Verify(f.request(forged, f.proof(forged, nil)))
		wantError(t, err, ErrMalformedToken)
	})

	// A DPoP proof is also an EdDSA JWS; typ keeps the two from being confused.
	t.Run("wrong typ", func(t *testing.T) {
		header := map[string]any{"alg": "EdDSA", "typ": "JWT", "kid": kid}
		forged := craftJWS(t, header, f.tokenPayload(), edSigner(testKey("issuer")))
		_, err := f.verifier.Verify(f.request(forged, f.proof(forged, nil)))
		wantError(t, err, ErrMalformedToken)
	})

	t.Run("garbage", func(t *testing.T) {
		for _, token := range []string{"x", "a.b.c", "....", strings.Repeat("A", maxTokenSize+1)} {
			_, err := f.verifier.Verify(f.request(token, "x"))
			wantError(t, err, ErrMalformedToken)
		}
	})
}

// A signed token has exactly one accepted spelling. Base64 leniency would
// otherwise let the same token be presented as many different strings, which
// defeats anything that identifies tokens by their text.
func TestVerifyRejectsNonCanonicalEncodings(t *testing.T) {
	f := newFixture(t)
	token := f.token(nil)
	proof := f.proof(token, nil)
	parts := strings.Split(token, ".")

	// An Ed25519 signature is 64 bytes, so its last base64 character carries
	// four unused bits. Setting them yields a different string that a lenient
	// decoder maps to the same signature.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, token[len(token)-1])
	respelled := token[:len(token)-1] + string(alphabet[last|1])
	if respelled == token {
		respelled = token[:len(token)-1] + string(alphabet[last|2])
	}

	variants := map[string]string{
		"unused trailing bits": respelled,
		"embedded newline":     parts[0] + ".\n" + parts[1] + "." + parts[2],
		"padding":              token + "=",
		"standard alphabet":    strings.NewReplacer("-", "+", "_", "/").Replace(token),
		"four segments":        token + "." + parts[2],
		"two segments":         parts[0] + "." + parts[1],
	}
	for name, variant := range variants {
		if variant == token {
			continue // this token happens not to contain the characters involved
		}
		t.Run("token "+name, func(t *testing.T) {
			// The proof is made for the variant, so only its spelling is at fault.
			_, err := f.verifier.Verify(f.request(variant, f.proof(variant, nil)))
			wantError(t, err, ErrMalformedToken)
		})
	}

	t.Run("proof with unused trailing bits", func(t *testing.T) {
		last := strings.IndexByte(alphabet, proof[len(proof)-1])
		variant := proof[:len(proof)-1] + string(alphabet[last|1])
		if variant == proof {
			variant = proof[:len(proof)-1] + string(alphabet[last|2])
		}
		_, err := f.verifier.Verify(f.request(token, variant))
		wantError(t, err, ErrMalformedProof)
	})

	// A key that is not exactly 32 bytes is not an Ed25519 key, even if a
	// library would quietly truncate or pad it into one.
	for name, x := range map[string][]byte{
		"oversized": append(append([]byte{}, f.clientPub()...), 1, 2, 3),
		"truncated": f.clientPub()[:31],
	} {
		t.Run("proof jwk "+name, func(t *testing.T) {
			header := map[string]any{"alg": "EdDSA", "typ": ProofType, "jwk": map[string]any{
				"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(x),
			}}
			forged := craftJWS(t, header, f.proofPayload(token), edSigner(f.client))
			_, err := f.verifier.Verify(f.request(token, forged))
			wantError(t, err, ErrMalformedProof)
		})
	}
}

func TestVerifySignature(t *testing.T) {
	f := newFixture(t)
	token := f.token(nil)

	claims, err := VerifySignature(token, f.issuer.Keys())
	if err != nil || claims.Subject != "alice@example.com" || claims.Role != "default" {
		t.Fatalf("VerifySignature = %+v, %v", claims, err)
	}

	header := map[string]any{"alg": "EdDSA", "typ": TokenType, "kid": f.issuer.KeyID()}
	forged := craftJWS(t, header, f.tokenPayload(), edSigner(testKey("attacker")))
	_, err = VerifySignature(forged, f.issuer.Keys())
	wantError(t, err, ErrTokenSignature)

	header["alg"] = "none"
	unsigned := craftJWS(t, header, f.tokenPayload(), func([]byte) []byte { return nil })
	_, err = VerifySignature(unsigned, f.issuer.Keys())
	wantError(t, err, ErrMalformedToken)

	other, err := NewIssuer(testIssuer, testKey("someone else"), "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifySignature(token, other.Keys())
	wantError(t, err, ErrUnknownKey)
}

func TestVerifyRejectsWrongIssuerAndAudience(t *testing.T) {
	f := newFixture(t)

	t.Run("wrong issuer", func(t *testing.T) {
		other, err := NewIssuer("https://evil.example.com", testKey("issuer"), "")
		if err != nil {
			t.Fatal(err)
		}
		token, _, err := other.Issue(TokenRequest{
			Subject: "alice@example.com", Audience: testAudience, Role: "default",
			Key: f.clientPub(), Validity: time.Minute, Now: f.now,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.verifier.Verify(f.request(token, f.proof(token, nil)))
		wantError(t, err, ErrWrongIssuer)
	})

	t.Run("wrong audience", func(t *testing.T) {
		token := f.token(func(r *TokenRequest) { r.Audience = "billing-api" })
		_, err := f.verifier.Verify(f.request(token, f.proof(token, nil)))
		wantError(t, err, ErrWrongAudience)
	})

	// Audience matching is exact, never by prefix or substring.
	t.Run("audience that merely contains ours", func(t *testing.T) {
		token := f.token(func(r *TokenRequest) { r.Audience = testAudience + "-staging" })
		_, err := f.verifier.Verify(f.request(token, f.proof(token, nil)))
		wantError(t, err, ErrWrongAudience)
	})

	// Nor is a token good here merely because we are on its list: one valid
	// at several services at once is what audience restriction prevents.
	header := map[string]any{"alg": "EdDSA", "typ": TokenType, "kid": f.issuer.KeyID()}
	for name, aud := range map[string]any{
		"list including ours": []string{"billing-api", testAudience},
		"list of ours twice":  []string{testAudience, testAudience},
		"empty list":          []string{},
		"missing":             nil,
	} {
		t.Run("audience "+name, func(t *testing.T) {
			payload := f.tokenPayload()
			if aud == nil {
				delete(payload, "aud")
			} else {
				payload["aud"] = aud
			}
			token := craftJWS(t, header, payload, edSigner(testKey("issuer")))
			_, err := f.verifier.Verify(f.request(token, f.proof(token, nil)))
			wantError(t, err, ErrWrongAudience)
		})
	}

	// A one-element list is the same audience, spelled the other way.
	t.Run("audience as a single-element list", func(t *testing.T) {
		payload := f.tokenPayload()
		payload["aud"] = []string{testAudience}
		token := craftJWS(t, header, payload, edSigner(testKey("issuer")))
		if _, err := f.verifier.Verify(f.request(token, f.proof(token, nil))); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	})
}

func TestVerifyTokenLifetime(t *testing.T) {
	issued := testNow
	cases := []struct {
		name string
		at   time.Duration // verifier's clock, relative to issuance
		want *Error
	}{
		{"just issued", 0, nil},
		{"last second", 15*time.Minute - time.Second, nil},
		{"expired, within leeway", 15*time.Minute + 29*time.Second, nil},
		{"expired, at leeway", 15*time.Minute + 30*time.Second, ErrTokenExpired},
		{"long expired", 24 * time.Hour, ErrTokenExpired},
		{"verifier clock slightly behind", -29 * time.Second, nil},
		{"not yet valid", -31 * time.Second, ErrTokenNotYetValid},
		{"far in the future", -time.Hour, ErrTokenNotYetValid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			token := f.token(func(r *TokenRequest) { r.Now = issued })
			f.now = issued.Add(tc.at)
			_, err := f.verifier.Verify(f.request(token, f.proof(token, nil)))
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				return
			}
			wantError(t, err, tc.want)
		})
	}
}

func TestVerifyRejectsIncompleteClaims(t *testing.T) {
	f := newFixture(t)
	header := map[string]any{"alg": "EdDSA", "typ": TokenType, "kid": f.issuer.KeyID()}
	for _, claim := range []string{"exp", "sub", "role", "cnf"} {
		t.Run("missing "+claim, func(t *testing.T) {
			payload := f.tokenPayload()
			delete(payload, claim)
			token := craftJWS(t, header, payload, edSigner(testKey("issuer")))
			_, err := f.verifier.Verify(f.request(token, f.proof(token, nil)))
			wantError(t, err, ErrMalformedToken)
		})
	}
}

// ---------------------------------------------------------------------------
// Proof verification
// ---------------------------------------------------------------------------

func TestVerifyRequiresDPoPScheme(t *testing.T) {
	f := newFixture(t)
	token := f.token(nil)
	proof := f.proof(token, nil)

	for name, header := range map[string]string{
		"bearer scheme": "Bearer " + token,
		"no scheme":     token,
		"empty":         "",
		"scheme only":   "DPoP ",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := f.verifier.Verify(Request{Method: "GET", URL: testURL, Authorization: header, DPoP: []string{proof}})
			wantError(t, err, ErrMissingToken)
		})
	}

	t.Run("no proof", func(t *testing.T) {
		_, err := f.verifier.Verify(Request{Method: "GET", URL: testURL, Authorization: "DPoP " + token})
		wantError(t, err, ErrMissingProof)
	})
	t.Run("two proofs", func(t *testing.T) {
		_, err := f.verifier.Verify(Request{
			Method: "GET", URL: testURL, Authorization: "DPoP " + token,
			DPoP: []string{proof, f.proof(token, nil)},
		})
		wantError(t, err, ErrMalformedProof)
	})
}

func TestVerifyRejectsInvalidOrMismatchedProofKeys(t *testing.T) {
	f := newFixture(t)
	token := f.token(nil)
	thief := testKey("thief")
	thiefPub := thief.Public().(ed25519.PublicKey)
	proofHeader := func(pub ed25519.PublicKey) map[string]any {
		return map[string]any{"alg": "EdDSA", "typ": ProofType, "jwk": publicJWKMap(pub)}
	}

	// The scenario DPoP exists for: a stolen token, presented with a
	// perfectly well-formed proof from the thief's own key.
	t.Run("stolen token, thief's key", func(t *testing.T) {
		proof, err := NewProof(thief, ProofParams{Method: "GET", URL: testURL, AccessToken: token, Now: f.now})
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.verifier.Verify(f.request(token, proof))
		wantError(t, err, ErrKeyMismatch)
	})

	// Claiming the right key in the header without holding it.
	t.Run("victim's jwk, thief's signature", func(t *testing.T) {
		proof := craftJWS(t, proofHeader(f.clientPub()), f.proofPayload(token), edSigner(thief))
		_, err := f.verifier.Verify(f.request(token, proof))
		wantError(t, err, ErrProofSignature)
	})

	t.Run("proof altered after signing", func(t *testing.T) {
		parts := strings.Split(f.proof(token, nil), ".")
		payload := f.proofPayload(token)
		payload["htm"] = "DELETE"
		raw, _ := json.Marshal(payload)
		proof := parts[0] + "." + base64.RawURLEncoding.EncodeToString(raw) + "." + parts[2]
		req := f.request(token, proof)
		req.Method = "DELETE"
		_, err := f.verifier.Verify(req)
		wantError(t, err, ErrProofSignature)
	})

	t.Run("no jwk header", func(t *testing.T) {
		header := map[string]any{"alg": "EdDSA", "typ": ProofType}
		proof := craftJWS(t, header, f.proofPayload(token), edSigner(f.client))
		_, err := f.verifier.Verify(f.request(token, proof))
		wantError(t, err, ErrMalformedProof)
	})

	t.Run("private key in jwk header", func(t *testing.T) {
		jwk := publicJWKMap(thiefPub)
		jwk["d"] = base64.RawURLEncoding.EncodeToString(thief.Seed())
		header := map[string]any{"alg": "EdDSA", "typ": ProofType, "jwk": jwk}
		proof := craftJWS(t, header, f.proofPayload(token), edSigner(thief))
		_, err := f.verifier.Verify(f.request(token, proof))
		wantError(t, err, ErrMalformedProof)
	})

	t.Run("wrong typ", func(t *testing.T) {
		header := proofHeader(f.clientPub())
		header["typ"] = "JWT"
		proof := craftJWS(t, header, f.proofPayload(token), edSigner(f.client))
		_, err := f.verifier.Verify(f.request(token, proof))
		wantError(t, err, ErrMalformedProof)
	})

	t.Run("alg none", func(t *testing.T) {
		header := proofHeader(f.clientPub())
		header["alg"] = "none"
		proof := craftJWS(t, header, f.proofPayload(token), func([]byte) []byte { return nil })
		_, err := f.verifier.Verify(f.request(token, proof))
		wantError(t, err, ErrMalformedProof)
	})

	// An unsupported key type is refused outright, not half-verified.
	t.Run("ES256 key", func(t *testing.T) {
		ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: ec},
			(&jose.SignerOptions{EmbedJWK: true}).WithType(ProofType))
		if err != nil {
			t.Fatal(err)
		}
		proof, err := signCompact(signer, f.proofPayload(token))
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.verifier.Verify(f.request(token, proof))
		wantError(t, err, ErrMalformedProof)
	})

	// The access token itself is not a proof, however validly signed.
	t.Run("access token used as proof", func(t *testing.T) {
		_, err := f.verifier.Verify(f.request(token, token))
		wantError(t, err, ErrMalformedProof)
	})

	t.Run("missing jti or iat", func(t *testing.T) {
		for _, claim := range []string{"jti", "iat"} {
			payload := f.proofPayload(token)
			delete(payload, claim)
			proof := craftJWS(t, proofHeader(f.clientPub()), payload, edSigner(f.client))
			_, err := f.verifier.Verify(f.request(token, proof))
			wantError(t, err, ErrMalformedProof)
		}
	})
}

func TestVerifyBindsProofToRequest(t *testing.T) {
	f := newFixture(t)
	token := f.token(nil)

	t.Run("method", func(t *testing.T) {
		req := f.request(token, f.proof(token, nil))
		req.Method = "DELETE"
		_, err := f.verifier.Verify(req)
		wantError(t, err, ErrMethodMismatch)
	})

	t.Run("path", func(t *testing.T) {
		req := f.request(token, f.proof(token, nil))
		req.URL = testOrigin + "/v1/secrets/root-password"
		_, err := f.verifier.Verify(req)
		wantError(t, err, ErrURIMismatch)
	})

	t.Run("host", func(t *testing.T) {
		proof := f.proof(token, func(p *ProofParams) { p.URL = "https://other.example.com/v1/secrets/db-password" })
		_, err := f.verifier.Verify(f.request(token, proof))
		wantError(t, err, ErrURIMismatch)
	})

	t.Run("scheme", func(t *testing.T) {
		proof := f.proof(token, func(p *ProofParams) { p.URL = strings.Replace(testURL, "https://", "http://", 1) })
		_, err := f.verifier.Verify(f.request(token, proof))
		wantError(t, err, ErrURIMismatch)
	})

	// A proof made for one token cannot escort another, even one issued to
	// the same key.
	t.Run("token hash", func(t *testing.T) {
		other := f.token(func(r *TokenRequest) { r.Role = "admin" })
		_, err := f.verifier.Verify(f.request(other, f.proof(token, nil)))
		wantError(t, err, ErrTokenHashMismatch)
	})

	t.Run("missing token hash", func(t *testing.T) {
		proof := f.proof(token, func(p *ProofParams) { p.AccessToken = "" })
		_, err := f.verifier.Verify(f.request(token, proof))
		wantError(t, err, ErrTokenHashMismatch)
	})

	// Equivalent spellings of the same URL do match.
	t.Run("equivalent URLs", func(t *testing.T) {
		for _, spelling := range []string{
			testURL + "?version=3#frag",
			"HTTPS://Broker.Example.COM/v1/secrets/db-password",
			"https://broker.example.com:443/v1/secrets/db-password",
		} {
			proof := f.proof(token, func(p *ProofParams) { p.URL = spelling })
			if _, err := f.verifier.Verify(f.request(token, proof)); err != nil {
				t.Errorf("%s: %v", spelling, err)
			}
		}
	})
}

func TestNormalizeURL(t *testing.T) {
	good := map[string]string{
		"https://Example.com":                 "https://example.com/",
		"https://example.com:443/a?b=c#d":     "https://example.com/a",
		"http://example.com:80/a":             "http://example.com/a",
		"https://example.com:8443/a":          "https://example.com:8443/a",
		"https://example.com/a%2Fb/c":         "https://example.com/a%2Fb/c",
		"http://[::1]:8080/x":                 "http://[::1]:8080/x",
		"https://example.com/Path/Is/Case":    "https://example.com/Path/Is/Case",
		"https://example.com/trailing/slash/": "https://example.com/trailing/slash/",
	}
	for in, want := range good {
		got, err := NormalizeURL(in)
		if err != nil || got != want {
			t.Errorf("NormalizeURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "/relative", "ftp://example.com/", "https://user@example.com/", "https:///nohost", "://bad"} {
		if got, err := NormalizeURL(in); err == nil {
			t.Errorf("NormalizeURL(%q) = %q, want an error", in, got)
		}
	}
}

func TestVerifyRejectsStaleProofs(t *testing.T) {
	cases := []struct {
		name string
		age  time.Duration // how long before the verifier's now the proof was made
		want *Error
	}{
		{"fresh", 0, nil},
		{"at the age limit", 60 * time.Second, nil},
		{"just past the limit", 61 * time.Second, ErrStaleProof},
		{"captured an hour ago", time.Hour, ErrStaleProof},
		{"client clock slightly ahead", -30 * time.Second, nil},
		{"dated in the future", -31 * time.Second, ErrStaleProof},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			token := f.token(func(r *TokenRequest) { r.Now = f.now.Add(-5 * time.Minute) })
			proof := f.proof(token, func(p *ProofParams) { p.Now = f.now.Add(-tc.age) })
			_, err := f.verifier.Verify(f.request(token, proof))
			if tc.want == nil {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				return
			}
			wantError(t, err, tc.want)
		})
	}
}

func TestVerifyRejectsReplayedProofs(t *testing.T) {
	f := newFixture(t)
	token := f.token(nil)
	proof := f.proof(token, nil)

	if _, err := f.verifier.Verify(f.request(token, proof)); err != nil {
		t.Fatalf("first use: %v", err)
	}
	_, err := f.verifier.Verify(f.request(token, proof))
	wantError(t, err, ErrProofReplayed)

	// Still refused later within the freshness window...
	f.now = f.now.Add(59 * time.Second)
	_, err = f.verifier.Verify(f.request(token, proof))
	wantError(t, err, ErrProofReplayed)

	// ...and once the cache has forgotten it, it is stale instead.
	f.now = f.now.Add(10 * time.Second)
	_, err = f.verifier.Verify(f.request(token, proof))
	wantError(t, err, ErrStaleProof)

	// A fresh proof for the same token is unaffected.
	if _, err := f.verifier.Verify(f.request(token, f.proof(token, nil))); err != nil {
		t.Fatalf("fresh proof after a replay: %v", err)
	}
}

// A request that fails any check must not consume its proof id: otherwise an
// attacker could burn a victim's proof ids, or fill the cache, without ever
// presenting anything valid.
func TestFailedRequestsDoNotTouchReplayCache(t *testing.T) {
	f := newFixture(t)
	token := f.token(nil)
	proof := f.proof(token, nil)
	thief := testKey("thief")
	thiefProof, err := NewProof(thief, ProofParams{Method: "GET", URL: testURL, AccessToken: token, Now: f.now})
	if err != nil {
		t.Fatal(err)
	}
	otherToken := f.token(func(r *TokenRequest) { r.Role = "admin" })
	wrongAudience := f.token(func(r *TokenRequest) { r.Audience = "billing-api" })

	failures := map[string]struct {
		req  Request
		want *Error
	}{
		"method":      {Request{Method: "DELETE", URL: testURL, Authorization: "DPoP " + token, DPoP: []string{proof}}, ErrMethodMismatch},
		"url":         {Request{Method: "GET", URL: testOrigin + "/other", Authorization: "DPoP " + token, DPoP: []string{proof}}, ErrURIMismatch},
		"token hash":  {f.request(otherToken, proof), ErrTokenHashMismatch},
		"wrong key":   {f.request(token, thiefProof), ErrKeyMismatch},
		"audience":    {f.request(wrongAudience, f.proof(wrongAudience, nil)), ErrWrongAudience},
		"bearer":      {Request{Method: "GET", URL: testURL, Authorization: "Bearer " + token, DPoP: []string{proof}}, ErrMissingToken},
		"stale proof": {f.request(token, f.proof(token, func(p *ProofParams) { p.Now = f.now.Add(-time.Hour) })), ErrStaleProof},
	}
	for name, tc := range failures {
		_, err := f.verifier.Verify(tc.req)
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s: error = %v, want %s", name, err, tc.want.Code)
		}
		if n := len(f.verifier.replay.seen); n != 0 {
			t.Fatalf("%s: replay cache holds %d entries after a rejected request", name, n)
		}
	}
	// The proof that was dragged through three failed attempts is still good.
	if _, err := f.verifier.Verify(f.request(token, proof)); err != nil {
		t.Fatalf("legitimate use after rejected attempts: %v", err)
	}
}

// One caller hammering the service must run out of its own share of the
// replay cache, not everybody's.
func TestReplayCacheQuotaIsPerSubject(t *testing.T) {
	f := newFixture(t)
	v, err := NewVerifier(VerifierConfig{
		Issuer: testIssuer, Audience: testAudience, Keys: f.issuer.Keys(),
		ReplayCacheSize: 100, ReplayPerSubject: 4, Now: func() time.Time { return f.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	greedy := f.token(func(r *TokenRequest) { r.Subject = "service:greedy" })
	// The same subject with a second key: more keys must not mean more quota.
	secondKey := testKey("greedy second key")
	greedyOther := f.token(func(r *TokenRequest) {
		r.Subject, r.Key = "service:greedy", secondKey.Public().(ed25519.PublicKey)
	})
	polite := f.token(nil)

	for i := 0; i < 4; i++ {
		if _, err := v.Verify(f.request(greedy, f.proof(greedy, nil))); err != nil {
			t.Fatalf("greedy request %d: %v", i, err)
		}
	}
	_, err = v.Verify(f.request(greedy, f.proof(greedy, nil)))
	wantError(t, err, ErrReplayCacheFull)
	proof, err := NewProof(secondKey, ProofParams{Method: "GET", URL: testURL, AccessToken: greedyOther, Now: f.now})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(f.request(greedyOther, proof))
	wantError(t, err, ErrReplayCacheFull)

	// Everyone else is unaffected.
	for i := 0; i < 4; i++ {
		if _, err := v.Verify(f.request(polite, f.proof(polite, nil))); err != nil {
			t.Fatalf("polite request %d while another subject is at its quota: %v", i, err)
		}
	}

	// And the greedy subject recovers once its proofs age out.
	f.now = f.now.Add(2 * time.Minute)
	if _, err := v.Verify(f.request(greedy, f.proof(greedy, nil))); err != nil {
		t.Fatalf("greedy subject after its entries expired: %v", err)
	}
	if got := v.replay.bySubject["service:greedy"]; got != 1 {
		t.Errorf("greedy subject is charged for %d entries after the sweep, want 1", got)
	}
	if _, stale := v.replay.bySubject["alice@example.com"]; stale {
		t.Error("a subject with no live entries is still tracked")
	}
}

func TestReplayCacheIsBounded(t *testing.T) {
	f := newFixture(t)
	v, err := NewVerifier(VerifierConfig{
		Issuer: testIssuer, Audience: testAudience, Keys: f.issuer.Keys(),
		ReplayCacheSize: 3, ReplayPerSubject: 2, Now: func() time.Time { return f.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	// Four callers, each well inside its own share: it is the total that
	// runs out.
	tokens := make([]string, 4)
	for i := range tokens {
		tokens[i] = f.token(func(r *TokenRequest) { r.Subject = fmt.Sprintf("user%d@example.com", i) })
	}

	for i := 0; i < 3; i++ {
		if _, err := v.Verify(f.request(tokens[i], f.proof(tokens[i], nil))); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	// Full: refuse rather than evict an entry that could then be replayed.
	_, err = v.Verify(f.request(tokens[3], f.proof(tokens[3], nil)))
	wantError(t, err, ErrReplayCacheFull)
	if n := len(v.replay.seen); n != 3 {
		t.Fatalf("cache holds %d entries, want 3", n)
	}

	// Once the remembered proofs have aged out, capacity returns.
	f.now = f.now.Add(2 * time.Minute)
	if _, err := v.Verify(f.request(tokens[3], f.proof(tokens[3], nil))); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
	if n := len(v.replay.seen); n != 1 {
		t.Fatalf("cache holds %d entries after sweep, want 1", n)
	}
}

// Proof ids are scoped to the key that signed them: two clients choosing the
// same jti do not collide.
func TestReplayCacheIsPerKey(t *testing.T) {
	f := newFixture(t)
	other := testKey("second client")
	tokenA := f.token(nil)
	tokenB := f.token(func(r *TokenRequest) { r.Key = other.Public().(ed25519.PublicKey) })

	proofA := f.proof(tokenA, func(p *ProofParams) { p.id = "same-id" })
	proofB, err := NewProof(other, ProofParams{Method: "GET", URL: testURL, AccessToken: tokenB, Now: f.now, id: "same-id"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.verifier.Verify(f.request(tokenA, proofA)); err != nil {
		t.Fatalf("client A: %v", err)
	}
	if _, err := f.verifier.Verify(f.request(tokenB, proofB)); err != nil {
		t.Fatalf("client B: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Key rotation
// ---------------------------------------------------------------------------

func TestSigningKeyRotation(t *testing.T) {
	f := newFixture(t)
	oldKey, newKey := testKey("issuer"), testKey("issuer-next")
	oldPub := oldKey.Public().(ed25519.PublicKey)
	newPub := newKey.Public().(ed25519.PublicKey)

	// Step 1: still signing with the old key, already publishing the new one.
	announcing, err := NewIssuer(testIssuer, oldKey, "", VerificationKey{Key: newPub})
	if err != nil {
		t.Fatal(err)
	}
	// Step 2: signing with the new key, still publishing the old one.
	rotated, err := NewIssuer(testIssuer, newKey, "", VerificationKey{Key: oldPub})
	if err != nil {
		t.Fatal(err)
	}

	for name, issuer := range map[string]*Issuer{"announcing": announcing, "rotated": rotated} {
		keys := issuer.Keys()
		if len(keys) != 2 {
			t.Fatalf("%s: publishes %d keys, want 2", name, len(keys))
		}
		// One active signing key, listed first.
		if keys[0].KeyID != issuer.KeyID() {
			t.Errorf("%s: active key is not first in the set", name)
		}
		parsed, err := ParseJWKS(issuer.JWKS())
		if err != nil || len(parsed) != 2 {
			t.Fatalf("%s: published set does not parse back: %v", name, err)
		}
	}
	if announcing.KeyID() != Thumbprint(oldPub) || rotated.KeyID() != Thumbprint(newPub) {
		t.Fatal("default key ids are not the key thumbprints")
	}

	issue := func(issuer *Issuer) string {
		token, _, err := issuer.Issue(TokenRequest{
			Subject: "alice@example.com", Audience: testAudience, Role: "default",
			Key: f.clientPub(), Validity: 15 * time.Minute, Now: f.now,
		})
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	oldToken, newToken := issue(announcing), issue(rotated)

	// A service that pinned the set published during rotation accepts both
	// generations, so tokens issued just before the switch keep working.
	both := f.newVerifier(rotated.Keys())
	for name, token := range map[string]string{"old": oldToken, "new": newToken} {
		if _, err := both.Verify(f.request(token, f.proof(token, nil))); err != nil {
			t.Errorf("%s token against both keys: %v", name, err)
		}
	}

	// A service that never refreshed its pin rejects the new generation —
	// loudly, as an unknown key, rather than as a bad signature.
	stale := f.newVerifier([]VerificationKey{{KeyID: Thumbprint(oldPub), Key: oldPub}})
	_, err = stale.Verify(f.request(newToken, f.proof(newToken, nil)))
	wantError(t, err, ErrUnknownKey)

	// Step 3: the old key is retired, and its tokens die with it.
	retired := f.newVerifier([]VerificationKey{{KeyID: Thumbprint(newPub), Key: newPub}})
	_, err = retired.Verify(f.request(oldToken, f.proof(oldToken, nil)))
	wantError(t, err, ErrUnknownKey)
	if _, err := retired.Verify(f.request(newToken, f.proof(newToken, nil))); err != nil {
		t.Errorf("new token after retirement: %v", err)
	}
}

func TestIssuerKeyIDs(t *testing.T) {
	key := testKey("issuer")
	otherPub := testKey("issuer-next").Public().(ed25519.PublicKey)

	named, err := NewIssuer(testIssuer, key, "2026-11", VerificationKey{KeyID: "2026-10", Key: otherPub})
	if err != nil {
		t.Fatal(err)
	}
	if named.KeyID() != "2026-11" || named.Keys()[1].KeyID != "2026-10" {
		t.Errorf("configured key ids not used: %+v", named.Keys())
	}
	token, _, err := named.Issue(TokenRequest{
		Subject: "a", Audience: "b", Role: "c", Key: otherPub, Validity: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	jws, err := jose.ParseSignedCompact(token, tokenAlgorithms)
	if err != nil {
		t.Fatal(err)
	}
	if kid := jws.Signatures[0].Protected.KeyID; kid != "2026-11" {
		t.Errorf("token kid = %q, want 2026-11", kid)
	}

	// Listing the active key again is tolerated; reusing its id for another
	// key is not.
	if dup, err := NewIssuer(testIssuer, key, "", VerificationKey{Key: key.Public().(ed25519.PublicKey)}); err != nil || len(dup.Keys()) != 1 {
		t.Errorf("re-listing the active key: %v", err)
	}
	if _, err := NewIssuer(testIssuer, key, "same", VerificationKey{KeyID: "same", Key: otherPub}); err == nil {
		t.Error("two different keys were accepted under one key id")
	}
}

func TestNewVerifierRejectsBadConfig(t *testing.T) {
	keys := []VerificationKey{{KeyID: "a", Key: testKey("issuer").Public().(ed25519.PublicKey)}}
	bad := map[string]VerifierConfig{
		"no issuer":             {Audience: testAudience, Keys: keys},
		"no audience":           {Issuer: testIssuer, Keys: keys},
		"no keys":               {Issuer: testIssuer, Audience: testAudience},
		"key without id":        {Issuer: testIssuer, Audience: testAudience, Keys: []VerificationKey{{Key: keys[0].Key}}},
		"duplicate ids":         {Issuer: testIssuer, Audience: testAudience, Keys: append(keys, keys[0])},
		"origin with a path":    {Issuer: testIssuer, Audience: testAudience, Keys: keys, Origin: "https://broker.example.com/api"},
		"origin without scheme": {Issuer: testIssuer, Audience: testAudience, Keys: keys, Origin: "broker.example.com"},
	}
	for name, cfg := range bad {
		if _, err := NewVerifier(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
