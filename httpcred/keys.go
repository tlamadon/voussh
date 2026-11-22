// Package httpcred implements voussh's HTTP credential format: an
// Ed25519-signed JWT access token bound to the holder's key (RFC 7800 "cnf"
// with a RFC 7638 "jkt" thumbprint), presented together with a DPoP proof
// (RFC 9449).
//
// The package has three independent users, and each needs only its own part:
//
//   - the issuer (voussh) signs tokens and publishes verification keys:
//     [NewIssuer], [Issuer.Issue], [Issuer.JWKS];
//   - the client (vsh) holds the private key and proves possession on every
//     request: [NewProof];
//   - the relying service verifies both, entirely offline, against a locally
//     pinned key set: [NewVerifier], [Verifier.Verify].
//
// Nothing here performs network I/O. A relying service never contacts voussh
// or the identity provider to authenticate a request.
package httpcred

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	// TokenType is the JOSE "typ" of an access token (RFC 9068).
	TokenType = "at+jwt"
	// ProofType is the JOSE "typ" of a DPoP proof (RFC 9449 §4.2).
	ProofType = "dpop+jwt"
	// AuthScheme is the Authorization scheme a bound token travels under. A
	// bound token presented as "Bearer" must be refused.
	AuthScheme = "DPoP"

	// SubjectUser and SubjectService are the values of the "sub_type" claim.
	SubjectUser    = "user"
	SubjectService = "service"
)

// The algorithm allowlists. Both are a single entry on purpose: every parse
// goes through one of these, so an "alg" switch (none, HS256 keyed with the
// public key, ...) is rejected before any signature is looked at. Supporting
// another proof key type means extending proofAlgorithms and the key parsing
// below — nothing else assumes Ed25519.
var (
	tokenAlgorithms = []jose.SignatureAlgorithm{jose.EdDSA}
	proofAlgorithms = []jose.SignatureAlgorithm{jose.EdDSA}
)

// maxJWKSize bounds a JWK submitted by a client. An Ed25519 public JWK is
// under 100 bytes.
const maxJWKSize = 2048

// publicJWK is the complete member set of an Ed25519 public JWK (RFC 8037).
// The field order is the lexicographic order RFC 7638 requires, so marshalling
// this struct yields the thumbprint input directly.
type publicJWK struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
}

// ParsePublicJWK parses a client-submitted public key. It accepts exactly one
// shape — an Ed25519 public JWK — and refuses anything carrying private
// material, so a client that sends the wrong half of its key pair gets an
// error instead of a token.
func ParsePublicJWK(data []byte) (ed25519.PublicKey, error) {
	if len(data) == 0 {
		return nil, errors.New("missing JWK")
	}
	if len(data) > maxJWKSize {
		return nil, errors.New("JWK too large")
	}
	var raw struct {
		Kty string  `json:"kty"`
		Crv string  `json:"crv"`
		X   string  `json:"x"`
		D   *string `json:"d"`
		K   *string `json:"k"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid JWK: %w", err)
	}
	if raw.D != nil || raw.K != nil {
		return nil, errors.New("JWK contains private key material; submit the public key only")
	}
	if raw.Kty != "OKP" || raw.Crv != "Ed25519" {
		return nil, errors.New("unsupported JWK: only Ed25519 keys (kty OKP, crv Ed25519) are accepted")
	}
	x, err := base64.RawURLEncoding.DecodeString(raw.X)
	if err != nil || len(x) != ed25519.PublicKeySize {
		return nil, errors.New("invalid JWK: x must be a base64url-encoded 32-byte Ed25519 public key")
	}
	return ed25519.PublicKey(x), nil
}

// MarshalPublicJWK renders a public key as a canonical JWK: only the required
// members, in RFC 7638 order. Issuers store and display this form rather than
// whatever JSON the client sent.
func MarshalPublicJWK(pub ed25519.PublicKey) []byte {
	out, _ := json.Marshal(publicJWK{
		Crv: "Ed25519",
		Kty: "OKP",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	})
	return out
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint of a public key,
// base64url-encoded without padding. This is the value of a token's cnf.jkt
// claim, and the fingerprint shown to a human approving a request.
func Thumbprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(MarshalPublicJWK(pub))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerificationKey is a public key tokens may be verified against, with the
// "kid" that selects it.
type VerificationKey struct {
	KeyID string
	Key   ed25519.PublicKey
}

// jwksKey is one entry of a published key set.
type jwksKey struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
}

type jwks struct {
	Keys []jwksKey `json:"keys"`
}

// MarshalJWKS renders verification keys as a JWK Set (RFC 7517 §5). The
// output is built field by field from public keys, so there is no code path
// by which private material could reach it.
func MarshalJWKS(keys []VerificationKey) []byte {
	set := jwks{Keys: make([]jwksKey, 0, len(keys))}
	for _, k := range keys {
		set.Keys = append(set.Keys, jwksKey{
			Kty: "OKP",
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(k.Key),
			Kid: k.KeyID,
			Alg: string(jose.EdDSA),
			Use: "sig",
		})
	}
	out, _ := json.MarshalIndent(set, "", "  ")
	return append(out, '\n')
}

// ParseJWKS reads a JWK Set as published at /.well-known/jwks.json — the file
// a relying service pins locally. It is strict: every key must be an Ed25519
// signature key, since a pinned file containing anything else is a mistake
// worth failing on rather than skipping over.
func ParseJWKS(data []byte) ([]VerificationKey, error) {
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("invalid JWKS: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("JWKS contains no keys")
	}
	seen := make(map[string]bool, len(set.Keys))
	out := make([]VerificationKey, 0, len(set.Keys))
	for i, raw := range set.Keys {
		pub, err := ParsePublicJWK(raw)
		if err != nil {
			return nil, fmt.Errorf("JWKS key %d: %w", i, err)
		}
		var meta struct {
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
		}
		if err := json.Unmarshal(raw, &meta); err != nil {
			return nil, fmt.Errorf("JWKS key %d: %w", i, err)
		}
		if meta.Alg != "" && meta.Alg != string(jose.EdDSA) {
			return nil, fmt.Errorf("JWKS key %d: unsupported alg %q", i, meta.Alg)
		}
		if meta.Use != "" && meta.Use != "sig" {
			return nil, fmt.Errorf("JWKS key %d: unsupported use %q", i, meta.Use)
		}
		if meta.Kid == "" {
			meta.Kid = Thumbprint(pub)
		}
		if seen[meta.Kid] {
			return nil, fmt.Errorf("JWKS key %d: duplicate kid %q", i, meta.Kid)
		}
		seen[meta.Kid] = true
		out = append(out, VerificationKey{KeyID: meta.Kid, Key: pub})
	}
	return out, nil
}
