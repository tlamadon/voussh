package httpcred

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// ProofParams describes the single HTTP request a DPoP proof authorizes.
type ProofParams struct {
	// Method is the HTTP method, e.g. "GET".
	Method string
	// URL is the request URL. Its query and fragment are dropped, as RFC 9449
	// §4.2 requires of "htu".
	URL string
	// AccessToken is the token sent alongside the proof; its hash becomes
	// "ath", tying the proof to that one token.
	AccessToken string
	// Nonce is a server-supplied DPoP-Nonce value, if the server asked for one.
	Nonce string
	// Now is the proof's creation time; the zero value means time.Now().
	Now time.Time

	id string // fixed jti, for reproducible test vectors only
}

// proofClaims is the payload of a DPoP proof (RFC 9449 §4.2).
type proofClaims struct {
	Jti   string           `json:"jti"`
	Htm   string           `json:"htm"`
	Htu   string           `json:"htu"`
	Iat   *jwt.NumericDate `json:"iat"`
	Ath   string           `json:"ath,omitempty"`
	Nonce string           `json:"nonce,omitempty"`
}

// NewProof signs a DPoP proof for one request. A proof is single-use: build a
// fresh one for every request, including retries.
func NewProof(key ed25519.PrivateKey, p ProofParams) (string, error) {
	if len(key) != ed25519.PrivateKeySize {
		return "", errors.New("proof key is not an Ed25519 private key")
	}
	if p.Method == "" {
		return "", errors.New("proof method must not be empty")
	}
	htu, err := NormalizeURL(p.URL)
	if err != nil {
		return "", err
	}

	now := p.Now
	if now.IsZero() {
		now = time.Now()
	}
	id := p.id
	if id == "" {
		if id, err = randomID(); err != nil {
			return "", err
		}
	}

	claims := proofClaims{
		Jti:   id,
		Htm:   p.Method,
		Htu:   htu,
		Iat:   jwt.NewNumericDate(now),
		Nonce: p.Nonce,
	}
	if p.AccessToken != "" {
		claims.Ath = TokenHash(p.AccessToken)
	}

	// EmbedJWK puts the public half in the "jwk" header. go-jose derives it
	// from the private key itself, so the private half cannot be embedded.
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: key},
		(&jose.SignerOptions{EmbedJWK: true}).WithType(ProofType),
	)
	if err != nil {
		return "", err
	}
	return signCompact(signer, claims)
}

// TokenHash returns the "ath" value for an access token: the base64url
// SHA-256 of its ASCII serialization (RFC 9449 §4.2).
func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// NormalizeURL reduces a request URL to the form compared as "htu": scheme
// and host lower-cased, default port removed, an empty path replaced by "/",
// and the query and fragment dropped (RFC 9449 §4.3 step 9, RFC 3986 §6.2).
// Percent-encoding in the path is left exactly as given.
func NormalizeURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("invalid URL: an absolute http or https URL is required")
	}
	if u.Host == "" || u.User != nil {
		return "", errors.New("invalid URL: a host and no userinfo is required")
	}

	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]" // IPv6 literal
	}
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}

	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + host + path, nil
}
