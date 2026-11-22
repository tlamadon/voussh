package httpcred

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Claims is the content of an access token. Every field is set by the issuer
// from its own policy; none is copied from a client request.
type Claims struct {
	Issuer      string // iss: the configured issuer identifier
	Subject     string // sub: verified email, or "service:<name>"
	SubjectType string // sub_type: SubjectUser or SubjectService
	Audience    []string
	IssuedAt    time.Time
	NotBefore   time.Time
	Expiry      time.Time
	ID          string // jti
	Role        string // role: the one role this token was issued for
	// KeyThumbprint is cnf.jkt: the RFC 7638 thumbprint of the key the holder
	// must prove possession of on every request.
	KeyThumbprint string
}

type wireConfirmation struct {
	JKT string `json:"jkt"`
}

// wireClaims is the JSON shape of the claims. The date fields are pointers so
// that a verifier can tell an absent claim from the epoch.
type wireClaims struct {
	Iss     string            `json:"iss"`
	Sub     string            `json:"sub"`
	SubType string            `json:"sub_type,omitempty"`
	Aud     jwt.Audience      `json:"aud"`
	Iat     *jwt.NumericDate  `json:"iat"`
	Nbf     *jwt.NumericDate  `json:"nbf"`
	Exp     *jwt.NumericDate  `json:"exp"`
	Jti     string            `json:"jti"`
	Role    string            `json:"role"`
	Cnf     *wireConfirmation `json:"cnf"`
}

func (c Claims) wire() wireClaims {
	return wireClaims{
		Iss:     c.Issuer,
		Sub:     c.Subject,
		SubType: c.SubjectType,
		Aud:     jwt.Audience(c.Audience),
		Iat:     jwt.NewNumericDate(c.IssuedAt),
		Nbf:     jwt.NewNumericDate(c.NotBefore),
		Exp:     jwt.NewNumericDate(c.Expiry),
		Jti:     c.ID,
		Role:    c.Role,
		Cnf:     &wireConfirmation{JKT: c.KeyThumbprint},
	}
}

func (w wireClaims) claims() Claims {
	c := Claims{
		Issuer:      w.Iss,
		Subject:     w.Sub,
		SubjectType: w.SubType,
		Audience:    []string(w.Aud),
		ID:          w.Jti,
		Role:        w.Role,
	}
	if w.Iat != nil {
		c.IssuedAt = w.Iat.Time()
	}
	if w.Nbf != nil {
		c.NotBefore = w.Nbf.Time()
	}
	if w.Exp != nil {
		c.Expiry = w.Exp.Time()
	}
	if w.Cnf != nil {
		c.KeyThumbprint = w.Cnf.JKT
	}
	return c
}

// Issuer signs access tokens with one active key and publishes that key plus
// any number of additional verification keys. Publishing more keys than are
// used for signing is what makes rotation possible: relying services can pin
// the next key before it starts signing, and keep the previous one until its
// last token has expired.
type Issuer struct {
	issuer string
	signer jose.Signer
	keys   []VerificationKey // active key first
}

// NewIssuer builds an issuer. keyID names the signing key in each token's
// "kid" header; when empty it defaults to the key's RFC 7638 thumbprint, which
// is stable and needs no bookkeeping. additional lists further public keys to
// publish; they are never used for signing.
func NewIssuer(issuer string, key ed25519.PrivateKey, keyID string, additional ...VerificationKey) (*Issuer, error) {
	if issuer == "" {
		return nil, errors.New("issuer must not be empty")
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("signing key is not an Ed25519 private key")
	}
	pub := key.Public().(ed25519.PublicKey)
	if keyID == "" {
		keyID = Thumbprint(pub)
	}

	keys := []VerificationKey{{KeyID: keyID, Key: pub}}
	for _, k := range additional {
		if len(k.Key) != ed25519.PublicKeySize {
			return nil, errors.New("verification key is not an Ed25519 public key")
		}
		if k.KeyID == "" {
			k.KeyID = Thumbprint(k.Key)
		}
		duplicate := false
		for _, existing := range keys {
			if existing.KeyID != k.KeyID {
				continue
			}
			// The same key listed twice is harmless. Two different keys under
			// one kid would make verification ambiguous.
			if !bytes.Equal(existing.Key, k.Key) {
				return nil, fmt.Errorf("two different keys share the key id %q", k.KeyID)
			}
			duplicate = true
		}
		if !duplicate {
			keys = append(keys, k)
		}
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: key, KeyID: keyID}},
		(&jose.SignerOptions{}).WithType(TokenType),
	)
	if err != nil {
		return nil, err
	}
	return &Issuer{issuer: issuer, signer: signer, keys: keys}, nil
}

// Name returns the issuer identifier placed in "iss".
func (i *Issuer) Name() string { return i.issuer }

// KeyID returns the "kid" of the active signing key.
func (i *Issuer) KeyID() string { return i.keys[0].KeyID }

// Keys returns the published verification keys, active signing key first.
func (i *Issuer) Keys() []VerificationKey {
	return append([]VerificationKey(nil), i.keys...)
}

// JWKS returns the published key set as a JWK Set document.
func (i *Issuer) JWKS() []byte { return MarshalJWKS(i.keys) }

// TokenRequest describes one token to sign. The caller is responsible for
// having authorized every field; Issue only refuses requests that could not
// produce a well-formed token.
type TokenRequest struct {
	Subject     string
	SubjectType string
	Audience    string
	Role        string
	// Key is the holder's public key; its thumbprint becomes cnf.jkt.
	Key      ed25519.PublicKey
	Validity time.Duration
	// Now is the issuance time; the zero value means time.Now().
	Now time.Time

	id string // fixed jti, for reproducible test vectors only
}

// Issue signs an access token and returns it with the claims it carries.
func (i *Issuer) Issue(req TokenRequest) (string, Claims, error) {
	switch {
	case req.Subject == "":
		return "", Claims{}, errors.New("token subject must not be empty")
	case req.Audience == "":
		return "", Claims{}, errors.New("token audience must not be empty")
	case req.Role == "":
		return "", Claims{}, errors.New("token role must not be empty")
	case len(req.Key) != ed25519.PublicKeySize:
		return "", Claims{}, errors.New("token key must be an Ed25519 public key")
	case req.Validity <= 0:
		return "", Claims{}, errors.New("token validity must be positive")
	}

	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.Truncate(time.Second)

	id := req.id
	if id == "" {
		var err error
		if id, err = randomID(); err != nil {
			return "", Claims{}, err
		}
	}

	claims := Claims{
		Issuer:        i.issuer,
		Subject:       req.Subject,
		SubjectType:   req.SubjectType,
		Audience:      []string{req.Audience},
		IssuedAt:      now,
		NotBefore:     now,
		Expiry:        now.Add(req.Validity),
		ID:            id,
		Role:          req.Role,
		KeyThumbprint: Thumbprint(req.Key),
	}
	token, err := signCompact(i.signer, claims.wire())
	if err != nil {
		return "", Claims{}, err
	}
	return token, claims, nil
}

// ParseUnverified decodes a token's claims WITHOUT checking its signature. It
// exists for the client, which already trusts the channel the token arrived
// on and only wants to display or sanity-check what it was given. A relying
// service must use Verifier instead.
func ParseUnverified(token string) (Claims, error) {
	jws, err := jose.ParseSignedCompact(token, tokenAlgorithms)
	if err != nil {
		return Claims{}, fmt.Errorf("not a voussh access token: %w", err)
	}
	var wire wireClaims
	if err := json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &wire); err != nil {
		return Claims{}, fmt.Errorf("not a voussh access token: %w", err)
	}
	return wire.claims(), nil
}

// VerifySignature checks that a token was signed by one of keys and returns
// its claims. That is ALL it checks: not the audience, not expiry, not the
// proof of possession. It is for a client that wants to confirm a token it
// was just handed really comes from its issuer before storing it. It does
// not authenticate a request — a relying service must use Verifier.
func VerifySignature(token string, keys []VerificationKey) (Claims, error) {
	if len(token) > maxTokenSize || !canonicalCompact(token) {
		return Claims{}, ErrMalformedToken
	}
	jws, err := jose.ParseSignedCompact(token, tokenAlgorithms)
	if err != nil || len(jws.Signatures) != 1 {
		return Claims{}, ErrMalformedToken
	}
	header := jws.Signatures[0].Protected
	if !hasType(header, TokenType) || header.JSONWebKey != nil {
		return Claims{}, ErrMalformedToken
	}
	for _, key := range keys {
		if key.KeyID != header.KeyID {
			continue
		}
		payload, err := jws.Verify(key.Key)
		if err != nil {
			return Claims{}, ErrTokenSignature
		}
		var wire wireClaims
		if err := json.Unmarshal(payload, &wire); err != nil {
			return Claims{}, ErrMalformedToken
		}
		return wire.claims(), nil
	}
	return Claims{}, ErrUnknownKey.detail("kid %q", header.KeyID)
}

func signCompact(signer jose.Signer, payload any) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(body)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}

// randomID returns 128 bits of base64url-encoded entropy, used for jti.
func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
