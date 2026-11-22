package httpcred

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Error is a verification failure. Code is a stable machine-readable reason
// (the same strings appear in testdata/vectors.json); Detail is for logs.
// Match with errors.Is against the Err* values below.
//
// A relying service should log the error and answer 401 without echoing
// Detail to the caller.
type Error struct {
	Code   string
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Code
	}
	return e.Code + ": " + e.Detail
}

// Is makes errors.Is(err, ErrTokenExpired) match on the code alone.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

func (e *Error) detail(format string, args ...any) *Error {
	return &Error{Code: e.Code, Detail: fmt.Sprintf(format, args...)}
}

// Verification failures, in the order the checks run.
var (
	ErrMissingToken       = &Error{Code: "missing_token"}
	ErrMalformedToken     = &Error{Code: "malformed_token"}
	ErrUnknownKey         = &Error{Code: "unknown_key"}
	ErrTokenSignature     = &Error{Code: "invalid_token_signature"}
	ErrWrongIssuer        = &Error{Code: "wrong_issuer"}
	ErrWrongAudience      = &Error{Code: "wrong_audience"}
	ErrTokenExpired       = &Error{Code: "token_expired"}
	ErrTokenNotYetValid   = &Error{Code: "token_not_yet_valid"}
	ErrMissingProof       = &Error{Code: "missing_proof"}
	ErrMalformedProof     = &Error{Code: "malformed_proof"}
	ErrProofSignature     = &Error{Code: "invalid_proof_signature"}
	ErrKeyMismatch        = &Error{Code: "key_mismatch"}
	ErrMethodMismatch     = &Error{Code: "method_mismatch"}
	ErrURIMismatch        = &Error{Code: "uri_mismatch"}
	ErrTokenHashMismatch  = &Error{Code: "token_hash_mismatch"}
	ErrStaleProof         = &Error{Code: "stale_proof"}
	ErrProofReplayed      = &Error{Code: "proof_replayed"}
	ErrReplayCacheFull    = &Error{Code: "replay_cache_full"}
	errVerifierMisconfig  = errors.New("httpcred: verifier is misconfigured")
	errOriginNotSet       = errors.New("httpcred: VerifierConfig.Origin must be set to use VerifyHTTP")
	errInvalidRequestPath = errors.New("httpcred: request has no usable path")
)

// Size bounds applied before any parsing, so an oversized header costs
// nothing. A voussh token is about 500 bytes and a proof about 400.
const (
	maxTokenSize = 4096
	maxProofSize = 4096
	maxProofID   = 256
)

// VerifierConfig is everything a relying service needs to authenticate
// requests. All of it is local: there is no URL to fetch and no callback.
type VerifierConfig struct {
	// Issuer is the exact "iss" value to require.
	Issuer string
	// Audience is this service's own audience name; tokens issued for any
	// other audience are refused.
	Audience string
	// Keys are the pinned verification keys, typically ParseJWKS of a file
	// shipped with the service.
	Keys []VerificationKey

	// Origin is the scheme and authority clients address this service by,
	// e.g. "https://broker.example.com". VerifyHTTP combines it with the
	// request path to form the URL the proof must match. It is configured
	// rather than read from the request because the Host header — and, behind
	// a proxy, X-Forwarded-* — are chosen by the caller.
	Origin string

	// Leeway is the clock skew tolerated on exp, nbf and proof iat.
	// Defaults to 30 seconds.
	Leeway time.Duration
	// ProofMaxAge is how old a proof may be. Defaults to 60 seconds. Proofs
	// are remembered for this long, so it also sizes the replay cache.
	ProofMaxAge time.Duration
	// ReplayCacheSize bounds the number of proofs remembered at once.
	// Defaults to 65536. When the cache is full, new proofs are refused
	// (fail closed) until old entries expire.
	ReplayCacheSize int
	// ReplayPerSubject bounds how much of the cache one subject ("sub") may
	// occupy, so that a single caller sending requests as fast as it can
	// exhausts its own share and nobody else's. Defaults to an eighth of
	// ReplayCacheSize; with the default sizes that is about 130 requests per
	// second sustained by one identity.
	ReplayPerSubject int

	// Now is swappable in tests. Defaults to time.Now.
	Now func() time.Time
}

// Verifier authenticates requests carrying a voussh access token and a DPoP
// proof. It is safe for concurrent use and should be created once and shared:
// the replay cache lives inside it.
type Verifier struct {
	cfg    VerifierConfig
	keys   map[string]ed25519.PublicKey
	replay *replayCache
}

// NewVerifier validates the configuration and builds a Verifier.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, fmt.Errorf("%w: issuer and audience are required", errVerifierMisconfig)
	}
	if len(cfg.Keys) == 0 {
		return nil, fmt.Errorf("%w: at least one verification key is required", errVerifierMisconfig)
	}
	keys := make(map[string]ed25519.PublicKey, len(cfg.Keys))
	for _, k := range cfg.Keys {
		if k.KeyID == "" || len(k.Key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: every key needs a key id and an Ed25519 public key", errVerifierMisconfig)
		}
		if _, dup := keys[k.KeyID]; dup {
			return nil, fmt.Errorf("%w: duplicate key id %q", errVerifierMisconfig, k.KeyID)
		}
		keys[k.KeyID] = k.Key
	}
	if cfg.Origin != "" {
		origin, err := NormalizeURL(cfg.Origin)
		if err != nil || !strings.HasSuffix(origin, "/") || strings.Count(origin, "/") != 3 {
			return nil, fmt.Errorf("%w: origin must be scheme://host[:port] with no path", errVerifierMisconfig)
		}
		cfg.Origin = strings.TrimSuffix(origin, "/")
	}
	if cfg.Leeway <= 0 {
		cfg.Leeway = 30 * time.Second
	}
	if cfg.ProofMaxAge <= 0 {
		cfg.ProofMaxAge = 60 * time.Second
	}
	if cfg.ReplayCacheSize <= 0 {
		cfg.ReplayCacheSize = 65536
	}
	if cfg.ReplayPerSubject <= 0 {
		cfg.ReplayPerSubject = max(cfg.ReplayCacheSize/8, 1)
	}
	if cfg.ReplayPerSubject > cfg.ReplayCacheSize {
		cfg.ReplayPerSubject = cfg.ReplayCacheSize
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Verifier{
		cfg:    cfg,
		keys:   keys,
		replay: newReplayCache(cfg.ReplayCacheSize, cfg.ReplayPerSubject),
	}, nil
}

// Request is the part of an HTTP request that authentication depends on.
type Request struct {
	// Method is the HTTP method as received.
	Method string
	// URL is the absolute URL the client addressed. Query and fragment are
	// ignored.
	URL string
	// Authorization is the Authorization header value.
	Authorization string
	// DPoP holds every DPoP header value on the request. Exactly one is
	// required; the slice lets the verifier reject a request carrying two.
	DPoP []string
}

// VerifyHTTP authenticates an incoming request. It requires
// VerifierConfig.Origin.
func (v *Verifier) VerifyHTTP(r *http.Request) (Claims, error) {
	if v.cfg.Origin == "" {
		return Claims{}, errOriginNotSet
	}
	path := r.URL.EscapedPath()
	if !strings.HasPrefix(path, "/") {
		return Claims{}, errInvalidRequestPath
	}
	return v.Verify(Request{
		Method:        r.Method,
		URL:           v.cfg.Origin + path,
		Authorization: r.Header.Get("Authorization"),
		DPoP:          r.Header.Values("DPoP"),
	})
}

// Verify authenticates a request and returns the token's claims. On success
// the caller may rely on Subject, SubjectType and Role for its own
// authorization decision; on failure nothing in the request may be trusted.
//
// The checks, in order:
//
//  1. the Authorization header uses the DPoP scheme;
//  2. the token is a compact JWS signed with EdDSA by a pinned key;
//  3. iss and aud are the configured values;
//  4. the token is within exp/nbf, give or take Leeway;
//  5. exactly one DPoP proof is present, typed dpop+jwt, signed by the key
//     embedded in its own header;
//  6. that key's thumbprint equals the token's cnf.jkt;
//  7. the proof names this method and URL, and hashes this token;
//  8. the proof was created within ProofMaxAge;
//  9. the proof has not been seen before.
//
// A proof is recorded in the replay cache only after every other check has
// passed, so unauthenticated traffic cannot fill the cache.
func (v *Verifier) Verify(req Request) (Claims, error) {
	now := v.cfg.Now()

	token, err := tokenFromHeader(req.Authorization)
	if err != nil {
		return Claims{}, err
	}
	claims, err := v.verifyToken(token, now)
	if err != nil {
		return Claims{}, err
	}

	switch len(req.DPoP) {
	case 0:
		return Claims{}, ErrMissingProof
	case 1:
	default:
		return Claims{}, ErrMalformedProof.detail("%d DPoP headers, want exactly one", len(req.DPoP))
	}
	if err := v.verifyProof(req.DPoP[0], req, token, claims, now); err != nil {
		return Claims{}, err
	}
	return claims, nil
}

// tokenFromHeader extracts the token from "Authorization: DPoP <token>".
func tokenFromHeader(header string) (string, error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", ErrMissingToken
	}
	scheme, token, ok := strings.Cut(header, " ")
	token = strings.TrimSpace(token)
	if !ok || token == "" {
		return "", ErrMissingToken.detail("malformed Authorization header")
	}
	if !strings.EqualFold(scheme, AuthScheme) {
		// This is what stops a stolen token from being replayed as a plain
		// bearer token, sidestepping the proof entirely.
		return "", ErrMissingToken.detail("authorization scheme must be %s", AuthScheme)
	}
	return token, nil
}

func (v *Verifier) verifyToken(token string, now time.Time) (Claims, error) {
	if len(token) > maxTokenSize {
		return Claims{}, ErrMalformedToken.detail("token too large")
	}
	if !canonicalCompact(token) {
		return Claims{}, ErrMalformedToken.detail("not a canonical compact JWS")
	}
	// The allowlist is enforced here, at parse time: a token whose "alg" is
	// anything but EdDSA never reaches signature verification.
	jws, err := jose.ParseSignedCompact(token, tokenAlgorithms)
	if err != nil {
		return Claims{}, ErrMalformedToken.detail("%v", err)
	}
	if len(jws.Signatures) != 1 {
		return Claims{}, ErrMalformedToken.detail("want exactly one signature")
	}
	header := jws.Signatures[0].Protected
	if !hasType(header, TokenType) {
		return Claims{}, ErrMalformedToken.detail("typ must be %s", TokenType)
	}
	if header.JSONWebKey != nil {
		// The key comes from the pinned set, never from the token.
		return Claims{}, ErrMalformedToken.detail("token must not embed a key")
	}
	key, ok := v.keys[header.KeyID]
	if !ok {
		return Claims{}, ErrUnknownKey.detail("kid %q is not pinned", header.KeyID)
	}
	payload, err := jws.Verify(key)
	if err != nil {
		return Claims{}, ErrTokenSignature
	}

	var wire wireClaims
	if err := json.Unmarshal(payload, &wire); err != nil {
		return Claims{}, ErrMalformedToken.detail("%v", err)
	}
	if wire.Iss != v.cfg.Issuer {
		return Claims{}, ErrWrongIssuer.detail("iss %q", wire.Iss)
	}
	// Exactly this audience and no other. RFC 7519 would also accept a list
	// that merely includes it, but this issuer never signs such a token, and
	// a credential valid at several services at once is the thing audience
	// restriction exists to prevent.
	if len(wire.Aud) != 1 || wire.Aud[0] != v.cfg.Audience {
		return Claims{}, ErrWrongAudience.detail("aud %q", []string(wire.Aud))
	}
	if wire.Exp == nil {
		return Claims{}, ErrMalformedToken.detail("missing exp")
	}
	if !now.Before(wire.Exp.Time().Add(v.cfg.Leeway)) {
		return Claims{}, ErrTokenExpired.detail("expired at %s", wire.Exp.Time().UTC().Format(time.RFC3339))
	}
	if wire.Nbf != nil && now.Add(v.cfg.Leeway).Before(wire.Nbf.Time()) {
		return Claims{}, ErrTokenNotYetValid.detail("nbf is %s", wire.Nbf.Time().UTC().Format(time.RFC3339))
	}
	if wire.Iat != nil && now.Add(v.cfg.Leeway).Before(wire.Iat.Time()) {
		return Claims{}, ErrTokenNotYetValid.detail("iat is %s", wire.Iat.Time().UTC().Format(time.RFC3339))
	}
	if wire.Sub == "" || wire.Role == "" {
		return Claims{}, ErrMalformedToken.detail("missing sub or role")
	}
	if wire.Cnf == nil || wire.Cnf.JKT == "" {
		// An unbound token would be a plain bearer token; this issuer never
		// produces one, so refuse rather than fall back.
		return Claims{}, ErrMalformedToken.detail("missing cnf.jkt")
	}
	return wire.claims(), nil
}

func (v *Verifier) verifyProof(proof string, req Request, token string, claims Claims, now time.Time) error {
	if len(proof) > maxProofSize {
		return ErrMalformedProof.detail("proof too large")
	}
	if !canonicalCompact(proof) {
		return ErrMalformedProof.detail("not a canonical compact JWS")
	}
	jws, err := jose.ParseSignedCompact(proof, proofAlgorithms)
	if err != nil {
		return ErrMalformedProof.detail("%v", err)
	}
	if len(jws.Signatures) != 1 {
		return ErrMalformedProof.detail("want exactly one signature")
	}
	header := jws.Signatures[0].Protected
	if !hasType(header, ProofType) {
		return ErrMalformedProof.detail("typ must be %s", ProofType)
	}
	// The embedded key is parsed by this package's own strict parser, from
	// the header bytes as sent: exactly an Ed25519 public JWK with a 32-byte
	// x, and nothing that carries private or symmetric material.
	pub, err := proofKey(proof)
	if err != nil {
		return ErrMalformedProof.detail("jwk header: %v", err)
	}
	payload, err := jws.Verify(pub)
	if err != nil {
		return ErrProofSignature
	}

	// A valid signature only shows that whoever built the proof holds *some*
	// key. This comparison is the binding: it must be the key the token was
	// issued to.
	thumbprint := Thumbprint(pub)
	if subtle.ConstantTimeCompare([]byte(thumbprint), []byte(claims.KeyThumbprint)) != 1 {
		return ErrKeyMismatch
	}

	var pc proofClaims
	if err := json.Unmarshal(payload, &pc); err != nil {
		return ErrMalformedProof.detail("%v", err)
	}
	if pc.Jti == "" || len(pc.Jti) > maxProofID || pc.Iat == nil {
		return ErrMalformedProof.detail("missing or oversized jti, or missing iat")
	}
	if pc.Htm != req.Method {
		return ErrMethodMismatch.detail("htm %q, request %q", pc.Htm, req.Method)
	}
	want, err := NormalizeURL(req.URL)
	if err != nil {
		return ErrURIMismatch.detail("request URL: %v", err)
	}
	got, err := NormalizeURL(pc.Htu)
	if err != nil || got != want {
		return ErrURIMismatch.detail("htu %q, request %q", pc.Htu, want)
	}
	if subtle.ConstantTimeCompare([]byte(pc.Ath), []byte(TokenHash(token))) != 1 {
		return ErrTokenHashMismatch
	}

	issued := pc.Iat.Time()
	if age := now.Sub(issued); age > v.cfg.ProofMaxAge {
		return ErrStaleProof.detail("proof is %s old", age.Round(time.Second))
	} else if age < -v.cfg.Leeway {
		return ErrStaleProof.detail("proof is dated %s in the future", (-age).Round(time.Second))
	}

	// Remember the proof for exactly as long as it could still be accepted:
	// past that point the freshness check above rejects it on its own.
	until := issued.Add(v.cfg.ProofMaxAge).Add(time.Second)
	return v.replay.remember(claims.Subject, thumbprint, pc.Jti, until, now)
}

// canonicalCompact reports whether s is a compact JWS in its one canonical
// spelling: three segments of unpadded base64url with no stray characters and
// no unused trailing bits. Base64 decoders are forgiving in ways that let
// several different strings decode to the same signed bytes; refusing all but
// one keeps a token's text a stable identifier for it, which matters to
// anything that logs, hashes ("ath") or blocks tokens by their text.
func canonicalCompact(s string) bool {
	segments := strings.Split(s, ".")
	if len(segments) != 3 {
		return false
	}
	for _, segment := range segments {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(segment)
		// Comparing the re-encoding also rejects the CR and LF that the
		// decoder skips even in strict mode.
		if err != nil || base64.RawURLEncoding.EncodeToString(raw) != segment {
			return false
		}
	}
	return segments[0] != "" && segments[1] != ""
}

// proofKey extracts the public key from a proof's protected "jwk" header.
func proofKey(proof string) (ed25519.PublicKey, error) {
	header, err := base64.RawURLEncoding.DecodeString(proof[:strings.IndexByte(proof, '.')])
	if err != nil {
		return nil, err
	}
	var fields struct {
		JWK json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(header, &fields); err != nil {
		return nil, err
	}
	return ParsePublicJWK(fields.JWK)
}

// hasType reports whether a JOSE header's "typ" names the given media type.
// RFC 7515 §4.1.9 lets a sender omit the "application/" prefix and treats the
// value as case-insensitive.
func hasType(header jose.Header, want string) bool {
	typ, _ := header.ExtraHeaders[jose.HeaderType].(string)
	return strings.EqualFold(typ, want) || strings.EqualFold(typ, "application/"+want)
}

// replayCache remembers proofs until they would be rejected as stale anyway.
//
// It is bounded twice over. The total bound caps memory. The per-subject
// bound stops one authenticated caller from occupying the whole cache and
// locking every other caller out: a subject that fills its share is refused
// further requests until its own entries expire, while everyone else carries
// on. The quota is counted by subject rather than by key because one identity
// can hold tokens for any number of keys.
//
// At either bound the cache sweeps expired entries — at most once a second,
// so hitting a bound cannot be turned into a CPU sink — and otherwise refuses
// the proof. Refusing is the safe failure: the alternative, evicting a live
// entry, would let that proof be replayed.
type replayCache struct {
	mu         sync.Mutex
	seen       map[[sha256.Size]byte]replayEntry
	bySubject  map[string]int
	max        int
	perSubject int
	lastSweep  time.Time
}

type replayEntry struct {
	until   time.Time
	subject string
}

func newReplayCache(max, perSubject int) *replayCache {
	return &replayCache{
		seen:       make(map[[sha256.Size]byte]replayEntry),
		bySubject:  make(map[string]int),
		max:        max,
		perSubject: perSubject,
	}
}

func (c *replayCache) remember(subject, thumbprint, id string, until, now time.Time) error {
	// Proof ids are only unique per key, and hashing keeps every entry the
	// same size however long the client made its jti.
	key := sha256.Sum256([]byte(thumbprint + "\x00" + id))

	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.seen[key]; ok && now.Before(entry.until) {
		return ErrProofReplayed
	}
	if len(c.seen) >= c.max || c.bySubject[subject] >= c.perSubject {
		c.sweep(now)
	}
	if c.bySubject[subject] >= c.perSubject {
		return ErrReplayCacheFull.detail("subject %q has %d proofs outstanding", subject, c.bySubject[subject])
	}
	if len(c.seen) >= c.max {
		return ErrReplayCacheFull
	}
	if old, ok := c.seen[key]; ok {
		c.forget(key, old)
	}
	c.seen[key] = replayEntry{until: until, subject: subject}
	c.bySubject[subject]++
	return nil
}

// sweep drops expired entries, at most once a second.
func (c *replayCache) sweep(now time.Time) {
	if !c.lastSweep.IsZero() && now.Sub(c.lastSweep) < time.Second {
		return
	}
	c.lastSweep = now
	for key, entry := range c.seen {
		if !now.Before(entry.until) {
			c.forget(key, entry)
		}
	}
}

func (c *replayCache) forget(key [sha256.Size]byte, entry replayEntry) {
	delete(c.seen, key)
	if c.bySubject[entry.subject]--; c.bySubject[entry.subject] <= 0 {
		delete(c.bySubject, entry.subject)
	}
}
