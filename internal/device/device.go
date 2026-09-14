// Package device implements the pending-request store behind voussh's device
// authorization flow.
//
// The flow is modelled on RFC 8628, but the "authorization server" is voussh
// itself rather than the upstream identity provider: the CLI polls voussh, and
// the browser that approves the request runs voussh's ordinary web login. That
// keeps the Google OAuth client type unchanged and keeps the flow usable with
// any identity provider voussh grows support for.
//
// A request moves through the states below and is removed from the store as
// soon as it reaches a terminal one, so a device code is never usable twice:
//
//	Pending ──(user enters code, completes IdP login)──▶ Authenticated
//	                                                      │
//	                            ┌─────────(approve)────────┤
//	                            ▼                          ▼ (deny)
//	                         Approved                    Denied
package device

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"time"
)

// Errors surfaced to a polling client. The first four map onto the error codes
// defined in RFC 8628 §3.5 and are returned to the CLI verbatim.
var (
	// ErrPending means nobody has approved the request yet.
	ErrPending = errors.New("authorization_pending")
	// ErrSlowDown means the client polled faster than the advertised interval.
	ErrSlowDown = errors.New("slow_down")
	// ErrExpired means the request outlived its TTL.
	ErrExpired = errors.New("expired_token")
	// ErrDenied means a user explicitly rejected the request.
	ErrDenied = errors.New("access_denied")
	// ErrNotFound means the code does not identify a live request. It is
	// deliberately indistinguishable from an expired-and-reaped request.
	ErrNotFound = errors.New("invalid_grant")

	// ErrFull means too many requests are already pending. It is a local
	// resource limit, not part of RFC 8628.
	ErrFull = errors.New("too many pending device requests")
	// ErrBadState means the request is not in a state that permits the
	// operation, e.g. approving something nobody has authenticated against.
	ErrBadState = errors.New("device request is not awaiting approval")
	// ErrBadToken means the approval token did not match.
	ErrBadToken = errors.New("invalid approval token")
)

// State is the position of a request in the flow.
type State int

const (
	// Pending: codes minted, nobody has entered the user code yet.
	Pending State = iota
	// Authenticated: a user entered the user code and completed the IdP
	// login, but has not yet confirmed the request.
	Authenticated
	// Approved: certificate signed, waiting for the CLI to collect it.
	Approved
	// Denied: a user explicitly rejected the request.
	Denied
)

func (s State) String() string {
	switch s {
	case Pending:
		return "pending"
	case Authenticated:
		return "authenticated"
	case Approved:
		return "approved"
	case Denied:
		return "denied"
	}
	return "unknown"
}

// userCodeAlphabet is the 20-consonant set recommended by RFC 8628 §6.1. It
// omits vowels so generated codes cannot spell words, and omits the digits and
// letters people confuse when transcribing by hand (0/O, 1/I/L).
const userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

// userCodeLen is the number of characters in a user code, excluding the
// separating dash. 20^8 is a little over 2^34, comfortably above the 20 bits
// of entropy RFC 8628 §5.1 asks for as a floor.
const userCodeLen = 8

// Request is one in-flight device authorization. Callers receive copies; the
// slice fields are never mutated after they are set, so sharing their backing
// arrays is safe.
type Request struct {
	// DeviceCode is the CLI's secret. It is never shown in a browser, so it
	// cannot leak through URLs, referrers or shoulder-surfing.
	DeviceCode string
	// UserCode is the short code the human transcribes.
	UserCode string

	// PubKey is the authorized_keys line the CLI wants signed, bound at
	// creation time. Fingerprint is its SSH fingerprint, shown on the approval
	// page so the approver can confirm the request came from their machine and
	// not from an attacker who phished them into approving it.
	PubKey      []byte
	Fingerprint string
	Role        string

	CreatedAt time.Time
	ExpiresAt time.Time
	State     State

	// Set once someone completes the IdP login against this request.
	Email      string
	Principals []string
	// ApprovalToken guards the approve/deny form. It is single-use and only
	// ever handed to the browser that authenticated, which both prevents CSRF
	// and stops a third party from approving a request they merely know the
	// user code for.
	ApprovalToken string

	// Cert is the signed certificate, set on approval.
	Cert []byte

	lastPoll time.Time
}

// Options configures a Store. Zero fields take the documented defaults.
type Options struct {
	// TTL is how long a request stays valid. Defaults to 10 minutes.
	TTL time.Duration
	// Interval is the minimum spacing between polls. Defaults to 5 seconds.
	Interval time.Duration
	// Max caps concurrent pending requests so an unauthenticated caller
	// cannot exhaust memory by minting codes. Defaults to 1024.
	Max int
	// Now is swappable in tests. Defaults to time.Now.
	Now func() time.Time
}

// Store holds in-flight device authorizations. It is safe for concurrent use.
//
// Requests live only in memory: a restart cancels everything in flight, which
// is the right trade for short-lived codes and avoids persisting material that
// can be replayed into a certificate.
type Store struct {
	mu       sync.Mutex
	byDevice map[string]*Request
	byUser   map[string]*Request

	ttl      time.Duration
	interval time.Duration
	max      int
	now      func() time.Time
}

// New builds a Store.
func New(opts Options) *Store {
	if opts.TTL <= 0 {
		opts.TTL = 10 * time.Minute
	}
	if opts.Interval <= 0 {
		opts.Interval = 5 * time.Second
	}
	if opts.Max <= 0 {
		opts.Max = 1024
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Store{
		byDevice: make(map[string]*Request),
		byUser:   make(map[string]*Request),
		ttl:      opts.TTL,
		interval: opts.Interval,
		max:      opts.Max,
		now:      opts.Now,
	}
}

// TTL reports how long newly created requests stay valid.
func (s *Store) TTL() time.Duration { return s.ttl }

// Interval reports the minimum poll spacing clients should honour.
func (s *Store) Interval() time.Duration { return s.interval }

// Len reports the number of live requests.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byDevice)
}

// Create mints a new request for the given public key. pubKey is the raw
// authorized_keys line and fingerprint its SSH fingerprint; the caller parses
// and validates the key so this package stays free of SSH specifics.
func (s *Store) Create(pubKey []byte, fingerprint, role string) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reaping here is enough to bound the map: entries only ever arrive
	// through Create, so no background goroutine is needed.
	s.reapLocked()

	if len(s.byDevice) >= s.max {
		return Request{}, ErrFull
	}

	now := s.now()
	req := &Request{
		PubKey:      pubKey,
		Fingerprint: fingerprint,
		Role:        role,
		CreatedAt:   now,
		ExpiresAt:   now.Add(s.ttl),
		State:       Pending,
	}

	// Collisions are vanishingly unlikely, but retry rather than let two live
	// requests share a code.
	for attempt := 0; ; attempt++ {
		if attempt == 10 {
			return Request{}, errors.New("device: could not allocate unique codes")
		}
		deviceCode, err := randomToken()
		if err != nil {
			return Request{}, err
		}
		userCode, err := randomUserCode()
		if err != nil {
			return Request{}, err
		}
		if _, taken := s.byDevice[deviceCode]; taken {
			continue
		}
		if _, taken := s.byUser[userCode]; taken {
			continue
		}
		req.DeviceCode, req.UserCode = deviceCode, userCode
		break
	}

	s.byDevice[req.DeviceCode] = req
	s.byUser[req.UserCode] = req
	return *req, nil
}

// Lookup resolves a user code typed by a human. The code is normalised first,
// so case and dash placement do not matter.
func (s *Store) Lookup(userCode string) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, err := s.liveByUserCodeLocked(userCode)
	if err != nil {
		return Request{}, err
	}
	return *req, nil
}

// Authenticate records the identity that completed the IdP login for a user
// code and issues the approval token for the confirmation form. It is safe to
// call twice — a browser reload re-issues the token — but not once the request
// has been approved or denied.
func (s *Store) Authenticate(userCode, email, role string, principals []string) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, err := s.liveByUserCodeLocked(userCode)
	if err != nil {
		return Request{}, err
	}
	if req.State != Pending && req.State != Authenticated {
		return Request{}, ErrBadState
	}

	token, err := randomToken()
	if err != nil {
		return Request{}, err
	}

	req.Email = email
	req.Role = role
	req.Principals = principals
	req.ApprovalToken = token
	req.State = Authenticated
	return *req, nil
}

// Prepare validates an approval token and returns the material needed to sign
// a certificate, without changing state. It lets a caller reject a bad token
// before doing any signing work.
func (s *Store) Prepare(userCode, approvalToken string) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, err := s.authenticatedLocked(userCode, approvalToken)
	if err != nil {
		return Request{}, err
	}
	return *req, nil
}

// Approve attaches the signed certificate and releases it to the polling
// client. The approval token must match the one issued by Authenticate.
func (s *Store) Approve(userCode, approvalToken string, cert []byte) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, err := s.authenticatedLocked(userCode, approvalToken)
	if err != nil {
		return Request{}, err
	}

	req.Cert = cert
	req.State = Approved
	// Burn the token so a replayed form submission cannot re-approve.
	req.ApprovalToken = ""
	return *req, nil
}

// Deny rejects a request. The polling client sees access_denied.
func (s *Store) Deny(userCode, approvalToken string) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, err := s.authenticatedLocked(userCode, approvalToken)
	if err != nil {
		return Request{}, err
	}

	req.State = Denied
	req.ApprovalToken = ""
	return *req, nil
}

// Poll is the client-facing half of the flow. On success it returns the
// approved request exactly once and drops it from the store; otherwise it
// returns one of the RFC 8628 error values.
func (s *Store) Poll(deviceCode string) (Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, ok := s.byDevice[deviceCode]
	if !ok {
		return Request{}, ErrNotFound
	}
	now := s.now()
	if !now.Before(req.ExpiresAt) {
		s.deleteLocked(req)
		return Request{}, ErrExpired
	}

	// RFC 8628 §3.5. Enforced here rather than trusting the client to behave.
	// A rejected poll deliberately does not refresh lastPoll: a client that is
	// only slightly early should recover on its next well-timed poll instead
	// of being locked out for as long as it keeps hammering.
	if !req.lastPoll.IsZero() && now.Sub(req.lastPoll) < s.interval {
		return Request{}, ErrSlowDown
	}
	req.lastPoll = now

	switch req.State {
	case Approved:
		out := *req
		// Collected exactly once — a replayed device code gets invalid_grant.
		s.deleteLocked(req)
		return out, nil
	case Denied:
		s.deleteLocked(req)
		return Request{}, ErrDenied
	default:
		return Request{}, ErrPending
	}
}

// liveByUserCodeLocked resolves a normalised user code to a request that has
// not expired. Callers must hold s.mu.
func (s *Store) liveByUserCodeLocked(userCode string) (*Request, error) {
	normalised := NormalizeUserCode(userCode)
	if normalised == "" {
		return nil, ErrNotFound
	}
	req, ok := s.byUser[normalised]
	if !ok {
		return nil, ErrNotFound
	}
	if !s.now().Before(req.ExpiresAt) {
		s.deleteLocked(req)
		return nil, ErrExpired
	}
	return req, nil
}

// authenticatedLocked resolves a request that is awaiting confirmation and
// checks the approval token. Callers must hold s.mu.
func (s *Store) authenticatedLocked(userCode, approvalToken string) (*Request, error) {
	req, err := s.liveByUserCodeLocked(userCode)
	if err != nil {
		return nil, err
	}
	if req.State != Authenticated {
		return nil, ErrBadState
	}
	if req.ApprovalToken == "" || subtle.ConstantTimeCompare([]byte(req.ApprovalToken), []byte(approvalToken)) != 1 {
		return nil, ErrBadToken
	}
	return req, nil
}

func (s *Store) deleteLocked(req *Request) {
	delete(s.byDevice, req.DeviceCode)
	delete(s.byUser, req.UserCode)
}

func (s *Store) reapLocked() {
	now := s.now()
	for _, req := range s.byDevice {
		if !now.Before(req.ExpiresAt) {
			s.deleteLocked(req)
		}
	}
}

// NormalizeUserCode canonicalises a hand-typed code to the "XXXX-XXXX" form
// used internally. It is case-insensitive and tolerant of missing, extra or
// misplaced dashes and whitespace. It returns "" if the input cannot be a user
// code, which also rejects anything containing characters outside the
// alphabet.
func NormalizeUserCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if r == '-' || r == ' ' || r == '\t' {
			continue
		}
		if !strings.ContainsRune(userCodeAlphabet, r) {
			return ""
		}
		b.WriteRune(r)
	}
	c := b.String()
	if len(c) != userCodeLen {
		return ""
	}
	return c[:userCodeLen/2] + "-" + c[userCodeLen/2:]
}

// randomUserCode returns a code in "XXXX-XXXX" form.
func randomUserCode() (string, error) {
	// 256 is not a multiple of 20, so a plain modulo would over-represent the
	// first 16 letters. Reject the short tail of the byte range instead.
	const limit = 256 - (256 % len(userCodeAlphabet)) // 240

	out := make([]byte, 0, userCodeLen)
	var buf [1]byte
	for len(out) < userCodeLen {
		if _, err := rand.Read(buf[:]); err != nil {
			return "", err
		}
		if int(buf[0]) >= limit {
			continue
		}
		out = append(out, userCodeAlphabet[int(buf[0])%len(userCodeAlphabet)])
	}
	return string(out[:userCodeLen/2]) + "-" + string(out[userCodeLen/2:]), nil
}

// randomToken returns 256 bits of base64url-encoded entropy.
func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
