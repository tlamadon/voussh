package device

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeClock lets tests drive expiry and poll throttling without sleeping.
type fakeClock struct{ t time.Time }

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func newTestStore(t *testing.T, clock *fakeClock) *Store {
	t.Helper()
	return New(Options{TTL: 10 * time.Minute, Interval: 5 * time.Second, Now: clock.Now})
}

// mustCreate makes a request with a stand-in key; the store never parses it.
func mustCreate(t *testing.T, s *Store, role string) Request {
	t.Helper()
	req, err := s.Create([]byte("ssh-ed25519 AAAA test@host"), "SHA256:abc", role)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return req
}

// approve drives a request all the way to Approved.
func approve(t *testing.T, s *Store, req Request, email string, principals []string) Request {
	t.Helper()
	authed, err := s.Authenticate(req.UserCode, email, "default", principals)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	approved, err := s.Approve(req.UserCode, authed.ApprovalToken, []byte("cert-data"))
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	return approved
}

func TestUserCodeShape(t *testing.T) {
	clock := newFakeClock()
	s := newTestStore(t, clock)

	for i := 0; i < 200; i++ {
		req := mustCreate(t, s, "")
		if len(req.UserCode) != userCodeLen+1 {
			t.Fatalf("user code %q has length %d, want %d", req.UserCode, len(req.UserCode), userCodeLen+1)
		}
		if req.UserCode[userCodeLen/2] != '-' {
			t.Fatalf("user code %q is missing its separator", req.UserCode)
		}
		for _, r := range strings.ReplaceAll(req.UserCode, "-", "") {
			if !strings.ContainsRune(userCodeAlphabet, r) {
				t.Fatalf("user code %q contains %q, which is outside the alphabet", req.UserCode, r)
			}
		}
		// The device code must be long enough to be unguessable.
		if len(req.DeviceCode) < 40 {
			t.Fatalf("device code %q is suspiciously short", req.DeviceCode)
		}
	}
}

func TestNormalizeUserCode(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"WDJB-MJHT", "WDJB-MJHT"},
		{"wdjb-mjht", "WDJB-MJHT"},   // case-insensitive
		{"WDJBMJHT", "WDJB-MJHT"},    // dash optional
		{" wdjb mjht ", "WDJB-MJHT"}, // whitespace tolerated
		{"W-D-J-B-M-J-H-T", "WDJB-MJHT"},
		{"", ""},
		{"WDJB", ""},       // too short
		{"WDJB-MJHTX", ""}, // too long
		{"WDJB-MJHA", ""},  // 'A' is a vowel, outside the alphabet
		{"WDJB-MJH1", ""},  // digits are outside the alphabet
		{"WDJB_MJHT", ""},  // underscore is not a tolerated separator
		{"<script>xx", ""}, // junk
	}
	for _, tc := range tests {
		if got := NormalizeUserCode(tc.in); got != tc.want {
			t.Errorf("NormalizeUserCode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHappyPath(t *testing.T) {
	clock := newFakeClock()
	s := newTestStore(t, clock)

	req := mustCreate(t, s, "admin")
	if req.State != Pending {
		t.Fatalf("new request state = %v, want pending", req.State)
	}

	// The CLI polls while nobody has approved yet.
	if _, err := s.Poll(req.DeviceCode); !errors.Is(err, ErrPending) {
		t.Fatalf("Poll before approval = %v, want ErrPending", err)
	}

	approve(t, s, req, "alice@example.com", []string{"root", "admin"})

	clock.Advance(6 * time.Second)
	got, err := s.Poll(req.DeviceCode)
	if err != nil {
		t.Fatalf("Poll after approval: %v", err)
	}
	if string(got.Cert) != "cert-data" {
		t.Errorf("cert = %q, want %q", got.Cert, "cert-data")
	}
	if got.Email != "alice@example.com" {
		t.Errorf("email = %q, want alice@example.com", got.Email)
	}

	// The certificate is released exactly once.
	clock.Advance(6 * time.Second)
	if _, err := s.Poll(req.DeviceCode); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Poll = %v, want ErrNotFound", err)
	}
	if s.Len() != 0 {
		t.Errorf("store still holds %d requests", s.Len())
	}
}

func TestPollSlowDown(t *testing.T) {
	clock := newFakeClock()
	s := newTestStore(t, clock)
	req := mustCreate(t, s, "")

	// First poll is always allowed.
	if _, err := s.Poll(req.DeviceCode); !errors.Is(err, ErrPending) {
		t.Fatalf("first Poll = %v, want ErrPending", err)
	}
	// Too soon.
	clock.Advance(time.Second)
	if _, err := s.Poll(req.DeviceCode); !errors.Is(err, ErrSlowDown) {
		t.Fatalf("early Poll = %v, want ErrSlowDown", err)
	}
	// A rejected poll must not push the window out, so waiting out the
	// original interval is enough to recover.
	clock.Advance(4 * time.Second)
	if _, err := s.Poll(req.DeviceCode); !errors.Is(err, ErrPending) {
		t.Fatalf("Poll after interval = %v, want ErrPending", err)
	}
}

func TestExpiry(t *testing.T) {
	clock := newFakeClock()
	s := newTestStore(t, clock)
	req := mustCreate(t, s, "")

	clock.Advance(10*time.Minute + time.Second)

	if _, err := s.Poll(req.DeviceCode); !errors.Is(err, ErrExpired) {
		t.Fatalf("Poll after TTL = %v, want ErrExpired", err)
	}
	// Expired requests are dropped, so a repeat is indistinguishable from an
	// unknown code.
	if _, err := s.Poll(req.DeviceCode); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Poll after reap = %v, want ErrNotFound", err)
	}
	if _, err := s.Lookup(req.UserCode); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Lookup after reap = %v, want ErrNotFound", err)
	}
}

func TestExpiredRequestCannotBeApproved(t *testing.T) {
	clock := newFakeClock()
	s := newTestStore(t, clock)
	req := mustCreate(t, s, "")

	authed, err := s.Authenticate(req.UserCode, "alice@example.com", "default", []string{"root"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	clock.Advance(10*time.Minute + time.Second)

	if _, err := s.Approve(req.UserCode, authed.ApprovalToken, []byte("cert")); !errors.Is(err, ErrExpired) {
		t.Fatalf("Approve after TTL = %v, want ErrExpired", err)
	}
}

func TestDeny(t *testing.T) {
	clock := newFakeClock()
	s := newTestStore(t, clock)
	req := mustCreate(t, s, "")

	authed, err := s.Authenticate(req.UserCode, "alice@example.com", "default", []string{"root"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if _, err := s.Deny(req.UserCode, authed.ApprovalToken); err != nil {
		t.Fatalf("Deny: %v", err)
	}

	if _, err := s.Poll(req.DeviceCode); !errors.Is(err, ErrDenied) {
		t.Fatalf("Poll after deny = %v, want ErrDenied", err)
	}
	if s.Len() != 0 {
		t.Errorf("denied request was not dropped")
	}
}

func TestApprovalTokenRequired(t *testing.T) {
	clock := newFakeClock()
	s := newTestStore(t, clock)
	req := mustCreate(t, s, "")

	// Nothing may be approved before someone authenticates.
	if _, err := s.Approve(req.UserCode, "", []byte("cert")); !errors.Is(err, ErrBadState) {
		t.Fatalf("Approve while pending = %v, want ErrBadState", err)
	}

	if _, err := s.Authenticate(req.UserCode, "alice@example.com", "default", []string{"root"}); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	if _, err := s.Approve(req.UserCode, "wrong-token", []byte("cert")); !errors.Is(err, ErrBadToken) {
		t.Fatalf("Approve with wrong token = %v, want ErrBadToken", err)
	}
	// Still awaiting approval, not consumed by the failed attempt.
	if _, err := s.Poll(req.DeviceCode); !errors.Is(err, ErrPending) {
		t.Fatalf("Poll after failed approve = %v, want ErrPending", err)
	}
}

func TestApprovalTokenIsSingleUse(t *testing.T) {
	clock := newFakeClock()
	s := newTestStore(t, clock)
	req := mustCreate(t, s, "")

	authed, err := s.Authenticate(req.UserCode, "alice@example.com", "default", []string{"root"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if _, err := s.Approve(req.UserCode, authed.ApprovalToken, []byte("cert")); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	// Replaying the form must not re-approve.
	if _, err := s.Approve(req.UserCode, authed.ApprovalToken, []byte("cert2")); !errors.Is(err, ErrBadState) {
		t.Fatalf("replayed Approve = %v, want ErrBadState", err)
	}
}

func TestReAuthenticateInvalidatesOldToken(t *testing.T) {
	clock := newFakeClock()
	s := newTestStore(t, clock)
	req := mustCreate(t, s, "")

	first, err := s.Authenticate(req.UserCode, "alice@example.com", "default", []string{"root"})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	// A browser reload re-authenticates and reissues the token.
	second, err := s.Authenticate(req.UserCode, "alice@example.com", "default", []string{"root"})
	if err != nil {
		t.Fatalf("re-Authenticate: %v", err)
	}
	if first.ApprovalToken == second.ApprovalToken {
		t.Fatal("re-authentication reused the approval token")
	}
	if _, err := s.Approve(req.UserCode, first.ApprovalToken, []byte("cert")); !errors.Is(err, ErrBadToken) {
		t.Fatalf("Approve with stale token = %v, want ErrBadToken", err)
	}
}

func TestApprovedRequestCannotBeReAuthenticated(t *testing.T) {
	clock := newFakeClock()
	s := newTestStore(t, clock)
	req := mustCreate(t, s, "")
	approve(t, s, req, "alice@example.com", []string{"root"})

	// An attacker who knows the user code must not be able to re-open an
	// already-approved request and swap in their own identity.
	if _, err := s.Authenticate(req.UserCode, "mallory@example.com", "default", []string{"root"}); !errors.Is(err, ErrBadState) {
		t.Fatalf("Authenticate after approval = %v, want ErrBadState", err)
	}
}

func TestUnknownCodes(t *testing.T) {
	clock := newFakeClock()
	s := newTestStore(t, clock)

	if _, err := s.Poll("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Poll(unknown) = %v, want ErrNotFound", err)
	}
	if _, err := s.Lookup("WDJB-MJHT"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Lookup(unknown) = %v, want ErrNotFound", err)
	}
	if _, err := s.Lookup("not a code"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Lookup(malformed) = %v, want ErrNotFound", err)
	}
}

func TestMaxPending(t *testing.T) {
	clock := newFakeClock()
	s := New(Options{TTL: time.Minute, Max: 3, Now: clock.Now})

	for i := 0; i < 3; i++ {
		mustCreate(t, s, "")
	}
	if _, err := s.Create([]byte("k"), "fp", ""); !errors.Is(err, ErrFull) {
		t.Fatalf("Create beyond cap = %v, want ErrFull", err)
	}

	// Expired entries are reaped on the next Create, freeing capacity.
	clock.Advance(2 * time.Minute)
	if _, err := s.Create([]byte("k"), "fp", ""); err != nil {
		t.Fatalf("Create after expiry: %v", err)
	}
	if s.Len() != 1 {
		t.Errorf("store holds %d requests, want 1", s.Len())
	}
}

func TestLookupIsCaseInsensitive(t *testing.T) {
	clock := newFakeClock()
	s := newTestStore(t, clock)
	req := mustCreate(t, s, "")

	got, err := s.Lookup(strings.ToLower(strings.ReplaceAll(req.UserCode, "-", "")))
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.DeviceCode != req.DeviceCode {
		t.Error("Lookup returned a different request")
	}
}

func TestLimiter(t *testing.T) {
	clock := newFakeClock()
	l := NewLimiter(3, 10*time.Second, clock.Now)

	for i := 0; i < 3; i++ {
		if !l.Allow("10.0.0.1") {
			t.Fatalf("attempt %d denied while burst remained", i+1)
		}
	}
	if l.Allow("10.0.0.1") {
		t.Fatal("burst was not enforced")
	}
	// A different caller has its own bucket.
	if !l.Allow("10.0.0.2") {
		t.Fatal("limiter is not keyed per caller")
	}
	// One token comes back per refill period.
	clock.Advance(10 * time.Second)
	if !l.Allow("10.0.0.1") {
		t.Fatal("token was not replenished")
	}
	if l.Allow("10.0.0.1") {
		t.Fatal("more than one token was replenished")
	}
}
