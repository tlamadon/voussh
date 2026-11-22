package main

// A session credential: `vsh token login --local` keeps the token and its
// key in the calling shell's environment instead of on disk, the way
// `vsh login --local` keeps an SSH certificate there.
//
// The login generates a key that exists only for that one token. vsh prints
// two `export` lines on stdout for the shell to evaluate, and nothing else
// there — everything a human reads, including the device code, goes to
// stderr. Later commands find the credential in their environment.
//
// What that buys and what it costs: nothing is written under the config
// directory, and the session ends with the shell. In exchange the credential
// is in the environment of every process started from that shell, and
// readable by any other process of the same user.

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/tlamadon/voussh/httpcred"
	"github.com/tlamadon/voussh/internal/keyfile"
)

const (
	// envLocalToken holds the access token of a session credential.
	envLocalToken = "VSH_LOCAL_TOKEN"
	// envLocalTokenKey holds the base64 seed of the Ed25519 key that token
	// is bound to.
	envLocalTokenKey = "VSH_LOCAL_TOKEN_KEY"

	// tokenModeSession is the mode shown for a credential read back from the
	// environment, where how it was obtained is no longer known.
	tokenModeSession = "session"
)

// session reports whether the credential lives in the environment rather
// than on disk.
func (r *tokenRecord) session() bool { return r.key != nil }

// privateKey returns the key the token is bound to: the one held in memory
// for a session credential, otherwise the one on disk.
func (r *tokenRecord) privateKey() (ed25519.PrivateKey, error) {
	if r.key != nil {
		return r.key, nil
	}
	return keyfile.LoadPrivate(r.KeyPath)
}

// sessionLoginHint is the command that starts a new session for an audience.
func sessionLoginHint(audience string) string {
	return fmt.Sprintf("vsh token login --local --audience %s (add --device where there is no browser)", audience)
}

// sessionToken reads the session credential from the environment. It returns
// nil when the shell holds none. A credential that is present but unusable is
// an error rather than nil: silently falling back to a stored credential
// would use an identity the user did not expect.
func sessionToken() (*tokenRecord, error) {
	token, seed := os.Getenv(envLocalToken), os.Getenv(envLocalTokenKey)
	if token == "" && seed == "" {
		return nil, nil
	}
	// The reasons below never include the values themselves.
	unusable := func(reason string) error {
		return fmt.Errorf("the session credential in this shell is unusable (%s). Clear it with: unset %s %s",
			reason, envLocalToken, envLocalTokenKey)
	}
	if token == "" || seed == "" {
		return nil, unusable("only one of its two variables is set")
	}
	raw, err := base64.StdEncoding.DecodeString(seed)
	if err != nil || len(raw) != ed25519.SeedSize {
		return nil, unusable("the key is malformed")
	}
	key := ed25519.NewKeyFromSeed(raw)

	// Not verified: there is no issuer to ask, and the relying service checks
	// the signature on every request anyway. The claims are read to know
	// what the credential is, and whether it is worth sending.
	claims, err := httpcred.ParseUnverified(token)
	if err != nil || len(claims.Audience) != 1 {
		return nil, unusable("the token is malformed")
	}
	if claims.KeyThumbprint != httpcred.Thumbprint(key.Public().(ed25519.PublicKey)) {
		return nil, unusable("the token is not bound to the key")
	}
	return &tokenRecord{
		Audience:      claims.Audience[0],
		Role:          claims.Role,
		Subject:       claims.Subject,
		Issuer:        claims.Issuer,
		ExpiresAt:     claims.Expiry,
		KeyThumbprint: claims.KeyThumbprint,
		Mode:          tokenModeSession,
		AccessToken:   token,
		key:           key,
	}, nil
}

// sessionExports renders a session credential as the shell commands that
// install it. Both values are drawn from alphabets (base64url with dots,
// base64) that need no escaping inside single quotes.
func sessionExports(rec *tokenRecord) string {
	seed := base64.StdEncoding.EncodeToString(rec.key.Seed())
	return fmt.Sprintf("export %s='%s'\nexport %s='%s'\n", envLocalToken, rec.AccessToken, envLocalTokenKey, seed)
}

// sessionUnset is the shell command that ends a session.
func sessionUnset() string {
	return fmt.Sprintf("unset %s %s", envLocalToken, envLocalTokenKey)
}

// checkSessionOutput refuses to run a --local login whose stdout is a
// terminal. The exports are meant for a shell to evaluate; on a terminal they
// would put the token and its key on screen and in the scrollback. Refusing
// up front, rather than after the login, saves an approval that would have
// been thrown away.
func checkSessionOutput(stdout *os.File, args []string) error {
	if !isTerminal(stdout) {
		return nil
	}
	rerun := displayArgs(append([]string{"vsh", "token", "login"}, args...))
	return fmt.Errorf("--local hands the credential to your shell, so its output has to be evaluated, not displayed:\n\n"+
		"    eval \"$(%s)\"\n\n"+
		"With the shell function from `vsh init` installed, `vsh token login --local ...` does this for you.", rerun)
}

// sessionLoginServer picks the server for a --local login. Unlike an ordinary
// login it never asks and never remembers: saving the answer would be a write
// to the config directory.
func sessionLoginServer(explicit string) (string, error) {
	if explicit = normalizeServerURL(explicit); explicit != "" {
		return explicit, nil
	}
	if serverURL != "" {
		return serverURL, nil
	}
	return "", errors.New("no server configured. Use --server or set VSH_SERVER")
}

// hasSessionVariables reports whether the shell holds a session credential,
// usable or not.
func hasSessionVariables() bool {
	return os.Getenv(envLocalToken) != "" || os.Getenv(envLocalTokenKey) != ""
}

// explainSessionLogout tells the user how to end a session. vsh cannot do it
// for them: the variables belong to the parent shell.
func explainSessionLogout() {
	fmt.Fprintln(os.Stderr, "This shell holds a session token (from `vsh token login --local`).")
	fmt.Fprintln(os.Stderr, "It lives in the shell's environment, which vsh cannot change. End the session with either:")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "    eval \"$(vsh token logout --eval)\"")
	fmt.Fprintf(os.Stderr, "    %s\n", sessionUnset())
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "It also ends when the shell exits. The token itself stays valid until it expires.")
}

// sessionTargeted reports whether a logout with these flags is about the
// session credential rather than one on disk.
func sessionTargeted(audience string) bool {
	if !hasSessionVariables() {
		return false
	}
	// An unusable session cannot be matched against an audience, but it can
	// still be cleared, and should be reachable without flags.
	session, err := sessionToken()
	return audience == "" || err != nil || session.Audience == audience
}
