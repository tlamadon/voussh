// Command secret-broker is a minimal relying service for voussh HTTP
// credentials. It exists to show the verification contract in running code:
// every request is authenticated offline, against a key set read from a local
// file at startup. The process never contacts voussh or the identity provider
// — run it with networking to both cut off and it behaves identically.
//
//	voussh jwks --config config.yaml > voussh-jwks.json
//	go run ./examples/secret-broker \
//	    --jwks voussh-jwks.json \
//	    --issuer https://auth.example.com \
//	    --audience secret-broker \
//	    --origin http://localhost:9000
//
// The secrets and the role policy below are hard-coded placeholders; a real
// broker would bring its own storage and its own authorization rules. What
// carries over unchanged is the first half of the handler.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/voussh/voussh/httpcred"
)

// secrets maps a name to its value and the roles allowed to read it. This is
// the broker's own policy: voussh says who the caller is and which role they
// were issued; what that role may do is decided here.
var secrets = map[string]struct {
	value string
	roles []string
}{
	"db-password":  {"correct horse battery staple", []string{"default", "admin"}},
	"root-api-key": {"k-live-0000", []string{"admin"}},
}

func main() {
	addr := flag.String("addr", "localhost:9000", "listen address")
	jwksPath := flag.String("jwks", "voussh-jwks.json", "pinned voussh verification keys (JWKS file)")
	issuer := flag.String("issuer", "", "expected token issuer (voussh's jwt.issuer)")
	audience := flag.String("audience", "secret-broker", "this service's audience name")
	origin := flag.String("origin", "http://localhost:9000", "scheme://host[:port] clients address this service by")
	flag.Parse()

	// The trust anchor is a file shipped with the service. Rotating voussh's
	// signing key means shipping a new file, on the broker's own schedule.
	raw, err := os.ReadFile(*jwksPath)
	if err != nil {
		log.Fatalf("read pinned keys: %v", err)
	}
	keys, err := httpcred.ParseJWKS(raw)
	if err != nil {
		log.Fatalf("parse pinned keys: %v", err)
	}
	verifier, err := httpcred.NewVerifier(httpcred.VerifierConfig{
		Issuer:   *issuer,
		Audience: *audience,
		Keys:     keys,
		Origin:   *origin,
	})
	if err != nil {
		log.Fatalf("configure verifier: %v", err)
	}

	http.HandleFunc("/v1/secrets/", func(w http.ResponseWriter, r *http.Request) {
		// Authentication: signature, issuer, audience, validity window, DPoP
		// proof, key binding, method/URL/token-hash binding, freshness and
		// replay — all inside this one call, all local.
		claims, err := verifier.VerifyHTTP(r)
		if err != nil {
			// The reason goes to the log, not to the caller.
			log.Printf("rejected %s %s: %v", r.Method, r.URL.Path, err)
			w.Header().Set("WWW-Authenticate", httpcred.AuthScheme)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		// Authorization: the broker's own rules, applied to the verified
		// identity and role.
		name := strings.TrimPrefix(r.URL.Path, "/v1/secrets/")
		secret, ok := secrets[name]
		if r.Method != http.MethodGet || !ok || !contains(secret.roles, claims.Role) {
			log.Printf("denied %s (%s, role %s): %s %s", claims.Subject, claims.SubjectType, claims.Role, r.Method, r.URL.Path)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}

		log.Printf("served %q to %s (%s, role %s, token %s)", name, claims.Subject, claims.SubjectType, claims.Role, claims.ID)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(map[string]string{"name": name, "value": secret.value})
	})

	log.Printf("secret-broker listening on %s (issuer %s, audience %s, %d pinned key(s))", *addr, *issuer, *audience, len(keys))
	log.Fatal(http.ListenAndServe(*addr, nil))
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}
