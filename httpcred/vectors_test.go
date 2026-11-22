package httpcred

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"
	"time"
)

// testdata/vectors.json is the language-neutral form of this package's
// verification rules: a relying service written in anything other than Go can
// load it and check its own verifier case by case. Regenerate it with
//
//	go test ./httpcred -run TestVectors -update
//
// Ed25519 signatures are deterministic and every time and identifier below is
// fixed, so regenerating without a code change reproduces the file exactly.
var updateVectors = flag.Bool("update", false, "rewrite testdata/vectors.json")

const vectorsPath = "testdata/vectors.json"

type vectorFile struct {
	Description string         `json:"description"`
	Verifier    vectorVerifier `json:"verifier"`
	Samples     vectorSamples  `json:"samples"`
	Cases       []vectorCase   `json:"cases"`
}

// vectorVerifier is the configuration every case is evaluated under.
type vectorVerifier struct {
	Issuer             string          `json:"issuer"`
	Audience           string          `json:"audience"`
	LeewaySeconds      int             `json:"leeway_seconds"`
	ProofMaxAgeSeconds int             `json:"proof_max_age_seconds"`
	JWKS               json.RawMessage `json:"jwks"`
}

// vectorSamples spells out one valid token and proof, decoded, for reading.
type vectorSamples struct {
	ClientPublicJWK     json.RawMessage `json:"client_public_jwk"`
	ClientJWKThumbprint string          `json:"client_jwk_thumbprint"`
	AccessToken         string          `json:"access_token"`
	AccessTokenHeader   json.RawMessage `json:"access_token_header"`
	AccessTokenClaims   json.RawMessage `json:"access_token_claims"`
	AccessTokenHash     string          `json:"access_token_hash"`
	DPoPProof           string          `json:"dpop_proof"`
	DPoPProofHeader     json.RawMessage `json:"dpop_proof_header"`
	DPoPProofClaims     json.RawMessage `json:"dpop_proof_claims"`
}

type vectorCase struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Now is the verifier's clock, in seconds since the epoch.
	Now           int64    `json:"now"`
	Method        string   `json:"method"`
	URL           string   `json:"url"`
	Authorization string   `json:"authorization"`
	DPoP          []string `json:"dpop"`
	// Times is how often the identical request is presented to one verifier
	// (default 1). Expect describes the last presentation; every earlier one
	// must be accepted.
	Times int `json:"times,omitempty"`
	// Expect is "ok" or the Code of the Error the request must fail with.
	Expect      string `json:"expect"`
	Subject     string `json:"subject,omitempty"`
	SubjectType string `json:"subject_type,omitempty"`
	Role        string `json:"role,omitempty"`
}

func decodeSegment(t *testing.T, jws string, index int) json.RawMessage {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(jws, ".")[index])
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// buildVectors constructs the vector file from the fixed test keys.
func buildVectors(t *testing.T) vectorFile {
	t.Helper()
	now := testNow
	current, previous := testKey("issuer"), testKey("issuer-previous")
	client, thief := testKey("client"), testKey("thief")
	clientPub := client.Public().(ed25519.PublicKey)

	// The pinned set holds two keys, as it does mid-rotation.
	issuer, err := NewIssuer(testIssuer, current, "", VerificationKey{Key: previous.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	previousIssuer, err := NewIssuer(testIssuer, previous, "")
	if err != nil {
		t.Fatal(err)
	}

	issue := func(by *Issuer, id string, adjust func(*TokenRequest)) string {
		req := TokenRequest{
			Subject: "alice@example.com", SubjectType: SubjectUser, Audience: testAudience, Role: "default",
			Key: clientPub, Validity: 15 * time.Minute, Now: now, id: "token-" + id,
		}
		if adjust != nil {
			adjust(&req)
		}
		token, _, err := by.Issue(req)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	prove := func(key ed25519.PrivateKey, id, token string, adjust func(*ProofParams)) string {
		params := ProofParams{Method: "GET", URL: testURL, AccessToken: token, Now: now, id: "proof-" + id}
		if adjust != nil {
			adjust(&params)
		}
		proof, err := NewProof(key, params)
		if err != nil {
			t.Fatal(err)
		}
		return proof
	}

	token := issue(issuer, "valid", nil)
	file := vectorFile{
		Description: "Verification test vectors for voussh HTTP credentials (EdDSA access token + RFC 9449 DPoP proof). " +
			"Configure a verifier from \"verifier\", set its clock to each case's \"now\", present the request, and compare the outcome with \"expect\". " +
			"All keys are throwaway test keys.",
		Verifier: vectorVerifier{
			Issuer: testIssuer, Audience: testAudience, LeewaySeconds: 30, ProofMaxAgeSeconds: 60,
			JWKS: json.RawMessage(bytes.TrimSpace(issuer.JWKS())),
		},
	}

	add := func(name, description, expect string, c vectorCase) {
		c.Name, c.Description, c.Expect = name, description, expect
		if c.Now == 0 {
			c.Now = now.Unix()
		}
		if c.Method == "" {
			c.Method = "GET"
		}
		if c.URL == "" {
			c.URL = testURL
		}
		if expect == "ok" && c.Subject == "" {
			c.Subject, c.SubjectType, c.Role = "alice@example.com", SubjectUser, "default"
		}
		file.Cases = append(file.Cases, c)
	}
	// request is the common shape: one token, one proof made for it.
	request := func(id, token string, key ed25519.PrivateKey, adjust func(*ProofParams)) vectorCase {
		return vectorCase{Authorization: "DPoP " + token, DPoP: []string{prove(key, id, token, adjust)}}
	}

	// --- accepted ---------------------------------------------------------
	validProof := prove(client, "valid", token, nil)
	add("valid", "A token from the active signing key with a matching proof.", "ok",
		vectorCase{Authorization: "DPoP " + token, DPoP: []string{validProof}})

	previousToken := issue(previousIssuer, "previous-key", nil)
	add("valid-previous-signing-key", "A token signed by the other pinned key, as happens mid-rotation.", "ok",
		request("previous-key", previousToken, client, nil))

	c := request("query", token, client, nil)
	c.URL = testURL + "?version=3"
	add("valid-query-ignored", "The request URL has a query string; htu is compared without it.", "ok", c)

	serviceToken := issue(issuer, "service", func(r *TokenRequest) {
		r.Subject, r.SubjectType, r.Role = "service:ci-runner", SubjectService, "deploy"
	})
	c = request("service", serviceToken, client, nil)
	c.Subject, c.SubjectType, c.Role = "service:ci-runner", SubjectService, "deploy"
	add("valid-service-identity", "A machine identity: sub_type is \"service\".", "ok", c)

	// --- token rejected ---------------------------------------------------
	parts := strings.Split(token, ".")
	payload := map[string]any{}
	if err := json.Unmarshal(decodeSegment(t, token, 1), &payload); err != nil {
		t.Fatal(err)
	}
	payload["role"] = "admin"
	altered, _ := json.Marshal(payload)
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(altered) + "." + parts[2]
	add("token-payload-tampered", "The role claim was changed after signing.", ErrTokenSignature.Code,
		request("tampered", tampered, client, nil))

	rogue, err := NewIssuer(testIssuer, testKey("rogue issuer"), "")
	if err != nil {
		t.Fatal(err)
	}
	add("token-unknown-key", "Correct claims, signed by a key that is not pinned.", ErrUnknownKey.Code,
		request("unknown-key", issue(rogue, "unknown-key", nil), client, nil))

	header := map[string]any{"alg": "EdDSA", "typ": TokenType, "kid": issuer.KeyID()}
	claims := json.RawMessage(decodeSegment(t, token, 1))
	forged := craftJWS(t, header, claims, edSigner(testKey("rogue issuer")))
	add("token-forged-under-pinned-kid", "Names a pinned kid but is signed by another key.", ErrTokenSignature.Code,
		request("forged", forged, client, nil))

	header["alg"] = "none"
	unsigned := craftJWS(t, header, claims, func([]byte) []byte { return nil })
	add("token-alg-none", "alg is \"none\" with an empty signature.", ErrMalformedToken.Code,
		request("alg-none", unsigned, client, nil))

	header["alg"] = "HS256"
	confused := craftJWS(t, header, claims, func(input []byte) []byte {
		mac := hmac.New(sha256.New, current.Public().(ed25519.PublicKey))
		mac.Write(input)
		return mac.Sum(nil)
	})
	add("token-alg-hs256-public-key", "alg is HS256, keyed with the issuer's public key (algorithm confusion).", ErrMalformedToken.Code,
		request("alg-hs256", confused, client, nil))

	otherIssuer, err := NewIssuer("https://auth.other.example", current, "")
	if err != nil {
		t.Fatal(err)
	}
	add("wrong-issuer", "Validly signed, but iss is not the expected issuer.", ErrWrongIssuer.Code,
		request("wrong-issuer", issue(otherIssuer, "wrong-issuer", nil), client, nil))

	wrongAud := issue(issuer, "wrong-audience", func(r *TokenRequest) { r.Audience = "billing-api" })
	add("wrong-audience", "Validly signed for a different service.", ErrWrongAudience.Code,
		request("wrong-audience", wrongAud, client, nil))

	expired := issue(issuer, "expired", func(r *TokenRequest) { r.Now = now.Add(-time.Hour) })
	add("token-expired", "exp is 45 minutes in the past.", ErrTokenExpired.Code,
		request("expired", expired, client, nil))

	future := issue(issuer, "not-yet-valid", func(r *TokenRequest) { r.Now = now.Add(10 * time.Minute) })
	add("token-not-yet-valid", "nbf is 10 minutes in the future.", ErrTokenNotYetValid.Code,
		request("not-yet-valid", future, client, nil))

	// --- proof rejected ---------------------------------------------------
	add("bearer-scheme", "A bound token presented as a bearer token.", ErrMissingToken.Code,
		vectorCase{Authorization: "Bearer " + token, DPoP: []string{prove(client, "bearer", token, nil)}})

	add("missing-proof", "No DPoP header at all.", ErrMissingProof.Code,
		vectorCase{Authorization: "DPoP " + token, DPoP: []string{}})

	add("proof-key-mismatch", "A stolen token with a well-formed proof from another key: cnf.jkt does not match.", ErrKeyMismatch.Code,
		request("key-mismatch", token, thief, nil))

	proofHeader := map[string]any{"alg": "EdDSA", "typ": ProofType, "jwk": publicJWKMap(clientPub)}
	proofPayload := map[string]any{
		"jti": "proof-bad-signature", "htm": "GET", "htu": testURL, "iat": now.Unix(), "ath": TokenHash(token),
	}
	add("proof-bad-signature", "The proof names the right key in its header but is signed by another.", ErrProofSignature.Code,
		vectorCase{Authorization: "DPoP " + token, DPoP: []string{craftJWS(t, proofHeader, proofPayload, edSigner(thief))}})

	c = request("method", token, client, nil)
	c.Method = "DELETE"
	add("method-mismatch", "A proof made for GET, replayed on a DELETE.", ErrMethodMismatch.Code, c)

	c = request("uri", token, client, nil)
	c.URL = testOrigin + "/v1/secrets/root-password"
	add("uri-mismatch", "A proof made for one path, replayed against another.", ErrURIMismatch.Code, c)

	otherToken := issue(issuer, "other", func(r *TokenRequest) { r.Role = "admin" })
	add("token-hash-mismatch", "A proof made for one token, presented with another issued to the same key.", ErrTokenHashMismatch.Code,
		vectorCase{Authorization: "DPoP " + otherToken, DPoP: []string{prove(client, "ath", token, nil)}})

	add("proof-stale", "The proof is two minutes old.", ErrStaleProof.Code,
		request("stale", token, client, func(p *ProofParams) { p.Now = now.Add(-2 * time.Minute) }))

	add("proof-from-the-future", "The proof is dated two minutes ahead.", ErrStaleProof.Code,
		request("future", token, client, func(p *ProofParams) { p.Now = now.Add(2 * time.Minute) }))

	c = request("replay", token, client, nil)
	c.Times = 2
	add("proof-replayed", "The identical request presented twice: the second is refused.", ErrProofReplayed.Code, c)

	file.Samples = vectorSamples{
		ClientPublicJWK:     MarshalPublicJWK(clientPub),
		ClientJWKThumbprint: Thumbprint(clientPub),
		AccessToken:         token,
		AccessTokenHeader:   decodeSegment(t, token, 0),
		AccessTokenClaims:   decodeSegment(t, token, 1),
		AccessTokenHash:     TokenHash(token),
		DPoPProof:           validProof,
		DPoPProofHeader:     decodeSegment(t, validProof, 0),
		DPoPProofClaims:     decodeSegment(t, validProof, 1),
	}
	return file
}

func marshalVectors(t *testing.T, file vectorFile) []byte {
	t.Helper()
	out, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

// TestVectorsAreCurrent fails when the checked-in file no longer matches what
// the code produces, so a change to the wire format cannot go unnoticed.
func TestVectorsAreCurrent(t *testing.T) {
	generated := marshalVectors(t, buildVectors(t))
	if *updateVectors {
		if err := os.MkdirAll("testdata", 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorsPath, generated, 0644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", vectorsPath)
		return
	}
	onDisk, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if !bytes.Equal(onDisk, generated) {
		t.Fatalf("%s is out of date; run: go test ./httpcred -run TestVectors -update", vectorsPath)
	}
}

// TestVectors evaluates the checked-in file exactly as a third-party
// implementation would: everything it needs comes from the JSON.
func TestVectors(t *testing.T) {
	if *updateVectors {
		t.Skip("updating")
	}
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	var file vectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	keys, err := ParseJWKS(file.Verifier.JWKS)
	if err != nil {
		t.Fatalf("vector JWKS: %v", err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("no cases")
	}

	covered := map[string]bool{}
	for _, c := range file.Cases {
		covered[c.Expect] = true
		t.Run(c.Name, func(t *testing.T) {
			// A fresh verifier per case: cases are independent, and only the
			// replay case relies on state carried between presentations.
			v, err := NewVerifier(VerifierConfig{
				Issuer:      file.Verifier.Issuer,
				Audience:    file.Verifier.Audience,
				Keys:        keys,
				Leeway:      time.Duration(file.Verifier.LeewaySeconds) * time.Second,
				ProofMaxAge: time.Duration(file.Verifier.ProofMaxAgeSeconds) * time.Second,
				Now:         func() time.Time { return time.Unix(c.Now, 0) },
			})
			if err != nil {
				t.Fatal(err)
			}
			req := Request{Method: c.Method, URL: c.URL, Authorization: c.Authorization, DPoP: c.DPoP}

			times := max(c.Times, 1)
			for i := 1; i < times; i++ {
				if _, err := v.Verify(req); err != nil {
					t.Fatalf("presentation %d of %d: %v", i, times, err)
				}
			}
			claims, err := v.Verify(req)
			if c.Expect == "ok" {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				if claims.Subject != c.Subject || claims.SubjectType != c.SubjectType || claims.Role != c.Role {
					t.Errorf("identity = %s/%s/%s, want %s/%s/%s",
						claims.Subject, claims.SubjectType, claims.Role, c.Subject, c.SubjectType, c.Role)
				}
				return
			}
			var verr *Error
			if err == nil {
				t.Fatalf("accepted; want %s", c.Expect)
			}
			if e, ok := err.(*Error); ok {
				verr = e
			}
			if verr == nil || verr.Code != c.Expect {
				t.Fatalf("error = %v, want %s", err, c.Expect)
			}
		})
	}

	// The file is only useful as a conformance suite if it exercises every
	// way a request can fail that does not depend on verifier-local state.
	for _, e := range []*Error{
		ErrMissingToken, ErrMalformedToken, ErrUnknownKey, ErrTokenSignature, ErrWrongIssuer, ErrWrongAudience,
		ErrTokenExpired, ErrTokenNotYetValid, ErrMissingProof, ErrProofSignature, ErrKeyMismatch,
		ErrMethodMismatch, ErrURIMismatch, ErrTokenHashMismatch, ErrStaleProof, ErrProofReplayed,
	} {
		if !covered[e.Code] {
			t.Errorf("no vector expects %s", e.Code)
		}
	}
}
