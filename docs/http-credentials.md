# HTTP credentials

voussh issues two kinds of credential from the same login:

| | SSH certificate | HTTP credential |
|---|---|---|
| For | `sshd` | any HTTP service ("relying service", "broker") |
| Format | OpenSSH user certificate | JWT access token, `alg: EdDSA` |
| Signed by | `ca_key` | `jwt.signing_key` (a different key) |
| Bound to | the user's SSH key | the client's key, via `cnf.jkt` + DPoP |
| Says | which principals | which audience, which one role |
| Verified by | `TrustedUserCAKeys` | a locally pinned public key |

Both are verified **offline**: the party checking the credential needs voussh's
public key and nothing else. It never calls voussh or Google.

This document covers how issuance fits into voussh, the token format, the
configuration, and — in [the verification contract](#offline-verification-contract)
— exactly what a relying service must check.

- [How it fits into voussh](#how-it-fits-into-voussh)
- [The token](#the-token)
- [Server configuration](#server-configuration)
- [Issuance flows](#issuance-flows)
- [Verification keys: publishing, pinning, rotating](#verification-keys-publishing-pinning-rotating)
- [The client: `vsh token` and `vsh http`](#the-client-vsh-token-and-vsh-http)
- [Offline verification contract](#offline-verification-contract)
- [Test vectors](#test-vectors)
- [Limitations](#limitations)

## How it fits into voussh

### What was already there

| Concern | Where it lives |
|---|---|
| **Identity.** Google OIDC: `/login` redirects to Google; `/callback` exchanges the code, verifies the ID token and reads the `email` claim. | `handleLogin`, `handleCallback` in `cmd/voussh/main.go` |
| **Roles.** `users: email -> role -> [principals]`. A requested role (default `default`) must be one the user holds. | `resolveRole` / `resolvePrincipals` in `cmd/voussh/main.go` |
| **Browser issuance.** The request rides the OAuth `state` parameter; the callback signs and redirects the result to `vsh`'s listener on `localhost`. Nothing is stored server-side. | `handleCallback` |
| **Device issuance.** An RFC 8628-shaped flow where voussh itself is the authorization server: `vsh` gets a device code and a user code, a human enters the user code in any browser, signs in, and confirms on an approval page; `vsh` polls for the result. Pending requests live in memory. | `cmd/voussh/device.go`, `internal/device` |
| **Signing.** `signPolicyCertificate` builds an `ssh.Certificate` and signs it with the CA key loaded at startup. | `cmd/voussh/main.go` |
| **Machine credentials.** `POST /sign`: a pre-shared bearer token (compared as a SHA-256 digest, in constant time) identifies an entry under `services:` and yields a certificate for that entry's principals. | `cmd/voussh/service.go` |
| **Client.** `vsh login` runs the browser or device flow and writes `~/.ssh/id_ed25519-cert.pub` (or exports it into the shell for `--local`); `vsh renew` calls `/sign`. | `cmd/vsh` |

### What changed

The design goal was the smallest change that adds a second credential format
without forking any of the above.

**Identity and role membership are shared; everything after that is separate.**
Each flow already had one point where it turned "verified email + role" into a
signed certificate. That point now branches on what was asked for:

```
                       ┌─ certificate ─ resolvePrincipals ─ signCertificate   (unchanged)
verified identity ─────┤
                       └─ token ─────── authorizeUserJWT ── issueJWT          (new)
```

- `resolveRole` — "does this user hold this role?" — is the single function
  both branches call. `resolvePrincipals` is now a thin wrapper that
  additionally requires the role to carry principals; the token branch does
  not, because SSH principals are not HTTP permissions.
- A request is a token request if it names an `audience`. Requests that do
  not are handled exactly as before, byte for byte: same parameters, same
  `state`, same responses.
- `internal/device` gained a `Kind` and an `Audience` on each pending request.
  The store itself stays format-agnostic — it carries opaque key and
  credential bytes.
- Everything specific to tokens — policy, keys, authorization, the three
  token-only endpoints — is in one file, `cmd/voussh/jwt.go`.
- The token format, DPoP proofs and the reference verifier are in the
  importable package `httpcred`, which performs no I/O and knows nothing
  about voussh's config. Server, client and relying services each use a
  different part of it.

Adding a third credential format later means: a new `device.Kind`, a new
branch at the same three points, and a file like `jwt.go`.

**No new state.** There is no database, no session store and no token
registry. The one piece of state the browser flow needed — remembering what
the user was shown between the confirmation page and the click — travels
through the browser inside an HMAC, keyed by a value derived from the signing
key, so it works across restarts and replicas.

**No OAuth authorization server.** voussh does not gain client registration,
scopes, refresh tokens or an introspection endpoint. A token is obtained the
way a certificate is: by logging in again.

### New endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/.well-known/jwks.json` | GET | Public verification keys |
| `/login/approve` | POST | Browser flow: the user confirms or rejects a token request |
| `/token` | POST | Machine identities: service token in, access token out |

`/login`, `/callback`, `/device/code`, `/device`, `/device/approve` and
`/device/token` are the existing endpoints; they accept token requests in
addition to certificate requests.

All of this is absent — the new endpoints return 404 — unless the config has a
`jwt:` block.

## The token

A compact JWS. Header:

```json
{ "alg": "EdDSA", "typ": "at+jwt", "kid": "bRqsG43ZHkEYuHn0iTswlvwHGuRSKH2yzktN8saTFsc" }
```

Claims:

```json
{
  "iss": "https://auth.example.com",
  "sub": "alice@example.com",
  "sub_type": "user",
  "aud": "secret-broker",
  "iat": 1790000000,
  "nbf": 1790000000,
  "exp": 1790000900,
  "jti": "mj2KyrQSOhzEEt5ItLDbcQ",
  "role": "default",
  "cnf": { "jkt": "ggnw6G5DgAodPO-A8-gXCtFmFImXop9r5MIZ2AIXInE" }
}
```

| Claim | Value | Source |
|---|---|---|
| `iss` | `jwt.issuer` | server config |
| `sub` | the verified Google email, or `service:<name>` for a machine identity | the login, or the authenticated service |
| `sub_type` | `user` or `service` | which flow issued it |
| `aud` | one audience name | requested by the client, accepted only if it is a key of `jwt.audiences` |
| `iat`, `nbf` | issuance time | server clock |
| `exp` | `iat` + validity | server config |
| `jti` | 128 random bits | server |
| `role` | exactly one role | requested by the client, accepted only if policy allows it (below) |
| `cnf.jkt` | RFC 7638 SHA-256 thumbprint of the client's public key | computed by the server from the submitted JWK |

There are exactly these ten claims. **No claim is copied from the request.**
A client chooses *which* configured audience and *which* of its own roles; it
supplies a public key. Everything else — and the decision on those three — is
the server's. The machine endpoint rejects a request body containing any
field other than `audience`, `role` and `jwk`.

The token carries **no SSH principals**. `role` is a name the relying service
interprets under its own policy; what `admin` may do at the secret broker is
the secret broker's decision, and has nothing to do with what the SSH role
`admin` maps to.

`sub` is the email because that is the identifier voussh's own `users` map is
keyed on. A machine identity can never collide with a user: its subject always
starts with `service:` and its `sub_type` is `service`.

The token is **sender-constrained**. On its own it authenticates nothing: every
request must also carry a DPoP proof signed by the key named in `cnf.jkt`. See
[the contract](#offline-verification-contract).

## Server configuration

```yaml
jwt:
  # "iss" claim. Relying services require this exact string.
  issuer: "https://auth.example.com"

  # Ed25519 private key that signs tokens. Deliberately NOT ca_key: the two
  # are separate trust domains, and compromising or rotating one must not
  # affect the other. Generate with `voussh jwt-init`.
  signing_key: "/etc/voussh/jwt_ed25519"

  # Optional "kid" for the signing key. Defaults to the key's RFC 7638
  # thumbprint, which is stable and needs no bookkeeping.
  # key_id: "2026-11"

  # Optional token lifetime. Default 15m; values above 24h are rejected.
  validity: 15m

  # Optional: further PUBLIC keys to publish in the JWKS without signing
  # with them. Used during rotation (see below). Each is an OpenSSH
  # "ssh-ed25519 ..." line or a JWK.
  # verification_keys:
  #   - key: "/etc/voussh/jwt_ed25519_previous.pub"
  #     key_id: "2026-10"        # optional; defaults to the thumbprint

  # The complete list of services tokens can be issued for.
  audiences:
    secret-broker:
      # Roles a user may obtain a token for. The user must ALSO hold the
      # role in the top-level `users` map.
      allowed_roles: [default, admin]

      # Optional: machine identities (entries of the top-level `services`
      # map) and the roles each may request.
      services:
        ci-runner: [deploy]

      # Optional per-audience lifetime; same 24h ceiling.
      # validity: 5m
```

### Who can get what

A **user** gets a token for audience *A* in role *R* only if all of these hold:

1. *A* is a key of `jwt.audiences`. There is no wildcard and no default
   audience; names are compared exactly.
2. The user holds *R* in the top-level `users` map (`R` defaults to `default`,
   as for SSH).
3. *R* is listed in `jwt.audiences.A.allowed_roles`.

Rule 2 is the existing user-to-role mapping, reused as is. Rule 3 is what
keeps the two protocols apart: holding the SSH role `deploy` gives no access
to an audience that does not list `deploy`.

A role can exist purely for HTTP. Map it to an empty principal list and SSH
will refuse it while tokens work:

```yaml
users:
  alice@example.com:
    default: [alice]     # SSH and, where allowed, HTTP
    secrets-reader: []   # HTTP only: `vsh login --role secrets-reader` is refused
```

A **service** gets a token only if `jwt.audiences.A.services` names it, for one
of the roles listed there. `allowed_roles` does not apply to services, and a
service's SSH `principals` confer nothing. The `role` may be omitted when
exactly one is granted.

A service that exists only to request tokens needs no `principals`:

```yaml
services:
  ci-runner:
    token_sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    # no principals: POST /sign answers 403 for this service
```

Config validation refuses a grant that names an unknown service, an audience
that grants nothing to anyone, and a service that could obtain neither a
certificate nor a token.

### Strictness

Unlike the rest of the config file, the `jwt:` block rejects keys it does not
know. A misspelt `validity` or `allowed_roles` stops the server from starting
(or the reload from applying) instead of being skipped — skipping would
quietly leave tokens on a longer default lifetime, or an audience with the
wrong roles. The loader also refuses a `signing_key` or verification key that
is the SSH CA key.

### Lifetime

15 minutes by default, configurable globally and per audience, capped at 24
hours. The cap is enforced when the config is loaded: a longer value is a
startup (or reload) error, not a silent clamp.

The lifetime is the revocation window — see [Limitations](#limitations). Prefer
minutes for humans' interactive use and let machine identities renew
automatically.

### Reload

The whole `jwt:` block is hot-reloaded with the rest of the config, **keys
included**: a reload re-reads `signing_key` and `verification_keys`, and swaps
policy and keys together. If the new block is invalid or a key cannot be read,
the reload is rejected and the previous config stays in force.

## Issuance flows

In every flow the client generates (or selects) an Ed25519 key pair, keeps the
private key, and submits only the public key, as a JWK:

```json
{ "kty": "OKP", "crv": "Ed25519", "x": "Z6PFhe-Jz2bZDr71mAtkdx0FiwxbKMBjyxJiT6_gpA8" }
```

A JWK containing private material (`d`, or a symmetric `k`) is rejected.
Ed25519 is the only key type accepted.

### Browser

```
vsh token login --audience secret-broker
```

1. `vsh` listens on a random `localhost` port and opens
   `/login?audience=…&jwk=…&role=…&cli_port=…&cli_state=…`.
2. voussh validates the request (the audience must be configured; the port
   must be a number) and redirects to Google, carrying the request in `state`.
3. Google returns to `/callback`. voussh verifies the ID token, then applies
   the rules above. If the user is not authorized, the browser is sent back
   to `vsh` with the reason.
4. Otherwise voussh shows a **confirmation page**: who you are, the
   **audience**, the role, the lifetime and the key thumbprint. Nothing has
   been signed yet.
5. On *Approve*, `/login/approve` re-checks authorization against the current
   config, signs the token and redirects it to `vsh`'s listener. On *Reject*,
   `vsh` is told and exits.

The confirmation form is valid for five minutes and is not single-use: the
server keeps no record of it, so the same browser could submit it again
within that time and receive another token for the same identity, audience,
role and key. That extends nothing but the expiry, by at most those five
minutes.

The confirmation page is the one step the certificate flow does not have.
Without it, a user who is already signed in to Google would mint a token for
any audience named in a link they clicked, without ever seeing which.

`vsh` prints the audience and key thumbprint the page should show, so you can
tell your own request from one somebody sent you.

### Device

```
vsh token login --audience secret-broker --device
```

The existing device flow, with `audience` and `jwk` in place of `pubkey` on
`/device/code`. The approval page shows the audience, role, lifetime and key
thumbprint instead of principals and an SSH fingerprint. Authorization is
checked when the user signs in and again when they click *Approve*.
`/device/token` answers with:

```json
{
  "access_token": "eyJhbGciOiJFZERTQSIs…",
  "token_type": "DPoP",
  "expires_in": 900,
  "audience": "secret-broker",
  "role": "default",
  "subject": "alice@example.com"
}
```

### Machine

```
vsh token login --audience secret-broker --role deploy \
    --service-token-file /var/lib/ci/voussh-token
```

or directly:

```bash
curl --fail https://auth.example.com/token \
  -H "Authorization: Bearer $(cat /var/lib/ci/voussh-token)" \
  -H "Content-Type: application/json" \
  -d '{"audience":"secret-broker","role":"deploy","jwk":{"kty":"OKP","crv":"Ed25519","x":"…"}}'
```

`POST /token` reuses the *authentication* of `/sign` — the same bearer token,
the same `services` entry, the same constant-time digest comparison — and none
of its *authorization*. Being able to obtain certificates through `/sign`
grants no tokens; only `jwt.audiences.<aud>.services` does. The response has
the same shape as the device flow's.

As with `/sign`, the service token is a standing capability: keep `/token` off
the public internet.

## Verification keys: publishing, pinning, rotating

### Publishing

```
GET /.well-known/jwks.json
```

```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "7n7fpGdVP5XCkQTMMXGrnD6IcuGs2dwkyIGd1d8VF3w",
      "kid": "bRqsG43ZHkEYuHn0iTswlvwHGuRSKH2yzktN8saTFsc",
      "alg": "EdDSA",
      "use": "sig"
    }
  ]
}
```

The active signing key is listed first, followed by any `verification_keys`.
The document is assembled from public keys only.

### Pinning

A relying service does not fetch this URL at runtime. It ships a copy.

On the voussh host, with no server running and no network:

```bash
voussh jwks --config /etc/voussh/config.yaml > voussh-jwks.json
```

(or `curl https://auth.example.com/.well-known/jwks.json`, once, from a
machine you trust to reach the real server). Deploy `voussh-jwks.json` with
the service, like any other trust anchor — a CA bundle, an
`authorized_keys` file — and load it at startup. From then on the service
needs nothing from voussh.

Pinning makes the service immune to anything that happens to voussh's HTTP
endpoint, DNS or TLS after the pin. The price is that key rotation is a
deployment on the relying side, which is why rotation is done in overlapping
steps.

### Rotating

One key signs; several may be published. A rotation never leaves a moment
where a valid token fails to verify:

1. **Announce.** Generate the new key (`voussh jwt-init /etc/voussh/jwt_ed25519_next`)
   and add its public half to `verification_keys`. voussh still signs with the
   old key but publishes both.
2. **Distribute.** Re-export the JWKS and roll it out to every relying
   service. They now accept both keys.
3. **Switch.** Set `signing_key` to the new key and move the old public key to
   `verification_keys`. New tokens carry the new `kid`; old ones remain valid.
4. **Retire.** Once the longest configured `validity` has passed since the
   switch, remove the old key from `verification_keys` and, at the next
   convenient deployment, from the pinned files.

Each step is a config edit picked up by the live reload.

If the old key is **compromised**, skip the overlap: switch immediately and
remove it from every pinned file as fast as you can deploy. Until a service
has dropped the key, tokens forged with it are accepted there.

## The client: `vsh token` and `vsh http`

```bash
vsh token login --audience secret-broker [--role admin] [--device] [--server URL]
vsh token login --local ...      # this shell only: nothing written to disk (see below)
vsh token status                 # audience, identity, role, expiry — never the token
vsh token renew                  # repeat the same login
vsh token logout [--all]
vsh http https://broker.example.com/v1/secrets/db-password
```

Paths below are relative to vsh's config directory: `~/.config/voussh` on
Linux, `~/Library/Application Support/voussh` on macOS.

**Key.** The first login generates an Ed25519 key at
`~/.config/voussh/http_ed25519` (mode 0600), used for all audiences. `--key`
selects another unencrypted Ed25519 key in OpenSSH or PKCS#8 format. The
private key is read locally to sign proofs and is never transmitted.

**Storage.** One file per audience under `~/.config/voussh/tokens/` (directory
0700, files 0600, written atomically). A new login for an audience replaces
the previous token. The record remembers how the token was obtained so that
`vsh token renew` can repeat it; for a machine identity it stores the *path*
of the service token, not its contents.

**What `vsh` accepts.** Before storing a token, `vsh` fetches the server's
JWKS and checks that the token is signed by it, bound to the local key, for
the requested audience and unexpired. This is not a substitute for the
relying service's verification; it ensures that whatever reaches `vsh` —
notably through the browser flow's `localhost` listener — is a real token
from that server.

**Renewal.** There are no refresh tokens: renewing is logging in again, with
the same key, through the same flow. A renewal must come back for the same
identity as the credential it replaces; if it does not, `vsh` refuses it and
keeps the old one (use `vsh token login` to switch identity on purpose). For a machine identity that needs no
human, so `vsh http` (and `print`, `proof`) renew an expired token
transparently. For a browser or device login they stop and tell you to run
`vsh token renew`.

**Session-only credentials (`--local`).** On a machine where nothing should be
left behind — no SSH key of yours on it, a borrowed host, a throwaway
container — `--local` keeps the credential in the current shell instead of on
disk. It is the counterpart of `vsh login --local` and works the same way:

```bash
eval "$(vsh init)"      # the vsh shell function; once per shell, or in your profile
vsh token login --local --device --server https://auth.example.com --audience secret-broker
vsh http https://broker.example.com/v1/secrets/db-password
vsh token logout        # or simply close the shell
```

Without the shell function, the login is
`eval "$(vsh token login --local …)"` and the logout is
`eval "$(vsh token logout --eval)"`.

What happens:

- `vsh` generates a new Ed25519 key for this login. It is used for this one
  token and never again.
- After approval, `vsh` prints two `export` lines on stdout and the shell
  evaluates them: `VSH_LOCAL_TOKEN` (the access token) and
  `VSH_LOCAL_TOKEN_KEY` (the key). Stdout carries nothing else; the device
  code and every other message go to stderr, so they stay on screen while
  stdout is being captured.
- Nothing is written to disk: no key, no token, no server history, not even
  the config directory. For the same reason a `--local` login never asks
  which server to use or remembers one — pass `--server`, or have
  `VSH_SERVER` or a saved server already.
- If stdout is a terminal, the login is refused before it starts: printing
  the exports there would put the token and key on screen.
- `vsh http`, `vsh token print`, `vsh token proof` and `vsh token status` run
  from that shell use the session credential. It takes precedence over a
  stored credential for the same audience; `--audience <other>` still reaches
  the stored ones. A shell holds one session credential: a second `--local`
  login replaces the first.
- It works with the device flow and the browser flow. It cannot be combined
  with `--service-token-file` or `--key`.

Who can read the credential:

- **Every process started from that shell.** Environment variables are
  inherited, so each command you run there, and whatever it starts, receives
  a copy of the token and the key.
- **Any process running as the same user, and root.** On Linux a process's
  environment is readable by its owner through `/proc/<pid>/environ`. This is
  the same boundary that protects the 0600 files of the default mode: the
  difference is not who can read the credential but how easily it travels.
  Environments get printed — by `env`, debug output, crash reports, CI logs,
  or `set -x` while the exports are evaluated.
- Not shell history and not the process list: the exports reach the shell
  through a pipe, and `export` is a shell builtin with no arguments visible to
  other processes. Do not redirect the output of `--local` to a file.

How the session ends:

- When the shell exits, or when the variables are unset: `vsh token logout`
  with the shell function, `eval "$(vsh token logout --eval)"` without it, or
  `unset VSH_LOCAL_TOKEN VSH_LOCAL_TOKEN_KEY`. A plain `vsh token logout`
  without the function can only tell you this — a program cannot change its
  parent shell's environment.
- Unsetting does not reach copies already inherited by running processes, and
  it does not revoke anything: the token stays valid until it expires (15
  minutes by default). The key signs nothing else, so after that it is worth
  nothing.
- When the token expires, `vsh http`, `print` and `proof` fail with a message
  telling you to log in again. There is no renewal — `vsh token renew` refuses
  a session credential — because nothing about the login was kept and the
  device flow needs a person. A new login is a new key.

**Requests.** `vsh http` sends one request with
`Authorization: DPoP <token>` and a fresh `DPoP` proof for that method and
URL:

```bash
vsh http https://broker.example.com/v1/secrets/db-password
vsh http -X PUT -H 'Content-Type: application/json' -d @secret.json \
    https://broker.example.com/v1/secrets/db-password
echo '{"value":"…"}' | vsh http -d @- https://broker.example.com/v1/secrets/api-key
```

- The response body goes to stdout. A status of 400 or above prints the
  status and body to **stderr** and exits non-zero, so `x=$(vsh http …)`
  never captures an error page.
- Redirects are not followed: a proof covers one URL, and following a
  redirect would send the token somewhere the proof does not vouch for.
- Plain `http://` is refused except to `localhost` (`--allow-http` overrides).
- If the service answers `401` with a `DPoP-Nonce` challenge (RFC 9449 §9),
  the request is retried once with the nonce in the proof.

**Scripting.** The token and proofs are available for tools that cannot go
through `vsh http`, but only when asked for explicitly:

```bash
URL=https://broker.example.com/v1/secrets/db-password
curl -H "Authorization: DPoP $(vsh token print)" \
     -H "DPoP: $(vsh token proof --method GET "$URL")" "$URL"
```

A proof is single-use: generate a new one per request. Nothing in `vsh`
accepts a token as an argument, prints one unprompted, or writes one to a
log, so tokens do not end up in shell history by accident. A token leaves
`vsh` in exactly two ways, both of which you ask for: `vsh token print`, and
the exports of a `--local` login, which go to a shell and are refused on a
terminal.

## Offline verification contract

This is what a relying service must do. It needs four pieces of local
configuration and no network:

- the **pinned JWKS** (a file);
- the expected **issuer** string;
- its own **audience** name;
- its own **origin** — the `scheme://host[:port]` clients address it by.

A request is authenticated when *every* step below passes. On any failure,
answer `401` and do not act on anything in the request.

**Input.** `Authorization: DPoP <token>` and exactly one `DPoP: <proof>` header.

**1. Verify the token signature against a locally trusted key.**
- The `Authorization` scheme must be `DPoP`. Reject `Bearer`: accepting a
  bound token as a bearer token discards the binding.
- The token must be a compact JWS — three unpadded base64url segments, in
  canonical form (no padding, no whitespace, no unused trailing bits) — with
  `alg` exactly `EdDSA`. Decide the algorithm from an allowlist *before*
  verifying — never let the header pick it. Reject `none`, `HS256`, and
  everything else.
- `typ` must be `at+jwt`.
- Look up `kid` in the pinned set. Unknown `kid`: reject. Never use a key
  from the token itself (`jwk`, `jku`, `x5c` headers) or fetch one.
- Verify the Ed25519 signature over `base64url(header) "." base64url(payload)`.

**2. Require the expected issuer, audience and algorithm.**
- `iss` must equal the configured issuer, byte for byte.
- `aud` must be the service's own audience name and nothing else: that exact
  string, or a one-element array holding it. No prefix or pattern matching,
  and no accepting a list that merely includes the name — voussh never issues
  a token for more than one audience.

**3. Validate expiry and not-before.**
- Reject if `exp` is absent or `now ≥ exp + leeway`.
- Reject if `now + leeway < nbf` (and likewise for `iat`).
- Keep `leeway` small; the reference verifier uses 30 seconds.

**4. Validate the DPoP proof's signature and its binding to `cnf.jkt`.**
- The proof must be a compact JWS (canonical, as above) with `typ` `dpop+jwt`,
  `alg` `EdDSA`, and a `jwk` header holding an Ed25519 **public** key whose
  `x` decodes to exactly 32 bytes. Reject a `jwk` with private members.
- Verify the proof's signature with that embedded key.
- Compute the RFC 7638 thumbprint of the embedded key:
  `base64url(SHA-256('{"crv":"Ed25519","kty":"OKP","x":"<x>"}'))` — members in
  that order, no whitespace. It must equal the token's `cnf.jkt`. A token
  without `cnf.jkt` is rejected.

  The signature check alone proves only that the sender holds *a* key. This
  comparison is what proves it is the key the token was issued to.

**5. Validate method, URI, token hash and freshness.**
- `htm` must equal the request method.
- `htu` must equal the request URL *without query and fragment*, after
  normalising both sides: lower-case scheme and host, drop a default port,
  treat an empty path as `/`. Build the request URL from the service's
  configured origin plus the request path — not from the `Host` or
  `X-Forwarded-*` headers, which the caller controls.
- `ath` must equal `base64url(SHA-256(token))`, hashing the token exactly as
  it appeared in the `Authorization` header.
- `iat` must be recent: reject if older than a short maximum age (reference:
  60 seconds) or further in the future than `leeway`.
- `jti` must be present.

**6. Reject replayed proofs with a bounded local cache.**
- Remember each accepted proof, keyed by (key thumbprint, `jti`), until
  `iat + max age` — after that the freshness check rejects it anyway, so the
  cache stays small.
- Reject a proof that is already in the cache.
- Insert only after every other check has passed, so unauthenticated traffic
  cannot fill the cache.
- Bound the cache. When it is full, **refuse new proofs** rather than evict a
  live entry; an evicted proof could be replayed.
- Bound each identity's share of it as well. Otherwise any one authenticated
  caller can fill the cache by sending valid requests quickly, and everyone
  else is refused until its entries expire. Count the share per `sub`, not
  per key: one identity can hold tokens for many keys. (The reference
  verifier gives each subject an eighth of the cache by default —
  `ReplayPerSubject`.)
- The cache is per process. Several replicas behind a load balancer each
  need to see a proof to reject its replay: share the cache, pin clients to
  a replica, or accept that a captured proof can be replayed once per replica
  within the freshness window.

**7. Extract the identity and role for local authorization.**
- `sub` and `sub_type` say who is calling; `role` is the single role this
  token was issued for. Apply the service's own policy to them.
- Do not treat `role` as an SSH principal, and do not infer permissions from
  anything outside these claims.

### In Go

`httpcred.Verifier` implements steps 1–6 and returns the claims for step 7.
Add it with `go get github.com/tlamadon/voussh/httpcred`:

```go
import "github.com/tlamadon/voussh/httpcred"

raw, _ := os.ReadFile("voussh-jwks.json")           // the pinned keys
keys, err := httpcred.ParseJWKS(raw)
verifier, err := httpcred.NewVerifier(httpcred.VerifierConfig{
    Issuer:   "https://auth.example.com",
    Audience: "secret-broker",
    Keys:     keys,
    Origin:   "https://broker.example.com",
})

func handler(w http.ResponseWriter, r *http.Request) {
    claims, err := verifier.VerifyHTTP(r)
    if err != nil {
        log.Printf("rejected: %v", err)              // reason to the log…
        http.Error(w, "unauthorized", http.StatusUnauthorized) // …not the caller
        return
    }
    // claims.Subject, claims.SubjectType, claims.Role
}
```

Create one `Verifier` and share it; the replay cache lives inside it.
[`examples/secret-broker`](../examples/secret-broker/main.go) is a complete,
runnable service built on this.

### In anything else

Use a maintained JOSE library for the signature checks and implement the
remaining comparisons directly — they are string equality, two SHA-256
hashes and a map. Then run your implementation against the
[test vectors](#test-vectors).

Common mistakes, each of which has a vector:

- accepting whatever `alg` the header names (`token-alg-none`,
  `token-alg-hs256-public-key`);
- verifying the proof's signature but not comparing its key to `cnf.jkt`
  (`proof-key-mismatch`);
- accepting the token under `Authorization: Bearer` (`bearer-scheme`);
- skipping `ath`, which lets a proof escort a different token
  (`token-hash-mismatch`);
- no replay cache (`proof-replayed`).

## Test vectors

[`httpcred/testdata/vectors.json`](../httpcred/testdata/vectors.json) contains:

- **`verifier`** — the issuer, audience, leeway, proof max age and pinned JWKS
  that every case is evaluated under. The JWKS has two keys, as it would
  mid-rotation.
- **`samples`** — one valid access token and DPoP proof, with their headers
  and claims decoded, the client's public JWK, its thumbprint, and the token
  hash. Use these to check thumbprint and `ath` computation in isolation.
- **`cases`** — 23 requests, each with the verifier's clock (`now`), the
  method, URL, `Authorization` value and `DPoP` header values, and the
  expected outcome: `ok` (with the identity to extract) or an error code.
  A case with `"times": 2` is presented twice to the same verifier; the
  expectation applies to the second presentation.

| Outcome | Cases |
|---|---|
| `ok` | `valid`, `valid-previous-signing-key`, `valid-query-ignored`, `valid-service-identity` |
| `invalid_token_signature` | `token-payload-tampered`, `token-forged-under-pinned-kid` |
| `unknown_key` | `token-unknown-key` |
| `malformed_token` | `token-alg-none`, `token-alg-hs256-public-key` |
| `wrong_issuer`, `wrong_audience` | `wrong-issuer`, `wrong-audience` |
| `token_expired`, `token_not_yet_valid` | `token-expired`, `token-not-yet-valid` |
| `missing_token`, `missing_proof` | `bearer-scheme`, `missing-proof` |
| `key_mismatch`, `invalid_proof_signature` | `proof-key-mismatch`, `proof-bad-signature` |
| `method_mismatch`, `uri_mismatch`, `token_hash_mismatch` | `method-mismatch`, `uri-mismatch`, `token-hash-mismatch` |
| `stale_proof` | `proof-stale`, `proof-from-the-future` |
| `proof_replayed` | `proof-replayed` |

An implementation need not use the same error codes, but it must accept the
four `ok` cases and reject the other nineteen.

The file is generated from fixed throwaway keys and fixed timestamps
(`go test ./httpcred -run TestVectors -update`), and a test fails if it drifts
from what the code produces. The sample signatures have been checked
independently with OpenSSL.

## Limitations

**There is no immediate revocation.** A relying service verifies offline, so
voussh has no way to tell it that a token should stop working. Removing a
user from `users`, removing a role from `allowed_roles`, or deleting a
service takes effect on the *next* issuance; tokens already issued remain
valid until `exp`. The exposure is bounded by the token lifetime — 15 minutes
by default, never more than 24 hours — and that is the only bound. Choose
`validity` as the answer to "how long may a removed user keep access?".

Getting closer to immediate revocation needs a mechanism this design
deliberately leaves out, for instance a denylist of `jti` or `sub` values
pushed to relying services, or an online check. Either reintroduces a
dependency between the service and something else at request time. A relying
service is free to add its own (a local list of blocked subjects is the
simplest), and the `jti` and `sub` claims are there to support it.

Revoking the **signing key** is possible but blunt: removing a key from the
pinned files invalidates every token signed with it.

**A stolen token is not enough; a stolen key is.** DPoP binds the token to the
client's private key, so a token captured from a log, a proxy or a browser
history cannot be used by itself. An attacker who can read
`~/.config/voussh/http_ed25519` can use the token until it expires and — if
they can also get through a login — obtain more. Protect that file as you
would an SSH key. A `--local` session holds its key in the shell's
environment instead, next to the token: anything that captures that
environment has both, for as long as the token lasts.

**The browser flow delivers the token in a `localhost` redirect URL**, as the
certificate flow does for certificates. It can therefore appear in local
browser history; per the previous point, it is not usable without the key.
The device and machine flows return it in a response body.

**The browser flow's login URL is a secret for five minutes.** It carries the
port and the one-time value by which `vsh` recognises the returning browser.
It is printed in the terminal and passed to the browser launcher, so on a
machine shared with other users it can be read from the process list.
Someone who has it, and who is themselves able to log in to the same voussh,
could complete the login as *themselves* and steer the result into your
`vsh` — you would then be acting at the service under their identity. `vsh`
prints the identity it stored (check it), refuses forged tokens and refuses
an identity change on renewal, but it cannot tell on a first login who you
meant to be. On a multi-user machine, use `--device`: nothing secret appears
in a URL or on a command line there.

**Proof replay protection is local and time-bounded.** See step 6: it holds
per verifier process, for the proof's freshness window.

**Clocks matter.** Tokens are short-lived and proofs shorter. The issuer, the
client and the relying service need clocks within the leeway of each other
(30 seconds in the reference verifier).

**One key type.** Token signatures and client keys are Ed25519 only.
