# VouSSH - OAuth-based SSH Certificate Authority

A stateless, lightweight SSH Certificate Authority server and client that authenticates users via Google OAuth and issues short-lived SSH certificates based on role assignments. 

The same login can also issue short-lived, key-bound **HTTP credentials** (Ed25519-signed JWTs with DPoP) that your own services verify offline — see [HTTP credentials](#http-credentials-jwt--dpop).

## Features

- 🔐 **Google OAuth authentication** - Leverage existing Google Workspace identities
- 🎫 **Short-lived certificates** - Time-bound certificates reduce security risks
- 👥 **Role-based access** - Map users to roles with specific SSH principals
- 📱 **Device flow** - Log in on a headless or remote machine by approving from your phone or laptop
- 🪪 **HTTP credentials** - Optional proof-of-possession JWTs for HTTP services, verified offline against a pinned key
- 🚀 **Stateless server** - Horizontally scalable, no session storage
- 🔧 **Simple setup** - Minimal configuration required
- 🌐 **HTTPS support** - Optional TLS for secure deployments
- 🏥 **Health endpoints** - Built-in monitoring support
- 🔀 **Dual session modes** - Global sessions (persistent) or local sessions (shell-specific)

## Quick Start

### Setup

1. Build binaries:
   ```bash
   go build -o voussh cmd/voussh/main.go
   go build -o vsh cmd/vsh/main.go
   ```

2. Create Google OAuth credentials and save them in `config.yaml`

### Server (voussh)

```bash

# Generate CA key pair
./voussh init [path]

# Start server with default config
./voussh

# Start with custom config file
./voussh --config /etc/voussh/config.yaml

# Generate a token signing key pair (only needed for HTTP credentials)
./voussh jwt-init [path]

# Print the public token verification keys (JWKS), without starting the server
./voussh jwks --config /etc/voussh/config.yaml

# Show help
./voussh --help
```

The server provides:
- OAuth login endpoint: `/login`
- OAuth callback endpoint: `/callback`
- CA public key endpoint: `/pubkey`
- Health check endpoint: `/health`
- Token verification keys: `/.well-known/jwks.json` (only with a `jwt:` block)

### Running with Docker

A prebuilt server image is published to GitHub Container Registry on every
push to `main` and every `v*` tag:

```
ghcr.io/tlamadon/voussh:latest     # latest main
ghcr.io/tlamadon/voussh:0.1.0      # a specific release
```

First, generate the CA key into the directory you'll mount (skip if you already
have one):

```bash
docker run --rm -v "$PWD:/data" ghcr.io/tlamadon/voussh:latest init /data/ca_key
```

Then create a `config.yaml` next to it (see the configuration section below),
making sure it points at the mounted key and port:

```yaml
addr: ":8080"
ca_key: "./ca_key"   # resolves to /data/ca_key inside the container
# ... client_id, client_secret, redirect_url, users, etc.
```

#### docker-compose.yml

```yaml
services:
  voussh:
    image: ghcr.io/tlamadon/voussh:latest
    restart: unless-stopped
    ports:
      - "8080:8080"
    volumes:
      - ./config.yaml:/data/config.yaml:ro
      - ./ca_key:/data/ca_key:ro
```

```bash
docker compose up -d
docker compose logs -f
```

The container's working directory is `/data` and it runs `voussh --config
/data/config.yaml` by default, so both the config and the CA key are expected
there. The image runs as root so it can read a bind-mounted `ca_key` with
`0600` permissions; the CA private key never needs to be world-readable.

> **Note:** Mount real TLS certificates (or terminate TLS at a reverse proxy)
> for any non-local deployment — the CA signs SSH certificates based on OAuth
> logins, so the endpoint must be trusted.

### Server Configuration (config.yaml)

```yaml
addr: ":8080"
ca_key: "./ca_key"
cert_validity: 8h

# Optional: global SSH certificate extensions. When omitted, defaults to:
#   [permit-pty, permit-agent-forwarding, permit-user-rc]
# Used for any role that doesn't define its own extensions under `roles`.
# extensions:
#   - permit-pty
#   - permit-agent-forwarding
#   - permit-user-rc

# Optional: per-role policy. Each role may override validity and/or extensions.
# Omitted fields fall back to cert_validity / extensions above.
# (extensions is a full override, not additive.)
# roles:
#   admin:
#     validity: 1h
#     extensions:
#       - permit-pty
#       - permit-port-forwarding
#       - permit-X11-forwarding
#   deploy:
#     validity: 24h
#     extensions:
#       - permit-pty
#       - permit-agent-forwarding
#       - permit-port-forwarding

# Optional TLS configuration
# tls:
#   cert: "./server.crt"
#   key: "./server.key"

# Google OAuth credentials
client_id: "xxx.apps.googleusercontent.com"
client_secret: "xxx"
redirect_url: "http://localhost:8080/callback"

# Users: email -> role -> principals
users:
  alice@example.com:
    default: [root, admin]
    deploy: [deploy]
  bob@example.com:
    default: [developer]
    deploy: [deploy]
  charlie@example.com:
    default: [developer]
    admin: [root, admin]
    deploy: [deploy]
```

#### Configuration Fields

| Field | Description |
|-------|-------------|
| `addr` | Server listen address |
| `ca_key` | Path to CA private key (without extension) |
| `cert_validity` | Default certificate validity duration (e.g., `8h`, `24h`) |
| `trusted_proxies` | Peers whose `X-Forwarded-*` headers are believed (optional — see [Behind a reverse proxy](#behind-a-reverse-proxy)) |
| `extensions` | Global SSH cert extensions (optional; defaults to `permit-pty`, `permit-agent-forwarding`, `permit-user-rc`) |
| `roles` | Per-role policy overrides (optional; each role may set `validity`, `extensions` and/or `source_address`) |
| `services` | Machine credentials for `POST /sign` (optional — see [Machine authentication](#machine-authentication-sign)) |
| `admin` | Web admin panel at `/admin` (optional — see [Admin panel](#admin-panel-admin)) |
| `jwt` | HTTP credential issuance (optional; off when absent — see [HTTP credentials](#http-credentials-jwt--dpop)) |
| `client_id` | Google OAuth client ID |
| `client_secret` | Google OAuth client secret |
| `redirect_url` | OAuth callback URL |
| `base_url` | Externally reachable origin for device-flow links (optional; derived from `redirect_url`) |
| `device_flow` | Device flow settings (optional; enabled by default — see [Device Flow](#device-flow-headless-and-remote-machines)) |
| `users` | User authorization mapping |

#### Live config reload

The server watches the config file and automatically reloads it when it
changes — no restart needed for policy changes. Each reload is logged:

```
Config reloaded from config.yaml (3 users, 2 roles, 1 services)
```

Hot-reloaded fields: `users`, `cert_validity`, `extensions`, `roles`,
`services`, `admin.emails`, `trusted_proxies`, `device_flow.enabled`, and the
whole `jwt` block (including its key files, which are re-read on every
reload). These take effect on the next credential issued — a newly added
service becomes usable without a restart.

Changes to `addr`, `tls`, `ca_key`, or the OAuth settings (`client_id`,
`client_secret`, `redirect_url`) still require a restart — the server logs a
warning telling you so. If the edited file is invalid, the reload is skipped
and the previous config is kept (also logged).

#### User Configuration

Users are configured with a mapping of email to roles, where each role maps to a list of SSH principals:

```yaml
users:
  email@example.com:
    role_name: [principal1, principal2]
```

- The `default` role is used when no role is specified during login
- Users can request any role they have configured
- Principals determine which usernames can be used when SSHing to servers


### Client (vsh)

#### Optional one-time Setup for local session

Add this to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.):
```bash
eval "$(vsh init)"
```
This creates a shell function that wraps the vsh binary and enables seamless local session management. Ignore this step 

#### Usage

```bash
# Pick a host and connect — logs in first if the certificate has expired
vsh

# Login and obtain SSH certificate (global session)
vsh login --server http://localhost:8080

# Login with a specific role
vsh login --server http://localhost:8080 --role admin

# Login without a local browser (approve from your phone or laptop)
vsh login --device --server http://localhost:8080

# Create a local session (shell-specific) - no eval needed!
vsh login --local --server http://localhost:8080

# Check certificate status
vsh status

# Logout - automatically handles both local and global sessions
vsh logout

# SSH to a host using your certificate
vsh ssh user@hostname

# SSH with additional options
vsh ssh user@hostname -L 8080:localhost:80

# Get CA public key (for server configuration)
vsh pubkey

# Obtain an HTTP credential and use it (see "HTTP credentials")
vsh token login --audience secret-broker
vsh http https://broker.example.com/v1/secrets/db-password

# Show or change the server vsh uses
vsh server
vsh server https://ca.example.com

# Show version
vsh version
```

#### Choosing a server

`vsh` uses one server and remembers it. The first `vsh login` asks which one
(or takes it from `--server`) and saves the answer; every later command uses
it without asking.

```bash
vsh server                          # show it
vsh server https://ca.example.com   # use this one from now on
vsh server --pick                   # choose among servers used before
vsh server --clear                  # forget it; the next login asks again
```

`--server` on a command and the `VSH_SERVER` environment variable override the
saved server for that invocation without changing it. `vsh logout` removes the
certificate but keeps the server.

#### Host picker

Running `vsh` with no arguments opens a picker instead of printing the usage:

```
vsh ssh> web
  2/7
> root@web1 -p 2222
  web2
```

The list is your recent `vsh ssh` connections, most recent first and with the
user and options you used, followed by the `Host` entries from
`~/.ssh/config` (including files pulled in with `Include`; wildcard patterns
are skipped). Pick an entry to connect, or type a new `[user@]host` — with ssh
options if you like — and press Enter. Esc cancels.

Before connecting, `vsh` checks the certificate. If there is none or it has
expired, it runs the login first — for the same role as the expired
certificate, and with the device flow when you are in an SSH session — and
then connects.

The picker uses [`fzf`](https://github.com/junegunn/fzf) when it is installed
and falls back to a numbered prompt when it is not. It only opens on a
terminal: a bare `vsh` in a script or pipe prints the usage as before.

### Device Flow (headless and remote machines)

The default login opens a browser and waits for a callback on `localhost`. That
only works when the browser runs on the same machine as `vsh`. When you are
SSH'd into a server, on a box with no desktop, or behind NAT, use the device
flow instead:

```bash
vsh login --device --server https://ca.example.com
```

```
To authorize this machine, open this page on any device:

    https://ca.example.com/device

and enter the code:

    WDJB-MJHT

Waiting for approval (expires in 10m0s)...
```

Open that page on your phone or laptop, enter the code, sign in with Google,
and confirm. The certificate is delivered straight to the waiting terminal:

```
Approved by alice@example.com (principals: root, admin)
Login successful! Role: default
Certificate saved to: /home/you/.ssh/id_ed25519-cert.pub (global session)
```

`--device` composes with `--role` and `--local` exactly like the browser flow.

Nothing about your Google Cloud setup changes: the approving browser runs the
same web login voussh already uses, so the existing "Web application" OAuth
client is all you need.

#### Before you approve

The confirmation page shows the **SSH key fingerprint** the certificate would
be issued against, along with the identity, role and principals:

```
Signed in as alice@example.com.

  Role          default
  Principals    root, admin
  SSH key       SHA256:kFPcGraoTAR5MhJuPRa6hWwCRqqDCJBfP91h+PNp62c
  Key comment   alice@laptop
  Code          WDJB-MJHT
```

Check it. Approving issues a certificate carrying **your** principals to
whichever machine holds that key. If you did not start the login, or the
fingerprint does not match the machine you are sitting at, choose **Reject** —
someone may be trying to get you to authorize their device. This is the one
attack the device flow adds that the browser flow does not have, and the
fingerprint is what defends against it.

Run `ssh-keygen -lf ~/.ssh/id_ed25519.pub` on the machine you are logging in
from to see the fingerprint it should match.

#### Server configuration

The flow is enabled by default and needs no configuration. It grants nothing
the browser flow does not: the same identity provider, the same `users` map,
the same roles. To tune or disable it:

```yaml
# Optional: externally reachable origin used to build the verification link.
# Derived from redirect_url when unset, which is usually correct.
# base_url: "https://ca.example.com"

device_flow:
  enabled: true          # set false to remove the /device endpoints entirely
  code_validity: 10m     # how long a code stays usable
  poll_interval: 5s      # minimum spacing between client polls
  max_pending: 1024      # cap on concurrent in-flight requests
```

`enabled` is picked up by the live config reload. The timing fields are read at
startup and need a restart; the server logs a warning if you change them.

Requests live only in memory, so a restart cancels anything in flight. Codes
are single-use: once a certificate is collected, the code is gone.

#### Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/device/code` | POST | CLI requests a device code and user code |
| `/device` | GET, POST | Human enters the user code |
| `/device/approve` | POST | Human confirms or rejects |
| `/device/token` | POST | CLI polls for its certificate |

The wire format follows [RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)
between `vsh` and `voussh`, including the `authorization_pending`, `slow_down`,
`expired_token` and `access_denied` responses.

### Machine authentication (`/sign`)

Interactive logins need a human in a browser. For daemons — dashboards, backup
jobs, anything on a systemd timer — `POST /sign` exchanges a pre-shared bearer
token for a short-lived certificate, no OAuth involved. Target hosts need
nothing beyond the `TrustedUserCAKeys` they already trust: no `authorized_keys`
entries, no per-target setup, and the credential expires on its own.

> **The token is CA-signing capability for the listed principals.** Whoever
> holds it can mint certificates for those principals until the service is
> removed from the config. Protect it like a private key: scope the service to
> the fewest principals possible, pin it with `source_address`, and never
> expose `/sign` to the internet — keep voussh on a VPN, tailnet or private
> network.

#### 1. Mint a token

```bash
openssl rand -hex 32
```

Store it on the client machine, readable only by the service account that will
use it (e.g. `/var/lib/herdr/voussh-token`, mode `0400`).

#### 2. Configure the service

```yaml
services:
  herdr-hq:
    # exactly one of token_file / token_sha256:
    token_sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    principals: [tlamadon]
    validity: 12h                      # falls back to cert_validity
    source_address: 100.88.151.28/32   # CIDRs the cert may be used from
```

With `token_sha256` the raw token never touches the CA host — compute the
digest with `printf %s "$TOKEN" | sha256sum` (`shasum -a 256` on macOS).
Alternatively `token_file: /path/to/token` makes the server read (and trim) the
raw token from a file at request time, so rotating it needs no config edit.
The live config reload picks up new and changed services without a restart.

Certificates for a service carry the key ID `<name>@service` (so sshd's log
distinguishes them from interactive `<email>@<role>` certs) and **no
extensions by default** — a daemon running non-interactive commands needs no
pty and no agent forwarding. If the client does need a terminal, opt in
explicitly with `extensions: [permit-pty]`. `source_address` is embedded as
the `source-address` critical option and enforced by sshd itself: the
certificate is refused from any other address, even if the token leaks. It
works for interactive roles too (`roles.<name>.source_address`).

#### 3. Request a certificate

```bash
curl --fail -H "Authorization: Bearer $(cat /var/lib/herdr/voussh-token)" \
  --data-binary @$HOME/.ssh/id_ed25519.pub \
  https://ca.example.com/sign > ~/.ssh/id_ed25519-cert.pub
```

Or use `vsh renew`, which does the same thing but generates the key pair if it
is missing and writes the certificate atomically:

```bash
vsh renew --server https://ca.example.com --token-file /var/lib/herdr/voussh-token
```

The response is the certificate in `authorized_keys` format — written next to
the key as `id_ed25519-cert.pub`, ssh picks it up automatically:

```bash
ssh -i ~/.ssh/id_ed25519 tlamadon@somehost   # no authorized_keys entry needed
```

#### 4. Renew on a systemd timer

Renew at half the certificate lifetime so an outage of the CA never strands
the client with an expired certificate. With `validity: 12h`, renew every 6h:

```ini
# /etc/systemd/system/vsh-renew.service
[Unit]
Description=Renew SSH certificate from voussh
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=herdr
ExecStart=/usr/local/bin/vsh renew \
  --server https://ca.example.com \
  --token-file /var/lib/herdr/voussh-token \
  --key /var/lib/herdr/.ssh/id_ed25519
```

```ini
# /etc/systemd/system/vsh-renew.timer
[Unit]
Description=Renew SSH certificate at half its lifetime

[Timer]
OnBootSec=1min
OnUnitActiveSec=6h
RandomizedDelaySec=5min

[Install]
WantedBy=timers.target
```

```bash
systemctl daemon-reload
systemctl enable --now vsh-renew.timer
```

Every issuance is logged on the server with the service name, principals,
certificate serial, key fingerprint, validity window and requesting IP; failed
token attempts are logged with the source IP.

### HTTP credentials (JWT + DPoP)

SSH certificates let `sshd` trust a user without calling anyone. HTTP
credentials do the same for your own HTTP services — a secret broker, an
internal API — so they can authenticate users and agents **without an SSH
connection and without contacting voussh or Google at request time**.

A credential is a short-lived JWT signed with Ed25519 (`alg: EdDSA`) and bound
to a key held by the client. Every request carries the token plus a
[DPoP](https://datatracker.ietf.org/doc/html/rfc9449) proof signed with that
key, so a token lifted from a log or a proxy is useless on its own. The
service verifies both against a public key it keeps in a local file.

The feature is off unless the config has a `jwt:` block, and enabling it
changes nothing about SSH issuance. The full reference — token format,
policy rules, key rotation and the verification contract — is in
[docs/http-credentials.md](docs/http-credentials.md). What follows is a
complete walk-through.

#### 1. Enable issuance

Generate a signing key. It is separate from the SSH CA key on purpose:

```bash
voussh jwt-init /etc/voussh/jwt_ed25519
```

```
Token signing key pair generated:
  Private key: /etc/voussh/jwt_ed25519
  Public key:  /etc/voussh/jwt_ed25519.pub
  Key ID:      bRqsG43ZHkEYuHn0iTswlvwHGuRSKH2yzktN8saTFsc
```

Say which services tokens may be issued for, and which roles each admits:

```yaml
users:
  alice@example.com:
    default: [alice]
    admin: [root]

jwt:
  issuer: "https://auth.example.com"
  signing_key: "/etc/voussh/jwt_ed25519"
  validity: 15m                 # default 15m, maximum 24h
  audiences:
    secret-broker:
      allowed_roles: [default, admin]
```

A user gets a token for an audience in a role only if the audience is listed,
the user holds the role under `users`, **and** the audience allows that role.
Anything else is refused: a client cannot name an arbitrary audience, ask for
a role it does not hold, or set any claim itself. The SSH principals attached
to a role play no part — the token does not contain them, and a role may map
to `[]` to make it HTTP-only.

The block is picked up by the live reload; no restart is needed.

#### 2. Pin the verification key in the service

Export the public keys — offline, straight from the config:

```bash
voussh jwks --config /etc/voussh/config.yaml > voussh-jwks.json
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

Ship `voussh-jwks.json` with the broker like any other trust anchor. The same
document is served at `GET /.well-known/jwks.json`, but the broker never needs
to fetch it: it reads the file at startup and is independent of voussh from
then on.

#### 3. Verify requests in the service

In Go, the `httpcred` package does the whole check
(`go get github.com/tlamadon/voussh/httpcred`):

```go
import "github.com/tlamadon/voussh/httpcred"

raw, _ := os.ReadFile("voussh-jwks.json")
keys, _ := httpcred.ParseJWKS(raw)
verifier, _ := httpcred.NewVerifier(httpcred.VerifierConfig{
    Issuer:   "https://auth.example.com",   // must match jwt.issuer
    Audience: "secret-broker",              // this service's own name
    Keys:     keys,                         // the pinned keys
    Origin:   "https://broker.example.com", // how clients address this service
})

http.HandleFunc("/v1/secrets/", func(w http.ResponseWriter, r *http.Request) {
    claims, err := verifier.VerifyHTTP(r)
    if err != nil {
        log.Printf("rejected: %v", err)
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return
    }
    // Authenticated. Authorization is the broker's own business:
    //   claims.Subject      "alice@example.com"
    //   claims.SubjectType  "user" (or "service")
    //   claims.Role         "default"
})
```

`VerifyHTTP` checks the token's signature against the pinned key, the issuer,
the audience and the validity window; then the DPoP proof's signature, that
its key is the one the token is bound to, that it names this method and URL
and hashes this token, that it is fresh, and that it has not been seen before.
None of it touches the network.

[`examples/secret-broker`](examples/secret-broker/main.go) is this, runnable:

```bash
go run ./examples/secret-broker --jwks voussh-jwks.json \
    --issuer https://auth.example.com --audience secret-broker \
    --origin http://localhost:9000
```

For a service in another language, [the verification contract](docs/http-credentials.md#offline-verification-contract)
lists every check, and [`httpcred/testdata/vectors.json`](httpcred/testdata/vectors.json)
has 23 request vectors — valid tokens, forged signatures, wrong issuer and
audience, expired tokens, mismatched keys, stale and replayed proofs — to run
an implementation against.

#### 4. Get a token

```bash
vsh token login --server https://auth.example.com --audience secret-broker
```

```
Generated a new key for HTTP credentials at /home/you/.config/voussh/http_ed25519
Opening browser for authentication...
Login URL: https://auth.example.com/login?audience=secret-broker&cli_port=41873&...

The approval page should show:
    Audience:    secret-broker
    Client key:  ggnw6G5DgAodPO-A8-gXCtFmFImXop9r5MIZ2AIXInE

Waiting for approval on localhost:41873...
```

After the Google sign-in, voussh shows a confirmation page before issuing
anything:

```
Issue an HTTP credential?

Signed in as alice@example.com.

  Audience     secret-broker
  Role         default
  Valid for    15m0s
  Client key   ggnw6G5DgAodPO-A8-gXCtFmFImXop9r5MIZ2AIXInE

  [ Approve ]  [ Reject ]
```

Check the audience and that the key matches your terminal, then approve:

```
Token saved for audience secret-broker
  Identity: alice@example.com
  Role:     default
  Expires:  14:32:10 on Nov 21 (in 15m0s)
```

On a machine with no browser, add `--device` and approve from your phone,
exactly as with `vsh login --device`. Add `--role admin` to request a
different role.

On first use `vsh` generates an Ed25519 key at
`~/.config/voussh/http_ed25519` (on macOS, under
`~/Library/Application Support/voussh`). Only its public half is sent to
voussh; the private key never leaves the machine. The token is stored next to
it under `tokens/`, readable only by you.

#### 5. Use it

```bash
vsh http https://broker.example.com/v1/secrets/db-password
```

```json
{"name":"db-password","value":"correct horse battery staple"}
```

`vsh http` attaches `Authorization: DPoP <token>` and a single-use proof for
exactly this method and URL. It takes the usual `-X`, `-H` and `-d` (`-d @file`,
`-d @-`), writes the body to stdout, and exits non-zero on an HTTP error —
with the error on stderr, so it is safe in `$(...)`.

```bash
vsh token status     # audience, identity, role, expiry — never the token itself
vsh token renew      # when it has expired: the same login again
vsh token logout
```

What the broker sees, and what a thief does not get:

```bash
URL=https://broker.example.com/v1/secrets/db-password
TOKEN=$(vsh token print)        # the raw token, only because we asked for it

curl -H "Authorization: Bearer $TOKEN" "$URL"                        # 401: not a bearer token
curl -H "Authorization: DPoP $TOKEN" "$URL"                          # 401: no proof

PROOF=$(vsh token proof --method GET "$URL")
curl -H "Authorization: DPoP $TOKEN" -H "DPoP: $PROOF" "$URL"        # 200
curl -H "Authorization: DPoP $TOKEN" -H "DPoP: $PROOF" "$URL"        # 401: proof replayed
```

`vsh token print` and `vsh token proof` exist for tools that cannot go through
`vsh http`. Nothing else prints a token, and no command accepts one as an
argument.

#### A session that leaves nothing on disk

On a machine you do not want to leave a key on — one without your SSH key, a
borrowed host, a container — add `--local`. A new key is generated for that
login, and the token and key are kept in the current shell's environment
instead of under `~/.config/voussh`:

```bash
eval "$(vsh init)"      # the vsh shell function, if it is not in your profile
vsh token login --local --device --server https://auth.example.com --audience secret-broker
```

```
To authorize this machine, open this page on any device:

    https://auth.example.com/device

and enter the code:

    WDJB-MJHT

Session token for audience secret-broker (this shell only; nothing was written to disk)
  Identity: alice@example.com
  Role:     default
  Expires:  14:32:10 on Nov 21 (in 15m0s)
```

```bash
vsh http https://broker.example.com/v1/secrets/db-password   # works in this shell
vsh token logout                                             # or close the shell
```

It is the same mechanism as `vsh login --local`. Without the shell function,
use `eval "$(vsh token login --local …)"`; run directly on a terminal, the
command refuses rather than print the credential.

The trade-off is where the credential lives. As environment variables
(`VSH_LOCAL_TOKEN`, `VSH_LOCAL_TOKEN_KEY`) it is inherited by every program
started from that shell and readable by any process of the same user. It ends
when the shell exits or the variables are unset; the token itself remains
valid until it expires. When it does, `vsh http` tells you to log in again —
a session is never renewed silently.
[Details](docs/http-credentials.md#the-client-vsh-token-and-vsh-http).

#### Agents and other machine identities

A daemon authenticates with a voussh service token, as it does for
[`/sign`](#machine-authentication-sign). Token rights are granted separately
and explicitly — a service that can request SSH certificates gets no tokens
unless an audience names it, and a service can be token-only:

```yaml
services:
  ci-runner:
    token_sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    # no principals: this identity cannot obtain SSH certificates at all

jwt:
  audiences:
    secret-broker:
      allowed_roles: [default, admin]
      services:
        ci-runner: [deploy]        # the roles this service may request
```

```bash
vsh token login --server https://auth.example.com --audience secret-broker \
    --service-token-file /var/lib/ci/voussh-token
vsh http https://broker.example.com/v1/secrets/deploy-key
```

The broker sees `sub: "service:ci-runner"`, `sub_type: "service"`,
`role: "deploy"`. No human is involved, so `vsh http` renews an expired token
by itself; there is nothing to schedule.

#### Rotating the signing key

voussh signs with one key and can publish several. Add the new public key
under `jwt.verification_keys`, redeploy the exported JWKS to your services,
switch `signing_key`, and drop the old key once its last token has expired.
Each step is a config reload. The procedure is spelled out in
[docs/http-credentials.md](docs/http-credentials.md#rotating).

#### What this does not give you

**Immediate revocation.** Because services verify offline, voussh cannot
reach out and cancel a token. Removing a user or a role stops *new* tokens;
ones already issued work until they expire. The token lifetime — 15 minutes
by default, 24 hours at most — is the revocation delay, so set it to how long
you are willing to wait. Anything faster needs an additional mechanism such
as a denylist distributed to services, which this design deliberately leaves
out. See [Limitations](docs/http-credentials.md#limitations).

### Admin panel (`/admin`)

A read-only web page showing what the server is doing: certificate issuances,
rejected tokens, device-flow activity and config reloads, colour-coded and
live-updating, with a filter box. Disabled unless configured:

```yaml
admin:
  emails: [alice@example.com]   # who may view the panel
  log_lines: 1000               # recent lines to keep (optional; restart to change)
```

Opening `/admin` walks through the ordinary Google login; anyone not listed in
`admin.emails` gets a 403. The session lives in a signed cookie (12h) — no
server-side state, and a server restart signs everyone out. `admin.emails` is
checked on every request, so removing someone via the live config reload locks
them out immediately.

The logs live in a fixed-size in-memory ring: the panel shows the most recent
`log_lines` lines since the process started, and nothing survives a restart —
for durable history, keep collecting stderr via journald as usual. Since the
page rides the same OAuth flow as everything else, no extra Google setup is
needed, but the panel does display emails, principals and client IPs: treat
`/admin` like the rest of voussh and keep it off the public internet, ideally
behind TLS (the server warns at startup if the panel is enabled without it).

### Session Management

The vsh client supports two session modes:

#### Global Sessions (Default)
- Certificate stored in `~/.ssh/id_ed25519-cert.pub`
- Persistent across all terminal sessions
- Shared by all shells on the system
- Use case: General day-to-day SSH access

```bash
# Create global session
vsh login --server http://localhost:8080

# Check status
vsh status
# Output: Session type: Global (all shells) - Server: http://localhost:8080

# Remove global session
vsh logout
```

#### Local Sessions (Shell-Specific)
- Certificate stored in environment variable `VSH_LOCAL_CERT`
- Isolated to current shell session
- Not visible to other terminals
- Use case: Temporary access, testing, or when you need different identities in different terminals

```bash
# After running 'eval "$(vsh init)"' in your shell profile:

# Create local session - simple and clean!
vsh login --local --server http://localhost:8080

# Check status
vsh status
# Output: Session type: Local (shell-specific) - Server: http://localhost:8080

# SSH automatically uses local session when available
vsh ssh user@hostname

# Remove local session - no eval needed!
vsh logout

# Manual removal (if not using the shell function):
unset VSH_LOCAL_CERT VSH_LOCAL_SERVER VSH_LOCAL_ROLE
```

**How it works**: The `vsh init` command creates a shell function that wraps the vsh binary. This function runs in your shell's process (not a subprocess), so it can directly modify environment variables for local sessions. This eliminates the need for `eval` wrappers during normal usage.

**Session Priority**: When both local and global sessions exist, the local session takes precedence.

### SSH Server Configuration 

#### Traditional Linux Systems

Add the CA public key to your SSH server's trusted user certificate authorities:

```bash
# Get CA public key
vsh pubkey > /etc/ssh/ca.pub

# Configure sshd_config
echo "TrustedUserCAKeys /etc/ssh/ca.pub" >> /etc/ssh/sshd_config
systemctl reload sshd
```

#### NixOS Configuration

##### Using the Flake

The flake provides NixOS and Home Manager modules for easy integration.

**Step 1: Add the flake input to your configuration**

```nix
# In your system flake.nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # Add voussh flake
    voussh = {
      url = "github:yourusername/voussh";  # Replace with actual repo
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # For Home Manager users
    home-manager = {
      url = "github:nix-community/home-manager";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, voussh, home-manager, ... }: {
    # Your NixOS configurations here
  };
}
```

**Step 2: Configure the Server (NixOS Module)**

Add the voussh module to your server configuration:

```nix
# In your flake.nix outputs
{
  nixosConfigurations.yourserver = nixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [
      ./configuration.nix
      # Import the voussh server module
      voussh.nixosModules.default

      # Configure the service
      {
        services.voussh = {
          enable = true;
          settings = {
            addr = ":8443";
            cert_validity = "8h";
            client_id = "your-client-id.apps.googleusercontent.com";
            client_secret = "your-client-secret";
            redirect_url = "https://voussh.example.com:8443/callback";

            users = {
              "alice@example.com" = {
                default = [ "root" "admin" ];
                deploy = [ "deploy" ];
              };
              "bob@example.com" = {
                default = [ "developer" ];
              };
            };

            # Optional TLS
            tls = {
              cert = "/path/to/cert.pem";
              key = "/path/to/key.pem";
            };
          };
        };
      }
    ];
  };
}
```

**Step 3: Configure the Client**

You have three options for client configuration:

**Option A: Home Manager Module (Per-user)**

```nix
# Add to your flake.nix outputs
{
  homeConfigurations."youruser" = home-manager.lib.homeManagerConfiguration {
    pkgs = nixpkgs.legacyPackages.x86_64-linux;
    modules = [
      # Import the vsh client module
      voussh.homeManagerModules.default

      # Configure the client
      {
        programs.vsh = {
          enable = true;
          enableShellIntegration = true;  # Adds 'vsh init' to shell
          defaultServer = "https://voussh.example.com:8443";
        };
      }
    ];
  };
}
```

**Option B: NixOS System-wide with Home Manager**

```nix
# In your NixOS configuration with home-manager as a module
{
  nixosConfigurations.yourdesktop = nixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [
      ./configuration.nix
      home-manager.nixosModules.home-manager
      {
        home-manager.users.youruser = {
          imports = [ voussh.homeManagerModules.default ];

          programs.vsh = {
            enable = true;
            enableShellIntegration = true;
            defaultServer = "https://voussh.example.com:8443";
          };
        };
      }
    ];
  };
}
```

**Option C: NixOS System Package (without Home Manager)**

```nix
{
  nixosConfigurations.yourclient = nixpkgs.lib.nixosSystem {
    system = "x86_64-linux";
    modules = [
      ./configuration.nix
      {
        # Install vsh client system-wide
        environment.systemPackages = [
          voussh.packages.${pkgs.system}.vsh
        ];

        # Optionally add shell integration system-wide
        programs.bash.interactiveShellInit = ''
          eval "$(vsh init)"
        '';

        # Configure SSH to trust the VouSSH CA
        services.openssh = {
          enable = true;
          settings = {
            PubkeyAuthentication = true;
            TrustedUserCAKeys = "/etc/ssh/trusted-user-ca-keys.pub";
            PasswordAuthentication = false;
          };
        };

        # Add your VouSSH CA public key
        environment.etc."ssh/trusted-user-ca-keys.pub" = {
          text = ''
            ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... voussh-ca
          '';
          mode = "0644";
        };
      }
    ];
  };
}
```

You can also run the client directly from the flake without installation:
```bash
# Run vsh directly from the flake
nix run github:yourusername/voussh#vsh -- login --server https://voussh.example.com

# Or enter a development shell
nix develop github:yourusername/voussh
```

##### Manual Configuration

For manual configuration, add the CA configuration to your system configuration:

```nix
{ config, pkgs, ... }:

{
  services.openssh = {
    enable = true;

    # Enable certificate authentication
    settings = {
      # Allow certificate-based authentication
      PubkeyAuthentication = true;

      # Path to trusted CA keys file
      TrustedUserCAKeys = "/etc/ssh/trusted-user-ca-keys.pub";

      # Optional: disable password authentication
      PasswordAuthentication = false;

      # Optional: require both certificate AND authorized_keys
      # AuthorizedKeysFile = "/etc/ssh/authorized_keys/%u";
    };
  };

  # Write the CA public key to the system
  environment.etc."ssh/trusted-user-ca-keys.pub" = {
    text = ''
      ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... voussh-ca
    '';
    mode = "0644";
  };

  # Optional: Configure principals mapping
  # This maps certificate principals to local users
  environment.etc."ssh/auth_principals/%u" = {
    text = ''
      # Principals that can log in as this user
      # One principal per line
      admin
      developer
    '';
    mode = "0644";
  };
}
```

Alternatively, you can fetch the CA key from the voussh server:

```nix
{ config, pkgs, ... }:

{
  services.openssh = {
    enable = true;
    settings = {
      PubkeyAuthentication = true;
      TrustedUserCAKeys = "/etc/ssh/trusted-user-ca-keys.pub";
      PasswordAuthentication = false;
    };
  };

  # Fetch CA key from voussh server at build time
  environment.etc."ssh/trusted-user-ca-keys.pub" = {
    source = pkgs.fetchurl {
      url = "https://voussh.example.com/pubkey";
      sha256 = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    };
  };
}
```

## NixOS Module Reference

### Server Module (`services.voussh`)

The NixOS module provides a complete systemd service for running the VouSSH server.

#### Available Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `services.voussh.enable` | boolean | false | Enable the VouSSH server |
| `services.voussh.package` | package | voussh | The voussh package to use |
| `services.voussh.dataDir` | path | /var/lib/voussh | Directory for CA keys |
| `services.voussh.user` | string | voussh | User to run the service |
| `services.voussh.group` | string | voussh | Group to run the service |
| `services.voussh.settings.addr` | string | :8080 | Listen address and port |
| `services.voussh.settings.ca_key` | string | /var/lib/voussh/ca_key | CA key path |
| `services.voussh.settings.cert_validity` | string | 8h | Certificate validity |
| `services.voussh.settings.client_id` | string | required | Google OAuth client ID |
| `services.voussh.settings.client_secret` | string | required | Google OAuth client secret |
| `services.voussh.settings.redirect_url` | string | required | OAuth callback URL |
| `services.voussh.settings.users` | attrset | {} | User role mappings |
| `services.voussh.settings.tls` | null or attrset | null | TLS configuration |

#### Security Features

The module includes extensive systemd hardening:
- Runs as non-root user
- Private tmp directory
- Read-only system directories
- No new privileges
- Restricted system calls
- Network namespace isolation

### Home Manager Module (`programs.vsh`)

The Home Manager module provides user-level installation and shell integration for the vsh client.

#### Available Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `programs.vsh.enable` | boolean | false | Enable vsh client |
| `programs.vsh.package` | package | vsh | The vsh package to use |
| `programs.vsh.enableShellIntegration` | boolean | true | Enable shell function for local sessions |
| `programs.vsh.defaultServer` | null or string | null | Default VouSSH server URL |

#### Shell Integration

When enabled, automatically configures:
- Bash: Adds to `.bashrc`
- Zsh: Adds to `.zshrc`
- Fish: Adds to `config.fish`

This enables the `vsh login --local` command for shell-specific sessions.

## Architecture

- **voussh**: Server that handles OAuth flow and signs SSH certificates — and, optionally, HTTP credentials
- **vsh**: CLI client for authentication and certificate management
- **httpcred**: Go package with the HTTP credential format and an offline verifier for relying services
- Certificates are signed during the OAuth callback flow
- Principals are assigned based on the requested role
- All certificates are time-limited (default 8 hours)

## How It Works

1. User runs `vsh login --server <url>` (add `--local` for shell-specific session)
2. Browser opens to Google OAuth
3. After authentication, the server signs the user's SSH public key
4. Certificate is returned to the CLI via local callback server
5. Certificate is either:
   - Saved to `~/.ssh/id_ed25519-cert.pub` (global session)
   - Stored in environment variable `VSH_LOCAL_CERT` (local session)
6. User can now SSH to any server that trusts the CA

## Deployment

### Running with systemd

Create a systemd service file `/etc/systemd/system/voussh.service`:

```ini
[Unit]
Description=VouSSH Certificate Authority
After=network.target

[Service]
Type=simple
User=voussh
Group=voussh
WorkingDirectory=/etc/voussh
ExecStart=/usr/local/bin/voussh --config /etc/voussh/config.yaml
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
systemctl daemon-reload
systemctl enable voussh
systemctl start voussh
```

### Docker Deployment

```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o voussh cmd/voussh/main.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/voussh .
COPY config.yaml .
EXPOSE 8080
CMD ["./voussh"]
```

### HTTPS with Let's Encrypt

For production deployments, use HTTPS:

1. Obtain certificates (e.g., using certbot)
2. Update `config.yaml`:
   ```yaml
   tls:
     cert: "/etc/letsencrypt/live/voussh.example.com/fullchain.pem"
     key: "/etc/letsencrypt/live/voussh.example.com/privkey.pem"
   ```
3. Update OAuth redirect URL to use HTTPS

### Behind a reverse proxy

Instead of terminating TLS itself, voussh can sit behind a proxy that does —
useful when a Caddy or nginx instance already holds a wildcard certificate.
Three settings matter:

```yaml
# no tls: block — the proxy terminates HTTPS, voussh speaks plain HTTP
addr: "127.0.0.1:8080"
redirect_url: "https://ca.example.com/callback"   # the EXTERNAL origin
trusted_proxies:
  - 127.0.0.1/32     # the address the proxy connects FROM
```

`base_url` is optional here: device-flow links are derived from
`redirect_url`, which already points at the external origin.

`trusted_proxies` tells voussh which peers' `X-Forwarded-For` and
`X-Forwarded-Proto` headers to believe. Without it everything still works,
but every request appears to come from the proxy: the per-IP rate limiters
collapse into a single bucket, the audit log names the proxy on every line,
and the admin session cookie loses its `Secure` flag. With it, voussh walks
`X-Forwarded-For` right to left past trusted hops, so a client-supplied
header (`X-Forwarded-For: 1.2.3.4` arrives as `1.2.3.4, <real-ip>` after the
proxy appends) can never forge the source address.

**The trust model**: listing an address in `trusted_proxies` is a statement
that nothing except the named proxy can connect from it. If the port is
reachable directly, the entry hands every caller the ability to forge their
source address — bind voussh to loopback (or a firewalled interface) so the
proxy is genuinely the only way in.

A complete Caddy example — Caddy sets `X-Forwarded-For`, `X-Forwarded-Proto`
and `X-Forwarded-Host` by default, no extra configuration needed:

```
ca.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

**The Docker gotcha**: when voussh runs as a container with a published port
and the proxy runs on the host, the peer address voussh sees is the Docker
bridge gateway (`172.17.0.1`), not `127.0.0.1` — the host-loopback connection
is serviced by `docker-proxy`. Configuring `trusted_proxies: [127.0.0.1/32]`
there is a silent no-op: nothing matches, and you keep the single-bucket
limiter. Trust the gateway address instead:

```yaml
trusted_proxies:
  - 172.17.0.1/32
```

`/32` on the gateway is tight: another container can source from other
`172.17.0.x` addresses but not from the gateway itself.

## Troubleshooting

### Common Issues

#### "Error 401: invalid_client"
- Verify Google OAuth credentials are correct
- Check that redirect URL in config matches Google Console exactly
- Ensure client_id ends with `.apps.googleusercontent.com`

#### Certificate not being received by CLI
- Ensure browser and CLI are on the same machine for localhost callback
- Check firewall rules aren't blocking the callback port
- For remote access, manually copy certificate from browser

#### "Invalid or expired state" error
- OAuth flow took too long (>10 minutes)
- Try logging in again

#### Tailscale/HSTS issues
- Tailscale domains (.ts.net) require HTTPS
- Use IP address instead of hostname for HTTP
- Or configure TLS on the server

### Debug Mode

View server logs for debugging:
```bash
./voussh --config config.yaml 2>&1 | tee voussh.log
```

The server logs will show:
- OAuth configuration details
- Login requests with parameters
- State encoding/decoding
- Certificate signing operations

## Security Considerations

- **Short-lived certificates**: Default 8-hour validity reduces risk
- **Stateless design**: No session data stored server-side
- **Role-based access**: Users only get principals for their assigned roles
- **OAuth security**: Leverages Google's OAuth 2.0 implementation
- **Certificate transparency**: All certificates include email and role in KeyId (service certificates use `<name>@service`)
- **Service tokens are CA capability**: A `/sign` token mints certificates for its principals — protect it like a private key, pin it with `source_address`, and never expose the server to the internet
- **Separate keys per protocol**: HTTP credentials are signed with `jwt.signing_key`, never with the SSH CA key; rotating or losing one does not affect the other
- **HTTP credentials are key-bound, not revocable**: A token is useless without the client's private key (DPoP), but cannot be cancelled before it expires — keep `jwt.validity` short

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT
