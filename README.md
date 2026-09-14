# VouSSH - OAuth-based SSH Certificate Authority

A stateless, lightweight SSH Certificate Authority server and client that authenticates users via Google OAuth and issues short-lived SSH certificates based on role assignments. 

## Features

- 🔐 **Google OAuth authentication** - Leverage existing Google Workspace identities
- 🎫 **Short-lived certificates** - Time-bound certificates reduce security risks
- 👥 **Role-based access** - Map users to roles with specific SSH principals
- 📱 **Device flow** - Log in on a headless or remote machine by approving from your phone or laptop
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

# Show help
./voussh --help
```

The server provides:
- OAuth login endpoint: `/login`
- OAuth callback endpoint: `/callback`
- CA public key endpoint: `/pubkey`
- Health check endpoint: `/health`

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
| `extensions` | Global SSH cert extensions (optional; defaults to `permit-pty`, `permit-agent-forwarding`, `permit-user-rc`) |
| `roles` | Per-role policy overrides (optional; each role may set `validity`, `extensions` and/or `source_address`) |
| `services` | Machine credentials for `POST /sign` (optional — see [Machine authentication](#machine-authentication-sign)) |
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
`services`, and `device_flow.enabled`. These take effect on the next
certificate issued — a newly added service becomes usable without a restart.

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

# Show version
vsh version
```

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

- **voussh**: Server that handles OAuth flow and signs SSH certificates
- **vsh**: CLI client for authentication and certificate management
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

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT
