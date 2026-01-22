# voussh - Minimal SSH Certificate Authority

A lightweight SSH Certificate Authority that authenticates users via Google OAuth and issues SSH certificates based on role assignments.

## Quick Start

### Setup

1. Generate a CA key pair:
   ```bash
   ./voussh init
   ```

2. Configure Google OAuth credentials in `config.yaml`

3. Build binaries:
   ```bash
   go build -o voussh cmd/voussh/main.go
   go build -o vsh cmd/vsh/main.go
   ```

### Server (voussh)

```bash
# Generate CA key pair
./voussh init [path]

# Start server (reads config.yaml)
./voussh
```

The server starts on the configured address (default `:8080`).

### Client (vsh)

```bash
# Login and obtain SSH certificate
vsh login --server http://localhost:8080

# Login with a specific role
vsh login --server http://localhost:8080 --role admin

# Check certificate status
vsh status

# SSH to a host using your certificate
vsh ssh user@hostname

# SSH with additional options
vsh ssh user@hostname -L 8080:localhost:80

# Get CA public key (for server configuration)
vsh pubkey
```

### SSH Server Configuration

Add the CA public key to your SSH server's trusted user certificate authorities:

```bash
# Get CA public key
vsh pubkey > /etc/ssh/ca.pub

# Configure sshd_config
echo "TrustedUserCAKeys /etc/ssh/ca.pub" >> /etc/ssh/sshd_config
systemctl reload sshd
```

## Configuration

### Server Configuration (config.yaml)

```yaml
addr: ":8080"
ca_key: "./ca_key"
cert_validity: 8h

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
| `cert_validity` | Certificate validity duration (e.g., `8h`, `24h`) |
| `client_id` | Google OAuth client ID |
| `client_secret` | Google OAuth client secret |
| `redirect_url` | OAuth callback URL |
| `users` | User authorization mapping |

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

## Architecture

- **voussh**: Server that handles OAuth flow and signs SSH certificates
- **vsh**: CLI client for authentication and certificate management
- Certificates are signed during the OAuth callback flow
- Principals are assigned based on the requested role
- All certificates are time-limited (default 8 hours)

## How It Works

1. User runs `vsh login --server <url>`
2. Browser opens to Google OAuth
3. After authentication, the server signs the user's SSH public key
4. Certificate is returned to the CLI via local callback server
5. Certificate is saved to `~/.ssh/id_ed25519-cert.pub`
6. User can now SSH to any server that trusts the CA
