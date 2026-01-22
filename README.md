# voussh - Minimal SSH Certificate Authority

A lightweight SSH Certificate Authority that authenticates users via Google OAuth and issues SSH certificates based on group memberships.

## Quick Start

### Setup

1. Configure Google OAuth credentials in `config.yaml`
2. Install dependencies: `go mod download`
3. Build binaries:
   ```bash
   go build -o voussh cmd/voussh/main.go
   go build -o vsh cmd/vsh/main.go
   ```

### Server

```bash
./voussh
```

The server reads `config.yaml` and starts on the configured address (default `:8080`).

### Client Usage

```bash
# First time login
vsh login --server http://localhost:8080

# Sign your SSH key (uses default ~/.ssh/id_ed25519.pub)
vsh sign

# Sign a specific key
vsh sign ~/.ssh/other_key.pub

# Check login status
vsh status

# Get CA public key (for server configuration)
vsh pubkey >> ~/.ssh/authorized_keys

# SSH to a configured target server
vsh ssh prod-web-01

# List available SSH targets
vsh ssh
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

### Server Configuration

Edit `config.yaml` to:
- Set Google OAuth credentials
- Define user groups and their SSH principals
- Map user emails to groups
- Configure certificate validity period

### SSH Targets Configuration

Edit `targets.yaml` to:
- Define SSH target servers with hostnames and ports
- Set user accounts for each target
- Configure access groups that can connect to each target
- Optionally set proxy commands for jump hosts

Example `targets.yaml`:
```yaml
targets:
  prod-web-01:
    host: web01.prod.example.com
    user: deploy
    port: 22
    groups: [admin, dev]
    description: Production web server
```

## Architecture

- **voussh**: Server that handles OAuth flow and signs SSH certificates
- **vsh**: CLI client for authentication and certificate management
- Certificates include principals based on group membership
- All certificates are time-limited (default 8 hours)