# VouSSH - OAuth-based SSH Certificate Authority

A stateless, lightweight SSH Certificate Authority that authenticates users via Google OAuth and issues short-lived SSH certificates based on role assignments. Perfect for managing SSH access in modern cloud environments.

## Features

- 🔐 **Google OAuth authentication** - Leverage existing Google Workspace identities
- 🎫 **Short-lived certificates** - Time-bound certificates reduce security risks
- 👥 **Role-based access** - Map users to roles with specific SSH principals
- 🚀 **Stateless server** - Horizontally scalable, no session storage
- 🔧 **Simple setup** - Minimal configuration required
- 🌐 **HTTPS support** - Optional TLS for secure deployments
- 🏥 **Health endpoints** - Built-in monitoring support

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

### Client (vsh)

```bash
# Login and obtain SSH certificate
vsh login --server http://localhost:8080

# Login with a specific role
vsh login --server http://localhost:8080 --role admin

# Check certificate status
vsh status

# Logout and remove certificate
vsh logout

# SSH to a host using your certificate
vsh ssh user@hostname

# SSH with additional options
vsh ssh user@hostname -L 8080:localhost:80

# Get CA public key (for server configuration)
vsh pubkey
```

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

For NixOS systems, add the CA configuration to your system configuration:

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

## Configuration

### Server Configuration (config.yaml)

```yaml
addr: ":8080"
ca_key: "./ca_key"
cert_validity: 8h

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
- **Certificate transparency**: All certificates include email and role in KeyId

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT
