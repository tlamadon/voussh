# VouSSH - OAuth-based SSH Certificate Authority

A stateless, lightweight SSH Certificate Authority server and client that authenticates users via Google OAuth and issues short-lived SSH certificates based on role assignments. 

## Features

- 🔐 **Google OAuth authentication** - Leverage existing Google Workspace identities
- 🎫 **Short-lived certificates** - Time-bound certificates reduce security risks
- 👥 **Role-based access** - Map users to roles with specific SSH principals
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
```

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
- **Certificate transparency**: All certificates include email and role in KeyId

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT
