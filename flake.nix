{
  description = "VouSSH - SSH Certificate Authority server and client";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    gomod2nix = {
      url = "github:nix-community/gomod2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, gomod2nix }:
    let
      # NixOS module for the voussh server
      nixosModule = { config, lib, pkgs, ... }:
        with lib;
        let
          cfg = config.services.voussh;
          settingsFormat = pkgs.formats.yaml { };
          configFile = settingsFormat.generate "config.yaml" cfg.settings;
        in
        {
          options.services.voussh = {
            enable = mkEnableOption "VouSSH SSH Certificate Authority server";

            package = mkOption {
              type = types.package;
              default = self.packages.${pkgs.system}.voussh;
              defaultText = literalExpression "pkgs.voussh";
              description = "The voussh package to use";
            };

            dataDir = mkOption {
              type = types.path;
              default = "/var/lib/voussh";
              description = "Directory where voussh stores its data (CA keys)";
            };

            user = mkOption {
              type = types.str;
              default = "voussh";
              description = "User under which voussh runs";
            };

            group = mkOption {
              type = types.str;
              default = "voussh";
              description = "Group under which voussh runs";
            };

            settings = mkOption {
              type = types.submodule {
                freeformType = settingsFormat.type;
                options = {
                  addr = mkOption {
                    type = types.str;
                    default = ":8080";
                    description = "Address and port to listen on";
                  };

                  ca_key = mkOption {
                    type = types.str;
                    default = "/var/lib/voussh/ca_key";
                    description = "Path to CA private key (without extension)";
                  };

                  cert_validity = mkOption {
                    type = types.str;
                    default = "8h";
                    description = "Certificate validity duration";
                  };

                  client_id = mkOption {
                    type = types.str;
                    description = "Google OAuth client ID";
                  };

                  client_secret = mkOption {
                    type = types.str;
                    description = "Google OAuth client secret";
                  };

                  redirect_url = mkOption {
                    type = types.str;
                    description = "OAuth callback URL";
                  };

                  users = mkOption {
                    type = types.attrsOf (types.attrsOf (types.listOf types.str));
                    default = { };
                    example = literalExpression ''
                      {
                        "alice@example.com" = {
                          default = [ "root" "admin" ];
                          deploy = [ "deploy" ];
                        };
                        "bob@example.com" = {
                          default = [ "developer" ];
                        };
                      }
                    '';
                    description = "User to role to principals mapping";
                  };

                  tls = mkOption {
                    type = types.nullOr (types.submodule {
                      options = {
                        cert = mkOption {
                          type = types.str;
                          description = "Path to TLS certificate";
                        };
                        key = mkOption {
                          type = types.str;
                          description = "Path to TLS key";
                        };
                      };
                    });
                    default = null;
                    description = "TLS configuration";
                  };
                };
              };
              default = { };
              description = "VouSSH configuration";
            };
          };

          config = mkIf cfg.enable {
            # Create system user and group
            users.users.${cfg.user} = {
              isSystemUser = true;
              group = cfg.group;
              home = cfg.dataDir;
              createHome = true;
              description = "VouSSH server user";
            };

            users.groups.${cfg.group} = { };

            # Create systemd service
            systemd.services.voussh = {
              description = "VouSSH SSH Certificate Authority server";
              wantedBy = [ "multi-user.target" ];
              after = [ "network.target" ];

              serviceConfig = {
                Type = "simple";
                User = cfg.user;
                Group = cfg.group;
                WorkingDirectory = cfg.dataDir;
                ExecStart = "${cfg.package}/bin/voussh --config ${configFile}";
                Restart = "on-failure";
                RestartSec = "10s";

                # Security hardening
                NoNewPrivileges = true;
                PrivateTmp = true;
                ProtectSystem = "strict";
                ProtectHome = true;
                ReadWritePaths = [ cfg.dataDir ];
                PrivateDevices = true;
                ProtectKernelTunables = true;
                ProtectKernelModules = true;
                ProtectControlGroups = true;
                RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
                RestrictNamespaces = true;
                LockPersonality = true;
                RestrictRealtime = true;
                RestrictSUIDSGID = true;
                SystemCallFilter = "@system-service";
                SystemCallErrorNumber = "EPERM";
              };

              preStart = ''
                # Initialize CA keys if they don't exist
                if [ ! -f "${cfg.settings.ca_key}" ]; then
                  ${cfg.package}/bin/voussh init "${cfg.settings.ca_key}"
                fi
              '';
            };
          };
        };

      # Home Manager module for the vsh client
      homeManagerModule = { config, lib, pkgs, ... }:
        with lib;
        let
          cfg = config.programs.vsh;
        in
        {
          options.programs.vsh = {
            enable = mkEnableOption "VouSSH client";

            package = mkOption {
              type = types.package;
              default = self.packages.${pkgs.system}.vsh;
              defaultText = literalExpression "pkgs.vsh";
              description = "The vsh package to use";
            };

            enableShellIntegration = mkOption {
              type = types.bool;
              default = true;
              description = "Whether to enable shell integration for local sessions";
            };

            defaultServer = mkOption {
              type = types.nullOr types.str;
              default = null;
              example = "https://voussh.example.com";
              description = "Default VouSSH server URL";
            };
          };

          config = mkIf cfg.enable {
            home.packages = [ cfg.package ];

            # Add shell integration for bash
            programs.bash.initExtra = mkIf cfg.enableShellIntegration ''
              # VouSSH shell integration for local sessions
              eval "$(${cfg.package}/bin/vsh init)"
              ${optionalString (cfg.defaultServer != null) ''
                export VSH_SERVER="${cfg.defaultServer}"
              ''}
            '';

            # Add shell integration for zsh
            programs.zsh.initExtra = mkIf cfg.enableShellIntegration ''
              # VouSSH shell integration for local sessions
              eval "$(${cfg.package}/bin/vsh init)"
              ${optionalString (cfg.defaultServer != null) ''
                export VSH_SERVER="${cfg.defaultServer}"
              ''}
            '';

            # Add shell integration for fish
            programs.fish.shellInit = mkIf cfg.enableShellIntegration ''
              # VouSSH shell integration for local sessions
              ${cfg.package}/bin/vsh init | source
              ${optionalString (cfg.defaultServer != null) ''
                set -gx VSH_SERVER "${cfg.defaultServer}"
              ''}
            '';
          };
        };
    in
    {
      # Export the modules
      nixosModules.default = nixosModule;
      nixosModules.voussh = nixosModule;

      homeManagerModules.default = homeManagerModule;
      homeManagerModules.vsh = homeManagerModule;

    } // flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        # Import gomod2nix builder
        buildGoApplication = gomod2nix.legacyPackages.${system}.buildGoApplication;
      in
      {
        packages = {
          voussh = buildGoApplication {
            pname = "voussh";
            version = "0.1.0";
            src = ./.;
            pwd = ./.;

            subPackages = [ "cmd/voussh" ];

            ldflags = [ "-s" "-w" "-extldflags=-static" ];

            meta = with pkgs.lib; {
              description = "SSH Certificate Authority server";
              homepage = "https://github.com/voussh/voussh";
              license = licenses.mit;
              maintainers = [ ];
              mainProgram = "voussh";
            };
          };

          vsh = buildGoApplication {
            pname = "vsh";
            version = "0.1.0";
            src = ./.;
            pwd = ./.;

            subPackages = [ "cmd/vsh" ];

            ldflags = [ "-s" "-w" "-extldflags=-static" ];

            meta = with pkgs.lib; {
              description = "VouSSH client for SSH certificate management";
              homepage = "https://github.com/voussh/voussh";
              license = licenses.mit;
              maintainers = [ ];
              mainProgram = "vsh";
            };
          };

          default = self.packages.${system}.vsh;
        };

        apps = {
          voussh = flake-utils.lib.mkApp {
            drv = self.packages.${system}.voussh;
          };

          vsh = flake-utils.lib.mkApp {
            drv = self.packages.${system}.vsh;
          };

          default = self.apps.${system}.vsh;
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go_1_24
            gopls
            gotools
            go-tools
            gomod2nix.packages.${system}.default
          ];
        };
      });
}