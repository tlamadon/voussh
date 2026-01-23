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
    flake-utils.lib.eachDefaultSystem (system:
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