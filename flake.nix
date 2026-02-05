{
  description = "Icebreaker - A Rust library for secure API proxy with cryptographic audit trails";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, crane, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        # Extract version from workspace Cargo.toml
        workspaceCargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
        version = workspaceCargoToml.workspace.package.version;

        # Use Rust version from rust-toolchain.toml
        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Common source filtering
        src = craneLib.cleanCargoSource ./.;

        # Common build inputs (runtime dependencies)
        commonBuildInputs = with pkgs; [ openssl ]
          ++ lib.optionals stdenv.isDarwin [
            darwin.apple_sdk.frameworks.Security
            darwin.apple_sdk.frameworks.SystemConfiguration
          ];

        # Common native build inputs (build-time tools)
        commonNativeBuildInputs = with pkgs; [ pkg-config ];

        # Common arguments for all builds
        commonArgs = {
          inherit src;
          pname = "icebreaker";
          inherit version;
          buildInputs = commonBuildInputs;
          nativeBuildInputs = commonNativeBuildInputs;
        };

        # Build dependencies separately for caching
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        # The main crate build
        icebreaker = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          cargoExtraArgs = "--all-features";
          meta = with pkgs.lib; {
            description = "A Rust library for secure API proxy with cryptographic audit trails";
            homepage = "https://github.com/windowlickers/icebreaker";
            license = licenses.mit;
            maintainers = [
              {
                name = "Evan Dobry";
                email = "evandobry@gmail.com";
                github = "ecdobry";
                githubId = 16653165;
              }
            ];
          };
        });

        # The CLI binary
        icebreaker-cli = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
          cargoExtraArgs = "--package icebreaker-cli";
          meta = with pkgs.lib; {
            description = "CLI for Icebreaker - A Rust library for secure API proxy with cryptographic audit trails";
            homepage = "https://github.com/windowlickers/icebreaker";
            license = licenses.mit;
            maintainers = [
              {
                name = "Evan Dobry";
                email = "evandobry@gmail.com";
                github = "ecdobry";
                githubId = 16653165;
              }
            ];
          };
        });

        # Container image
        icebreakerImage = import ./image.nix {
          inherit pkgs icebreaker-cli version;
        };

        # Load image into Docker
        loadImage = pkgs.writeShellScriptBin "load" ''
          set -euo pipefail
          echo "Loading icebreaker:${version} into Docker..."
          ${pkgs.docker}/bin/docker load < ${icebreakerImage}
          echo "Loaded icebreaker:${version}"
        '';

        # Push image to Harbor
        registry = "harbor.windowlicke.rs/windowlickers";
        pushImage = pkgs.writeShellScriptBin "push" ''
          set -euo pipefail
          echo "Pushing to ${registry}/icebreaker:${version}..."
          ${pkgs.skopeo}/bin/skopeo --insecure-policy copy \
            docker-archive:${icebreakerImage} \
            docker://${registry}/icebreaker:${version}
          echo "Pushing to ${registry}/icebreaker:latest..."
          ${pkgs.skopeo}/bin/skopeo --insecure-policy copy \
            docker-archive:${icebreakerImage} \
            docker://${registry}/icebreaker:latest
          echo "Pushed ${version}"
        '';

      in
      {
        # `nix flake check` runs all of these
        checks = {
          inherit icebreaker icebreaker-cli;

          fmt = craneLib.cargoFmt { inherit src; };

          clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets --all-features -- -D warnings";
          });

          tests = craneLib.cargoTest (commonArgs // {
            inherit cargoArtifacts;
            cargoTestExtraArgs = "--all-features";
          });
        };

        packages = {
          inherit icebreaker icebreaker-cli;
          icebreaker-image = icebreakerImage;
          default = icebreaker;
        };

        apps = {
          load = { type = "app"; program = "${loadImage}/bin/load"; };
          push = { type = "app"; program = "${pushImage}/bin/push"; };
        };

        devShells.default = craneLib.devShell {
          checks = self.checks.${system};
          packages = with pkgs; [
            cargo-watch
            cargo-edit
            cargo-outdated
            cargo-audit
            cargo-expand
            skopeo
            dive
          ];

          # Environment variables
          RUST_BACKTRACE = "1";
        };

        # Formatter
        formatter = pkgs.nixpkgs-fmt;
      }
    );
}
