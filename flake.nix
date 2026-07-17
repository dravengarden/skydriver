{
  description = "Carrack data transport and Cloudflare control plane";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
  };

  outputs =
    {
      nixpkgs,
      flake-utils,
      rust-overlay,
      crane,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
        lib = pkgs.lib;
        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
        version = "0.3.6";
        cargoSrc = craneLib.cleanCargoSource ./.;
        rustSrc = lib.cleanSourceWith {
          src = lib.cleanSource ./.;
          filter =
            path: type:
            craneLib.filterCargoSources path type
            || path == toString ./testdata
            || lib.hasPrefix "${toString ./testdata}/" (toString path);
          name = "carrack-rust-source";
        };
        cargoArtifacts = craneLib.buildDepsOnly {
          pname = "carrack-deps";
          inherit version;
          src = cargoSrc;
          strictDeps = true;
          cargoExtraArgs = "--locked --package carrack-cli";
          # The repository gate owns Clippy and workspace tests, while the
          # final package still runs carrack-cli's release tests. This layer
          # only needs linkable dependency artifacts.
          buildPhaseCargoCommand = "cargoWithProfile build --locked --package carrack-cli";
          doCheck = false;
        };
        carrack = craneLib.buildPackage {
          pname = "carrack";
          inherit version cargoArtifacts;
          src = rustSrc;
          strictDeps = true;
          cargoExtraArgs = "--locked --package carrack-cli";
          meta = {
            description = "Encrypted complete-object VFS client and operator CLI";
            mainProgram = "carrack";
          };
        };
        go1265 = pkgs.go.overrideAttrs (
          _finalAttrs: _previousAttrs: {
            version = "1.26.5";
            src = pkgs.fetchurl {
              # The official archive redirects to a Google endpoint blocked on
              # hawk. The hash is the checksum published by go.dev.
              url = "https://mirrors.aliyun.com/golang/go1.26.5.src.tar.gz";
              hash = "sha256-SVvkvIcXasVnOS5bQRar2YRm0z17SdQedkzMaXay3EI=";
            };
          }
        );
      in
      {
        packages = {
          default = carrack;
          inherit carrack;
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            go1265
            golangci-lint
            govulncheck
            rustToolchain
            sccache
            cargo-nextest
            cargo-deny
            cargo-machete
            rust-analyzer
            worker-build
            nodejs_24
            pnpm
            just
            nixfmt
            git
            jq
            ripgrep
          ];

          RUSTC_WRAPPER = "sccache";

          shellHook = ''
            export PATH="$PWD/bin:$PWD/node_modules/.bin:$PATH"
            if [ -f .env ]; then
              set -a
              . ./.env
              set +a
              echo "carrack: loaded Cloudflare deployment credentials from .env"
            fi
            echo "carrack dev shell — $(go version | cut -d' ' -f3) · $(rustc --version | cut -d' ' -f2) · pnpm $(pnpm --version)"
          '';
        };

        formatter = pkgs.nixfmt;
      }
    );
}
