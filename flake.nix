{
  description = "Carrack data transport and Cloudflare control plane";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
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
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            go1265
            golangci-lint
            govulncheck
            cargo
            rustc
            rustfmt
            clippy
            lld
            worker-build
            nodejs_24
            pnpm
            just
            git
            jq
            ripgrep
          ];

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
