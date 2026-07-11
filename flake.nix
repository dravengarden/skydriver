{
  description = "Carrack data transport and Cloudflare control plane";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            go
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
            echo "carrack dev shell — $(go version | cut -d' ' -f3) · $(rustc --version | cut -d' ' -f2) · pnpm $(pnpm --version)"
          '';
        };

        formatter = pkgs.nixfmt;
      });
}
