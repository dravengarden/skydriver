# Contributing to Skydriver

Thanks for helping improve Skydriver. Keep changes focused, documented, and
compatible with the security and correctness requirements in
[`docs/requirements.md`](docs/requirements.md).

## Development environment

Use the pinned Nix development shell from the repository root:

```bash
nix develop -c just verify
```

The shell supplies the Rust, Go, Node, pnpm, Worker, formatting, lint, and test
toolchains. Do not commit generated build output, local Wrangler state, or
environment files.

Useful inner-loop commands include:

```bash
nix develop -c just check-format
nix develop -c just verify-fast
nix develop -c just test-fast
nix develop -c just secrets-check
```

Live provider acceptance is opt-in. It requires an explicitly supplied control
URL and short-lived test token; do not add a deployment URL or credential to a
test default.

## Change requirements

- Keep product behavior provider-neutral and preserve the complete-object
  contract.
- Update protocol documentation and golden or regression tests when wire
  formats, cryptographic domains, migrations, or authorization rules change.
- Keep secrets, personal data, private URLs, account identifiers, and provider
  credentials out of source, fixtures, logs, and commit messages.
- Use a public dependency with a reviewed license; do not add private Git
  dependencies.
- Keep the browser console and `skydriverctl` on the same server validation
  contract.

## Pull requests

Describe the behavior change, security impact, migration impact, and commands
used for verification. Include focused tests for regressions and call out any
validation that requires an external provider or physical device.
