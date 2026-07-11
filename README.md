# Carrack

Carrack is a low-cost data transport and archive system for moving public
market data through consumer and cloud storage without coupling research code
to a specific provider.

The first release targets Hyperliquid public S3 data and direct transfers to
R2 or Aliyun Drive. A Go agent performs every payload transfer. A Rust
Cloudflare Worker with D1 provides the control plane and serves a React web
console; it does not relay data bytes.

## Initial layout

- `archive`: configurable physical block and crypto frame layout.
- `manifest`: versioned, content-addressed archive manifests.
- `provider`: storage provider boundaries.
- `sdk`: embeddable transfer planning API used by Lightsail and local agents.
- `cmd/carrack`: operator CLI.
- `control-plane`: Cloudflare Worker and D1 migrations.
- `web`: Carrack control console.
- `schemas`: shared protocol schemas.

## Provider status

The Go SDK includes an Aliyun Drive provider for the official Open API. It
supports OpenList-compatible OAuth renewal without running an OpenList server,
automatic folder creation, bounded-memory multipart uploads, metadata lookup,
and exact range downloads. The provider deliberately keeps uploads sequential
and applies the same conservative per-operation request limits as OpenList.

OpenList cannot be consumed as a normal Go SDK because its public driver
packages expose contracts from Go `internal` packages. Carrack therefore owns
a narrow adapter aligned to a recorded OpenList commit; see
`provider/aliyundrive/UPSTREAM.md`.

Credentials are runtime dependencies. Callers may use a fixed access token or
the OpenList-compatible refresh-token source. A rotated refresh token must be
persisted through the supplied callback before the new access token is used.
Neither tokens nor download URLs belong in manifests, D1, logs, or Git.

The V1 default layout uses 128 MiB physical blocks, 8 MiB crypto frames, and
8 GiB logical packs. These are defaults rather than protocol constants.

## Development

```bash
cp .env.example .env
chmod 600 .env
nix develop
just verify
```

Cloudflare operator authentication, D1 migrations, runtime secrets, and deploy
commands are documented in `docs/cloudflare.md`.

This repository is private. Credentials belong in runtime secret stores, never
in tracked files.
