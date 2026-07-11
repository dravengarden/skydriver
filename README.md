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

The V1 default layout uses 128 MiB physical blocks, 8 MiB crypto frames, and
8 GiB logical packs. These are defaults rather than protocol constants.

## Development

```bash
nix develop
just verify
```

This repository is private. Credentials belong in runtime secret stores, never
in tracked files.
