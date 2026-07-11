# AGENTS.md — Carrack

Carrack is a low-cost, content-addressed data transport system. The first
source is Hyperliquid public data, but transport and storage abstractions must
remain source-neutral.

## Architecture

- `cmd/carrack/`, `archive/`, `manifest/`, `provider/`, `sdk/`: Go CLI and SDK.
- `control-plane/`: Rust Cloudflare Worker for auth, index, jobs, and status.
- `web/`: strict TypeScript SPA using React, TanStack, and MUI.
- `schemas/`: language-neutral wire contracts.

V1 supports direct transfer only. Data bytes flow between a Carrack agent and
storage providers. The Worker is a control plane and must never relay object or
block payloads.

## Rules

- All code, comments, commit messages, and docs are English.
- Carrack is the canonical product, repository, CLI, SDK, agent, and protocol
  name. Do not introduce `dp`, `data-pipeline`, or similar aliases.
- Go uses the Columbus maximum-strictness golangci-lint profile.
- TypeScript is strict: no `any`, no unchecked boundary casts.
- Secrets and credentials never enter Git. Preset UI credentials are supplied
  through Cloudflare secrets as a username and an Argon2id PHC password hash.
- Run `just verify` before committing.
