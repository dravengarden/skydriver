# AGENTS.md — Carrack

Carrack is a business-neutral, content-addressed data transport and encrypted
archive system. It must not contain exchange adapters, dataset catalogs,
ingestion schedules, trading semantics, or other consumer-specific behavior.

## Architecture

- `crates/carrack-client/`, `crates/carrack-cli/`: canonical Rust client core
  and the `carrack`/`carrackctl` binaries.
- `cmd/`, `archive/`, `manifest/`, `provider/`, `sdk/`: compatibility Go
  implementation retained while commands migrate behind language-neutral
  contracts. It must not gain new provider lifecycle policy.
- `control-plane/`: Rust Cloudflare Worker for auth, index, jobs, and status.
- `web/`: strict TypeScript SPA using React, TanStack, and MUI.
- `schemas/`: language-neutral wire contracts.

V1 supports direct transfer only. Data bytes flow between a Carrack agent and
storage providers. The Worker is a control plane and must never relay object or
block payloads.

The control plane and client SDK are the only product components. CLI and
agent processes are SDK consumers, not a third architectural component.

## Rules

- All code, comments, commit messages, and docs are English.
- Carrack is the canonical product, repository, CLI, SDK, client, and protocol
  name. Consumer projects depend on Carrack; Carrack never depends on them.
- Go uses the Columbus maximum-strictness golangci-lint profile.
- TypeScript is strict: no `any`, no unchecked boundary casts.
- Secrets and credentials never enter Git. D1 stores only password hashes,
  token verifiers, and encrypted provider-credential envelopes. Pack keys are
  derived rather than stored. Root seeds stay in Cloudflare secrets or Secrets
  Store and have offline recovery copies.
- Run `just verify` before committing.
- Use `.agents/skills/carrack-admin` for Carrack management inspection and
  supported VFS policy changes. Agents must not bypass its CLI validation with
  direct D1 writes or reconstructed management HTTP requests.
- Treat `docs/requirements.md` as the normative product and correctness
  baseline. Architecture and implementation changes must preserve its MUST and
  MUST NOT guarantees or revise the requirements deliberately.
