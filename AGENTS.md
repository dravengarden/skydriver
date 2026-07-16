# AGENTS.md — Carrack

Carrack is a business-neutral, content-addressed data transport and encrypted
archive system. It must not contain exchange adapters, dataset catalogs,
ingestion schedules, trading semantics, or other consumer-specific behavior.

## Architecture

- `crates/carrack-sdk-core/`: stable, portable correctness kernel split into
  orthogonal canonical, integrity, crypto, catalog, and acceptance modules.
- `crates/carrack-client/`: native I/O, driver, recovery, and publication
  orchestration that delegates wire correctness to `carrack-sdk-core`.
- `crates/carrack-cli/`: thin `carrack`/`carrackctl` SDK consumers; business or
  protocol rules do not belong here.
- `driver/`, `transfer/journal/`, `vfs/`: narrow Go conformance oracles for the
  complete-object contract, recovery journal, and shared binary vectors. They
  are not a public SDK or installation surface and must not gain product
  behavior.
- `control-plane/`: Rust Cloudflare Worker for auth, index, jobs, and status.
- `web/`: strict TypeScript SPA using React, TanStack, and MUI.
- `docs/vfs-*.md`: language-neutral wire contracts and correctness invariants.

V2 supports direct transfer only. Data bytes flow between a Carrack agent and
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
- Merkle domains, block-manifest rules, encryption derivation, and catalog
  closure logic belong only in the matching `carrack-sdk-core` module. Worker,
  client, CLI, and UI may adapt values and improve diagnostics but must not
  duplicate those algorithms.
- Secrets and credentials never enter Git. D1 stores only password hashes,
  token verifiers, encrypted provider-credential envelopes, and wrapped VFS
  directory keys. VFS master keys stay in Cloudflare secrets or Secrets Store
  and have tested offline recovery copies.
- The pinned Nix development shell owns the Go, Rust, Node, Worker, and lint
  toolchains. From the repository root, run project commands as
  `nix develop -c <command>`; never use the host Rustup/Cargo toolchain for a
  preliminary check. If a compiler or linker resolves through `~/.rustup` or a
  missing Nix-store wrapper, stop and correct the shell rather than changing
  code or the host toolchain.
- Run `nix develop -c just verify` before committing.
- Use `.agents/skills/carrack-admin` for Carrack management inspection and
  supported VFS policy changes. Agents must not bypass its CLI validation with
  direct D1 writes or reconstructed management HTTP requests.
- Treat `docs/requirements.md` as the normative product and correctness
  baseline. Architecture and implementation changes must preserve its MUST and
  MUST NOT guarantees or revise the requirements deliberately.
- Legacy Go archive packages, public Go CLIs, packs, extents, bundles, leaf
  merging, and compaction are forbidden. Product behavior belongs in the Rust
  client, Worker, or their language-neutral contracts.
