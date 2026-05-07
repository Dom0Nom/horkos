# Next Phase: Phase 3 — Windows KMDF Watchdog + SDK Wiring

Phase 2 (`phase-2-server`) is complete. Phase 3 starts after that PR merges.

## Prerequisites for Phase 3

### Windows build environment
- **Windows VM or CI runner** with Windows 11 24H2 (or later).
- **WDK** (Windows Driver Kit) — installs to `C:\Program Files (x86)\Windows Kits\10\`.
- **Visual Studio Build Tools** with the Spectre-mitigated MSVC toolset.
- **Test-signing enabled in the VM**: `bcdedit /set testsigning on`.
- **`verifier.exe`** configured against the Horkos driver before any load.

### Signing strategy
- **Test-signing for Phase 3 acceptance.** Documented in `docs/windows-signing.md`
  (created in Step 3.1).
- **EV code-signing certificate** is a **ship prerequisite, not a Phase 3 prerequisite.**
  Procurement was kicked off in Phase 0 (DigiCert/Sectigo lead time is 1–4 weeks
  plus a hardware token). See risk register entry R11.
- **WHQL submission** is a separate ship prerequisite tracked under R12.

### Snapshot-ready VM
All kernel work happens in a snapshot-ready Windows VM. Before any IRQL-sensitive
code change, take a snapshot. CLAUDE.md guardrail #13 applies: when uncertain
about a kernel API, stop and flag.

### Split decision
Phase 3 has a defined split seam (3a kernel skeleton + 3b SDK and BYOVD
plumbing). Per risk register R13, if Sonnet 4.6 estimates more than two
sessions of focused work, split Phase 3 into 3a/3b at the seam between
Step 3.4 and Step 3.5. Record the split in the Mutation log.

## Server side (carries over from Phase 2)

- Server workspace builds clean: `cargo build --workspace --release` in `server/`.
- `cargo test --workspace` is green; clippy `-D warnings` clean; rustfmt clean.
- Cargo workspace pinned to Rust 1.95.0 (see Mutation log for the bump from 1.83.0).
- ort 2.0.0-rc.10 wired but no model loaded. CPU provider only.
- GDPR-17 deletion route returns `503 + Retry-After: 86400`. Flip to 202 + 30-day
  SLA is gated on the durable persistence + worker phase under `/tdd`.
- ban-engine fail-closed gate is enforced: release+`unverified_bundles_dev_only`
  combination is rejected at compile time.

## Phase 4 prerequisites (early heads-up)

- Linux CI image needed: `tpm2-tss-dev`, `libbpf-dev`, `clang-19`, `bpftool`.
- macOS host needed for daemon work; ES entitlement application starts now
  (Apple lead time is independent of code work).
