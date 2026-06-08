# Horkos Ship Readiness

What stands between the current scaffold and a production alpha. Each item is a
hard gate, not a nice-to-have. Ordered roughly by lead time.

## Signing & attestation (longest lead time)

- [ ] **EV code-signing certificate** on a hardware token (DigiCert/Sectigo,
      1–4 weeks). Required for the Windows driver and any external distribution.
      Risk register R11.
- [ ] **WHQL / attestation signing** via Microsoft Hardware Dev Center for the
      boot-start kernel driver on Secure-Boot machines. Risk register R12.
- [ ] **Apple `endpoint-security.client` entitlement** approval. Until then macOS
      ships the userspace daemon only (Locked Decision #4, risk register R1).
- [ ] **ObRegisterCallbacks Allocated Altitude** from Microsoft (the dev
      placeholder `385201` must be replaced).

## Kernel verification (blocked on hardware, not code)

- [ ] Windows KMDF driver compiled against a real WDK (CI job `win-driver` in
      `.github/workflows/ci.yml`) — blocked on that job running green.
- [ ] Driver loaded in a snapshot VM with `verifier /standard` clean across
      multiple reboots; `hk_ioctl_smoke` passes against the loaded driver.
- [ ] Linux eBPF programs load + attach on a CI kernel (Phase 4).
- [ ] macOS daemon + ES target build and load (Phase 4).

## Functional gaps (code, in later phases)

- [ ] **GDPR-17 deletion logic** — flip the route from `503` to `202` + 30-day
      SLA once the durable store + deletion worker land (`docs/gdpr-17-rollout.md`,
      risk register R10).
- [ ] **Signed rule-bundle pipeline** — Ed25519 verification + weekly rotation
      replacing the fail-closed placeholder in `ban-engine`.
- [ ] **BYOVD blocklist ingestion** — the kernel `Whitelist.c` list is empty;
      wire it to the signed bundle. Real enforcement + the self-built vulnerable
      test fixture activate the `bypass-tests/win/byovd_load` assertions.
- [ ] **ML model training + inference path** — `ort` is wired but no model is
      loaded; the behavioural ban path is not yet real.
- [ ] **TPM / Secure Enclave attestation backends** — currently `NotImplemented`
      stubs behind the stable `Attestation.h` interface.
- [ ] **Real anti-debug / DMA enforcement** — Phase 1/4 land detection scaffolds;
      DMA detection is detect-and-report only (UEFI firmware caveat,
      `docs/dma-detection.md`).

## Merge gates (operational)

- [ ] Every security-folder change carries a bypass test (guardrail #12). Phase 5
      lands one representative test per PC platform, disabled until enforcement.
- [ ] Every telemetry field is declared in `server/api/data-categories.md`
      (guardrail #11).
- [ ] The obfuscator is a build-time tool only and is never shipped
      (Locked Decision #5).

## Console (separately gated, NDA)

- [ ] NintendoSDK / PlayStation integrations need NDA + dev-account access; only
      public-doc-shaped GDK stubs exist today (Locked Decision #7).
