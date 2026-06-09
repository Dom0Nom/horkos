# macOS — Code-Signing & Platform Trust — Implementation Plan

**Scope:** read-only macOS sensors that verify the trust posture of the running
game image and the host: code-signing flags, cdhash/notarization parity,
dynamic SecCode validity, library-validation conformance, amfid integrity, AMFI
boot/Developer-Mode posture, Gatekeeper provenance, and entitlement-blob drift.
All sensors **sample and report**; the server scores and bans. No signature
forging, no page writes, no enforcement on-box. Every ES event used here is a
NOTIFY event (no auth reply involved) except where noted.

**Catalog signals covered:** 118 (CS_HARD/CS_KILL flag drift), 119 (cdhash vs
notarization ticket), 120 (dynamic `SecCodeCheckValidity`), 121
(`NOTIFY_CS_INVALIDATED` correlated to mmap), 122 (per-dylib team-id / LV
divergence), 123 (amfid task-port / trust override), 124 (AMFI boot-arg /
Developer-Mode posture), 125 (quarantine xattr + Gatekeeper provenance), 126
(entitlement-set drift).

These extend the existing macOS bring-up path: the launchd/XPC daemon
(`daemon/macos/horkosd.cpp`) and the EndpointSecurity client
(`kernel/macos/es/EsClient.mm`). They reuse the established hand-off pattern —
EsClient emits fixed-size `hk_event_record` structs (`event_schema.h`) to the
daemon's sink; the daemon-side probes synthesize the same record type from
periodic polling. The only new wire surface is one additional event type
carrying a "code-signing finding" payload. No IOCTL surface is involved on
macOS (the IOCTL plane in `ioctl.h` is the Windows KMDF bridge; macOS transports
records over the daemon sink / XPC, not a device IOCTL).

---

## New files

All paths honor guardrail #1 (platform code stays under `daemon/macos/`,
`kernel/macos/es/`, or `platform/`; no raw `__APPLE__` — CMake `if(APPLE)` and
the `HORKOS_MACOS_*` options gate compilation), #3 (module comment on every
file), #4 (the ES `.mm` TU and the daemon `.cpp`/`.mm` probe TUs never share a
translation unit; they communicate only through the `event_schema.h` record
contract and the existing `HKEsEventSink` callback). All probe `.cpp` files are
**userspace** — there is no macOS kernel TU in this domain (the ES client is a
userspace SystemExtension/daemon, not a kext).

| Path | Role | Module-comment summary |
|---|---|---|
| `daemon/macos/csops/CsIntegrityProbe.h` | Stable daemon-internal interface for all csops-based probes (118/119/122/126). Declares `HkCsProbeSample(const HkCsProbeTarget*, HkCsFinding* out)` and the per-probe registration vtable. | Role: csops-probe interface. Target: macOS (userspace daemon). Interface: declared here, implemented by `Cs*Probe.cpp`; consumed by the daemon scan orchestrator. |
| `daemon/macos/csops/CsFlagsProbe.cpp` | Signal 118. `csops(pid, CS_OPS_STATUS, &flags)` on self + sibling game PIDs; compare against the known-good csflags baked into Horkos's own shipped signature. | Role: csflags (CS_HARD/CS_KILL/CS_RUNTIME) drift probe. Target: macOS (userspace). Interface: implements `CsIntegrityProbe.h`; emits `HK_EVENT_CS_FINDING`. |
| `daemon/macos/csops/CdHashProbe.cpp` | Signal 119. `csops(pid, CS_OPS_PIDCDHASH)` live cdhash vs `SecCodeCopySigningInformation` cdhashes from the on-disk bundle (translocation-resolved). | Role: live-vs-disk cdhash / notarization parity probe. Target: macOS (userspace). Interface: implements `CsIntegrityProbe.h`; emits `HK_EVENT_CS_FINDING`. |
| `daemon/macos/csops/EntitlementDiffProbe.cpp` | Signal 126. `csops(pid, CS_OPS_ENTITLEMENTS_BLOB)` kernel-granted blob vs on-disk `kSecCodeInfoEntitlementsDict`; canonicalized diff of security-relevant keys. | Role: kernel-granted vs signed entitlement-blob diff. Target: macOS (userspace). Interface: implements `CsIntegrityProbe.h`; emits `HK_EVENT_CS_FINDING`. |
| `daemon/macos/csops/CsInvalidationCorrelator.cpp` | Signal 121 (daemon half). Joins ES `NOTIFY_CS_INVALIDATED` with a recent `NOTIFY_MMAP` (PROT_EXEC, non-platform FD) on the same audit_token + a confirming `CS_OPS_STATUS` CS_VALID-cleared read. | Role: CS_INVALIDATED↔mmap correlation. Target: macOS (userspace). Interface: consumes ES records via the daemon sink; emits `HK_EVENT_CS_FINDING`. |
| `daemon/macos/csops/AmfidWatch.cpp` | Signal 123 (daemon half). Consumes ES `NOTIFY_GET_TASK`/`NOTIFY_GET_TASK_READ` records whose target resolves to `/usr/libexec/amfid`; cross-checks SIP state. | Role: amfid task-port acquisition watch. Target: macOS (userspace). Interface: consumes ES records via sink + SIP probe; emits `HK_EVENT_CS_FINDING`. |
| `daemon/macos/seccode/DynamicValidityProbe.cpp` | Signal 120. `SecCodeCopyGuestWithAttributes(pid)` → `SecCodeCheckValidity(kSecCSEnforceRevocation, DR)` against Horkos's own designated requirement; N-of-M confirmation before reporting. | Role: dynamic SecCode validity probe. Target: macOS (userspace, Security.framework). Interface: standalone probe; emits `HK_EVENT_CS_FINDING`. |
| `daemon/macos/seccode/DylibTeamIdProbe.cpp` | Signal 122 (daemon half). For each ES-observed dylib load, compare `team_id`/`is_platform_binary`/`signing_id` against the host's main-binary team-id + LV bit (`CS_REQUIRE_LST`); allowlist Apple/Steam ids. | Role: per-dylib team-id / library-validation divergence. Target: macOS (userspace). Interface: consumes ES mmap records; emits `HK_EVENT_CS_FINDING`. |
| `daemon/macos/trust/AmfiPostureProbe.cpp` | Signal 124. `csr_check`/`csr_get_active_config` CSR flags, `boot-args` via IORegistry, Developer-Mode state; reported verbatim as a trust-tier input, never a standalone ban. | Role: AMFI / SIP / Developer-Mode boot-posture probe. Target: macOS (userspace). Interface: emits `HK_EVENT_CS_FINDING`; uses `platform_macos` IORegistry helper. |
| `daemon/macos/trust/GatekeeperProbe.cpp` | Signal 125. `getxattr(com.apple.quarantine)` + `SecAssessmentCopyResult`/`SecAssessmentTicketLookup` on the bundle; weak signal, only emitted as corroborating. | Role: Gatekeeper / quarantine / notarization-staple provenance. Target: macOS (userspace, Security.framework). Interface: emits `HK_EVENT_CS_FINDING`. |
| `daemon/macos/csops/CsScanOrchestrator.cpp` | Daemon-side periodic scheduler: enumerates the game PID set, runs the poll-based probes (118/119/120/122/124/125/126) on a timer, fans ES-driven probes (121/123) off the sink, throttles, dedups. | Role: macOS code-signing scan orchestrator. Target: macOS (userspace). Interface: `HkCsScanInit`/`HkCsScanStop`; owns the `CsIntegrityProbe` registry + sink registration. |
| `daemon/macos/csops/CsScan.h` | Declares the orchestrator entry points, the `HkCsFinding` struct used internally before serialization, and the probe registration table. | Role: orchestrator/probe-registry header. Target: macOS (userspace). Interface: declared here; included by every probe `.cpp` and `horkosd.cpp`. |
| `kernel/macos/es/EsClient.mm` (extend existing) | Add `NOTIFY_MMAP`, `NOTIFY_CS_INVALIDATED`, `NOTIFY_GET_TASK`, `NOTIFY_GET_TASK_READ` to the subscription set; emit new record types for signals 121/122/123. All additions are NOTIFY (no auth reply) — guardrail #7 invariant unchanged. | (existing file) extend subscription array + add `emit_*` helpers; remains a pure userspace TU. |
| `platform/platform_macos.cpp` (extend existing) | Add `hk::platform::read_boot_args(...)`, `hk::platform::csr_active_config(...)`, `hk::platform::sip_enabled(...)` — the IORegistry + `csr_*` reads for signal 124, kept out of the probe TU per guardrail #1. | (existing file) extend `hk::platform`; macOS-only backend selected by `if(APPLE)`. |
| `platform/platform.h` (extend existing) | Declare the three new `hk::platform` helpers above (platform-neutral signatures; macOS-only bodies). | (existing header) interface declaration only. |

Rationale for splitting orchestrator vs probes: every poll-based probe needs the
same game-PID enumeration, the same translocation-path resolution, and the same
throttle/dedup; centralizing that mirrors the Windows `HkIntegrityScan.c`
substrate pattern and keeps each probe a single-responsibility TU.

---

## Interfaces & data structures

### New event type (single addition to the wire schema)

`sdk/include/horkos/event_schema.h` — append to `hk_event_type` (existing values
never change, per the header's own rule):

```c
HK_EVENT_CS_FINDING = 6,   /* macOS code-signing / platform-trust finding. */
```

This is **coordinated with** the Windows integrity plan, which claims
`HK_EVENT_INTEGRITY_FINDING = 5` and bumps the schema 2→3. To avoid an enum-value
collision when the two plans land, `HK_EVENT_CS_FINDING` takes the next free
value `6`. Whichever plan merges second bumps `HK_EVENT_SCHEMA_VERSION` to the
next integer (the win plan does 2→3; this one then does 3→4) — the bump is
mechanical and the Rust serde mirror updates in lockstep. **Decision flagged for
the reviewer:** if both land in one PR, allocate 5 and 6 together and bump once.

New fixed-size payload, **≤ `HK_EVENT_PAYLOAD_MAX` = 16** so the 40-byte
`hk_event_record` and the macOS daemon record path are unchanged (no
`HK_EVENT_PAYLOAD_MAX` bump, no record-size drift, every existing
`HK_STATIC_ASSERT` in `ioctl.h` stays green):

```c
typedef struct hk_event_cs_finding {
    uint32_t signal_id;   /* Catalog number 118..126. */
    uint32_t finding;     /* HK_CS_* code (see below). */
    uint32_t target_pid;  /* Game PID the finding pertains to (0 = host-wide,
                             e.g. AMFI posture / amfid). */
    uint32_t detail;      /* Signal-specific compact value: a masked csflags
                             delta bitmask, a CSR-config bitfield, a one-byte
                             team-id-class enum, or the low 32 bits of a cdhash
                             XOR-fold. NEVER a raw cdhash or full pointer —
                             full digests stay server-side via the bundle path
                             (see masking note). */
} hk_event_cs_finding;
HK_STATIC_ASSERT(sizeof(hk_event_cs_finding) == 16,
    "hk_event_cs_finding size mismatch");
```

16 bytes exactly. `HK_EVENT_PAYLOAD_MAX` stays 16; `sizeof(hk_event_record)`
stays 40; no `ioctl.h` change.

Why `detail` is only a compact discriminant, not the full evidence: a raw
cdhash (20–32 bytes) or full entitlement blob does not fit the 16-byte payload
and should not be streamed per-event anyway. The orchestrator computes the
mismatch on-box; the event carries the verdict + a compact discriminant, and the
full evidence (cdhash hex, the diffed entitlement keys, the offending
`signing_id`) travels on the separate JSON daemon→server report plane (see
"Server-side" below), where it is a declared telemetry field. This keeps the
fixed-size kernel-event record stable and avoids leaking raw digests through the
compact wire.

Finding-code constants (in `event_schema.h`, next to the payload):

```c
#define HK_CS_OK                    0x00u
#define HK_CS_FLAGS_DRIFT           0x01u  /* signal 118: CS_KILL/CS_HARD cleared */
#define HK_CS_CDHASH_MISMATCH       0x02u  /* signal 119 */
#define HK_CS_DYNAMIC_INVALID       0x03u  /* signal 120: SecCodeCheckValidity fail */
#define HK_CS_INVALIDATED_TAMPER    0x04u  /* signal 121: CS_INVALIDATED + exec mmap */
#define HK_CS_LV_TEAMID_DIVERGENCE  0x05u  /* signal 122 */
#define HK_CS_AMFID_TASKPORT        0x06u  /* signal 123 */
#define HK_CS_AMFI_POSTURE_WEAK     0x07u  /* signal 124: SIP/Dev-Mode/boot-arg */
#define HK_CS_GATEKEEPER_BYPASS     0x08u  /* signal 125 (corroborating only) */
#define HK_CS_ENTITLEMENT_DRIFT     0x09u  /* signal 126 */
```

### New ES record types feeding the daemon (signals 121/122/123)

EsClient already emits `hk_event_process_create`. The correlator/team-id/amfid
probes need three more ES-sourced facts. Rather than invent three more 16-byte
payloads (and three enum values) for transient intra-daemon plumbing, EsClient
emits a single compact **ES observation** record the daemon's correlator
consumes; the correlator alone decides whether it becomes an `HK_EVENT_CS_FINDING`.
Two options, flagged for the reviewer to choose:

- **Option A (preferred):** keep these as in-process structs passed over the
  existing `HKEsEventSink` using a new internal-only type that is **not** added
  to the public `event_schema.h` wire (the sink callback is in-process; only the
  finding it ultimately produces hits the wire). This keeps the public schema to
  the single `HK_EVENT_CS_FINDING` addition.
- **Option B:** add `HK_EVENT_ES_MMAP` / `HK_EVENT_ES_GET_TASK` to the public
  schema if the server ever needs the raw mmap/get-task stream. Not needed for
  these nine signals; deferred.

This plan adopts **Option A** — the public wire grows by exactly one type
(`HK_EVENT_CS_FINDING`). The internal ES-observation struct lives in `CsScan.h`,
not `event_schema.h`, so guardrail #4 (no kernel/userspace TU sharing) and the
"every wire field declared" discipline both hold (it is not a wire field).

### Server-side mirror (Phase 2 Rust) and the report plane

Two server-side touches:

1. **Kernel-event ingest:** add a serde mirror of `hk_event_cs_finding` (identical
   field names/order, `#[repr(C)]`-compatible decode) to the kernel-event decode
   path. Guardrail #8: `thiserror` error type, no `unwrap()` outside tests; the
   decoder returns `Result` on a short/over-long record. Unknown `finding` codes
   decode to a quarantined-but-typed value, never a panic.
2. **Evidence report plane:** the full evidence (cdhash hex, diffed entitlement
   keys, offending `signing_id`, CSR-config breakdown) rides the daemon→server
   JSON report, a new `CsEvidence` serde struct alongside `TickPayload` in
   `server/telemetry/` (distinct wire plane, same as `TickPayload`). These are
   variable-length and explicitly NOT in the fixed C record.

### Guardrail #11 — `data-categories.md` (same PR)

Every new telemetry field MUST be declared. Add a section to
`server/api/data-categories.md`:

> ### 5. macOS code-signing & platform-trust findings
>
> | Field | Source | Retention default | Legal basis | Operator-of-record |
> |---|---|---|---|---|
> | `signal_id` | macOS cs-scan (`hk_event_cs_finding`) | 90 days | Legitimate interest — anti-cheat enforcement | Horkos Service Operator |
> | `finding` | as above (`HK_CS_*` code) | 90 days | Legitimate interest | Horkos Service Operator |
> | `target_pid` | as above | 90 days | Legitimate interest | Horkos Service Operator |
> | `detail` | as above (masked csflags/CSR/team-id-class discriminant) | 90 days | Legitimate interest | Horkos Service Operator |
> | `cs_live_cdhash` | `CsEvidence` report (csops `CS_OPS_PIDCDHASH`) | 90 days | Legitimate interest | Horkos Service Operator |
> | `cs_disk_cdhash` | `CsEvidence` report (`SecCodeCopySigningInformation`) | 90 days | Legitimate interest | Horkos Service Operator |
> | `cs_dylib_signing_id` | `CsEvidence` report (offending dylib `signing_id`) | 90 days | Legitimate interest | Horkos Service Operator |
> | `cs_entitlement_diff_keys` | `CsEvidence` report (security-relevant keys only) | 90 days | Legitimate interest | Horkos Service Operator |
> | `amfi_posture` | `CsEvidence` report (SIP state, Dev-Mode, boot-args presence flags) | 90 days | Legitimate interest — trust-tier input | Horkos Service Operator |

Note in that section that `detail` is masked (no raw cdhash/pointer leaves the
box) and that `amfi_posture` is reported verbatim as a **trust-tier input**, not
a ban trigger (catalog FP gate on signals 124/125: server policy decides whether
reduced-security boots may play).

---

## Mechanism implementation notes

Shared rules for every probe (guardrails #8 at the server edge; userspace
discipline on-box): probes never block the ES delivery queue (the existing
`sSinkQueue` async hand-off in `EsClient.mm` already enforces this — guardrail
#7/#8); every `csops`/`Sec*`/`getxattr`/`csr_*` return is checked and a failure
aborts that probe cleanly (emit nothing rather than a garbage finding); all
`CFTypeRef`/`SecCodeRef`/`SecStaticCodeRef` are released exactly once on every
path (`CFRelease`, no leaks — these run on a long-lived daemon). The poll-based
probes run from the orchestrator's serial timer queue, never from the ES queue.

**Signal 118 — CsFlagsProbe.cpp.** `csops(pid, CS_OPS_STATUS, &flags,
sizeof(flags))` (and `csops_audittoken` when starting from an ES audit_token).
Read the bitmask (`CS_VALID`, `CS_HARD`, `CS_KILL`, `CS_RUNTIME`, `CS_RESTRICT`,
`CS_ENFORCEMENT`, `CS_REQUIRE_LST`) from `<sys/codesign.h>`. **FP gate (catalog):
do NOT compare against an absolute expected mask** — compare against the csflags
Horkos baked into its own shipped signature (a known-good constant captured at
build/sign time), because Rosetta, debug builds, and VM/translation layers carry
different-but-legitimate flag sets. Emit `HK_CS_FLAGS_DRIFT` only when CS_KILL or
CS_HARD is cleared on a binary whose baseline had them set. `detail` = masked
delta bitmask (which expected bits are missing), not the raw flags.

**Signal 119 — CdHashProbe.cpp.** `csops(pid, CS_OPS_PIDCDHASH, buf,
sizeof(buf))` for the kernel's live cdhash; guard with `CS_OPS_TEISDISABLED`.
Cross-check against `SecStaticCodeCreateWithPath` → `SecCodeCopySigningInformation(
kSecCSDefaultFlags | kSecCSSigningInformation)` → `kSecCodeInfoUnique` /
`kSecCodeInfoCdHashes` on the on-disk bundle. **FP gate:** resolve
app-translocation (`SecTranslocateCreateOriginalPathForURL`) and pick the
architecture slice actually executing (fat binaries) before comparing — a raw
path comparison false-positives under Gatekeeper quarantine randomized paths and
Rosetta AOT caches. Emit `HK_CS_CDHASH_MISMATCH` with `detail` = low 32 bits of a
fold of the live cdhash (discriminant only); full hex goes on the report plane.
**UNCERTAINTY (flag):** the exact `CS_OPS_PIDCDHASH` buffer size and whether
`CS_OPS_TEISDISABLED` is the correct guard across macOS 12–15 — see Risks.

**Signal 120 — DynamicValidityProbe.cpp.** `SecCodeCopyGuestWithAttributes(NULL,
{kSecGuestAttributePid: pid}, kSecCSDefaultFlags, &code)` then
`SecCodeCheckValidity(code, kSecCSEnforceRevocation, requirement)` where
`requirement` = `SecRequirementCreateWithString` of Horkos's own designated
requirement, restricted to the main executable's signed `__TEXT`. Run
**periodically, not just at start** (catalog). **FP gate:** JIT regions,
unsigned plugin bundles, and lazily-paged code can transiently fail
(`errSecCSGuestInvalid` / `errSecCSVmwMapping`); require **N-of-M confirmation**
across consecutive scans before emitting `HK_CS_DYNAMIC_INVALID`. Treat a single
transient failure as a re-check trigger, not a finding.

**Signal 121 — CsInvalidationCorrelator.cpp + EsClient.mm.** EsClient subscribes
`ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED` and `ES_EVENT_TYPE_NOTIFY_MMAP` (both
NOTIFY — no reply, guardrail #7 untouched). For mmap it reads `es_event_mmap_t`
(source FD `signing_id`, `protection & PROT_EXEC`). The correlator joins a
CS_INVALIDATED on the game's audit_token with a recent PROT_EXEC mmap from a
**non-platform FD** within a short window, then confirms with a `csops
CS_OPS_STATUS` read that CS_VALID actually cleared on that exact audit_token.
**FP gate:** Sparkle/self-updaters and shared-cache repaging legitimately
invalidate — gate on the invalidated image being the game's own signed binary
AND the correlated mmap being non-platform. Emit `HK_CS_INVALIDATED_TAMPER`.

**Signal 122 — DylibTeamIdProbe.cpp + EsClient.mm.** From each ES dylib-load /
`NOTIFY_MMAP`, read `es_message_t.process.team_id`, `es_process_t.is_platform_binary`,
`signing_id`. Cross-check against the host process's `CS_REQUIRE_LST` bit
(`csops CS_OPS_STATUS`) and the main binary's team-id; a loaded dylib whose
team-id differs (and is not an Apple platform binary) while LV is nominally
enabled means LV was bypassed. **FP gate:** gate on the host being the game
itself (not the launcher), LV being declared in the game's own entitlements, and
an allowlist of known-good Apple/Steam `signing_id`s — OBS virtual-cam, audio AU
plugins, and accessibility tools legitimately inject differently-signed dylibs.
Emit `HK_CS_LV_TEAMID_DIVERGENCE`; `detail` = a small team-id-class enum
(apple-platform / same-team / allowlisted / foreign).

**Signal 123 — AmfidWatch.cpp + EsClient.mm.** EsClient subscribes
`ES_EVENT_TYPE_NOTIFY_GET_TASK` and `ES_EVENT_TYPE_NOTIFY_GET_TASK_READ` (NOTIFY).
The watch fires when the target audit_token resolves to `/usr/libexec/amfid`.
Daemon-side parity: `task_get_exception_ports` on amfid to spot an unexpected
debug exception port (**requires the daemon's own debug entitlement** — flag).
**FP gate:** any get-task on amfid is high-signal only with **SIP on**; lldb/Apple
tools can task_for_pid daemons with SIP off. Cross-check SIP state (signal 124's
`csr_check`) and report SIP-disabled dev boxes **separately**, not as cheating.
Emit `HK_CS_AMFID_TASKPORT`. **UNCERTAINTY (flag):** whether `NOTIFY_GET_TASK`
fires for amfid acquisition on the target macOS versions and the exact
entitlement needed for `task_get_exception_ports` on a system daemon — see Risks.

**Signal 124 — AmfiPostureProbe.cpp + platform_macos.cpp.** `csr_check()` /
`csr_get_active_config()` for CSR flags (`CSR_ALLOW_UNRESTRICTED_FS`,
`CSR_ALLOW_TASK_FOR_PID`, etc.); `boot-args` via IORegistry
(`IORegistryEntryFromPath` on `IOService:/` → `IOPlatformExpertDevice` →
`IORegistryEntryCreateCFProperty(CFSTR("boot-args"))`); Developer-Mode state via
the AMFI developer-mode check. The IORegistry + `csr_*` reads live in
`platform/platform_macos.cpp` (guardrail #1 — platform API out of the probe TU);
the probe calls `hk::platform::read_boot_args` / `csr_active_config` /
`sip_enabled`. **FP gate (catalog):** legitimate devs enable Developer Mode and
set boot-args; Apple-Silicon Permissive Security is supported. **Report posture
verbatim as a trust-tier input — never a standalone ban.** Emit
`HK_CS_AMFI_POSTURE_WEAK` with `detail` = CSR-config bitfield. **UNCERTAINTY
(flag):** `csr_get_active_config` is a private/SPI symbol; its availability and
the Developer-Mode query API across macOS 12–15 are uncertain — see Risks.

**Signal 125 — GatekeeperProbe.cpp.** `getxattr(path, "com.apple.quarantine",
...)` on the bundle; `SecAssessmentCreate`/`SecAssessmentCopyResult`
(`kSecAssessmentOperationTypeExecute`); `SecAssessmentTicketLookup` for staple
presence. **FP gate (HIGH per catalog):** self-built, Steam/Epic-managed, and
App-Store binaries legitimately lack the quarantine xattr; enterprises disable GK
by policy. **This signal is WEAK alone — emit `HK_CS_GATEKEEPER_BYPASS` only as a
corroborating finding** combined with a cdhash (119) or notarization-ticket
result; never as a standalone ban input. The orchestrator suppresses emission
unless a 119/126 finding co-occurs for the same PID. **UNCERTAINTY (flag):**
`SecAssessment*` is a partially-SPI surface (`<Security/SecAssessment.h>` is not
fully public); confirm the linkable subset — see Risks.

**Signal 126 — EntitlementDiffProbe.cpp.** `csops(pid,
CS_OPS_ENTITLEMENTS_BLOB, buf, size)` (and/or `CS_OPS_DER_ENTITLEMENTS_BLOB`) for
the kernel-held blob; compare against `SecCodeCopySigningInformation(
kSecCSRequirementInformation)` → `kSecCodeInfoEntitlementsDict` from the on-disk
binary. Canonicalize and diff only the **security-relevant keys**
(`com.apple.security.get-task-allow`, `...cs.disable-library-validation`,
`...cs.debugger`, `...cs.allow-dyld-environment-variables`). **FP gate:** Rosetta
and Apple-shimmed processes get kernel-added entitlements not on disk — maintain
a small OS-injected-entitlement allowlist and diff only the security keys. Emit
`HK_CS_ENTITLEMENT_DRIFT`; full diffed key set on the report plane.

**Server (guardrail #8).** The `hk_event_cs_finding` decoder and the
`CsEvidence` ingest are fully async on tokio, `thiserror` error type, no
`unwrap()` outside tests. Per-`finding` scoring weights live in the ban-engine
config; signals 124/125 feed a trust-tier input, not a direct ban, matching the
catalog FP gates.

---

## Build wiring

- New sources compile under the existing macOS targets, all gated by `if(APPLE)`
  in the parent CMake (guardrail #1 — no raw `__APPLE__`):
  - The daemon probes (`daemon/macos/csops/*.cpp`, `seccode/*.cpp`,
    `trust/*.cpp`, the orchestrator) build into the `horkosd` target
    (`daemon/macos/CMakeLists.txt`), or into a new `horkos_csprobes` static lib
    that `horkosd` links — preferred, so probe unit tests link the lib without
    the daemon `main`.
  - The `EsClient.mm` subscription extensions build in the existing
    `kernel/macos/es` `horkos_es` target, still behind `HORKOS_MACOS_ES`
    (default OFF) — the ES-driven probes (121/122/123) only function when ES is
    built.
- New CMake feature options (cached, documented in `docs/macos-es.md` /
  `docs/macos-build.md`), default tuned to the catalog FP risk:
  - `HK_MACOS_CS_FLAGS` — signal 118 — **default ON** (low risk, FP medium but
    baseline-gated).
  - `HK_MACOS_CS_CDHASH` — signal 119 — **default ON** (low FP).
  - `HK_MACOS_CS_ENTITLEMENT` — signal 126 — **default ON** (low FP).
  - `HK_MACOS_CS_DYNAMIC` — signal 120 — **default ON** (medium FP, N-of-M gated).
  - `HK_MACOS_CS_AMFI_POSTURE` — signal 124 — **default ON** (trust-tier input,
    never a ban; `csr_*` SPI uncertainty flagged → ships report-only).
  - `HK_MACOS_CS_GATEKEEPER` — signal 125 — **default OFF** (HIGH FP, corroborating
    only; SecAssessment SPI uncertainty).
  - `HK_MACOS_CS_INVALIDATION` — signal 121 — **default OFF**, requires
    `HORKOS_MACOS_ES` (needs CS_INVALIDATED + MMAP subscriptions).
  - `HK_MACOS_CS_DYLIB_LV` — signal 122 — **default OFF**, requires
    `HORKOS_MACOS_ES`.
  - `HK_MACOS_CS_AMFID` — signal 123 — **default OFF**, requires
    `HORKOS_MACOS_ES` + daemon debug entitlement (flagged).
- Each option maps to a `target_compile_definitions`; a probe whose flag is OFF
  compiles to a no-op stub so the daemon links with any subset (mirrors the
  Windows sensor-stub pattern).
- The orchestrator + `CsScan.h` + `CsIntegrityProbe.h` are always compiled (the
  shared substrate); they fan out only to enabled probes.
- Toolchain: Xcode Command Line Tools / clang, macOS 12+ SDK (Security.framework,
  EndpointSecurity.framework). `find_library` for `Security` and the existing
  `EndpointSecurity` find in `kernel/macos/es/CMakeLists.txt`. All new TUs build
  `-Wall -Wextra -Werror` (matching `horkosd` and `horkos_es`), `-fobjc-arc`
  where Objective-C++ is used, `-mmacosx-version-min=12.0`.
- `csops` is declared in `<sys/codesign.h>` / `<System/codesign.h>`; no extra
  library link. `csr_check`/`csr_get_active_config` are in libSystem but are SPI
  — flagged below.

---

## Test strategy

### Unit / host-buildable tests (guardrail #14: logic where testable)

- **Schema pin tests** (host, no ES/SDK): a C++ TU including `event_schema.h`
  asserting `sizeof(hk_event_cs_finding) == 16`, `HK_EVENT_PAYLOAD_MAX == 16`,
  `sizeof(hk_event_record) == 40` still hold post-addition. Runs in CI on every
  host, not just macOS.
- **csflags baseline-diff logic** factored into a pure function
  `cs_flags_drifted(baseline_mask, observed_mask) -> missing_critical_bits`,
  unit-tested host-side: CS_KILL/CS_HARD cleared → flagged; CS_RUNTIME cleared on
  a baseline that lacked it → not flagged; Rosetta-style differing-but-legit mask
  → not flagged.
- **cdhash compare + translocation-path normalization** logic tested host-side
  with fixture paths (the path-resolution branch is pure; the `csops` call is
  mocked behind the `CsIntegrityProbe` seam).
- **Entitlement canonical-diff** tested host-side: only security-relevant keys
  diffed; OS-injected-allowlist keys ignored; added `get-task-allow` flagged.
- **N-of-M confirmation** logic for signal 120 tested host-side: M transient
  fails below threshold → no emit; ≥N → emit.
- **Correlator window logic** (signal 121) tested host-side with synthetic
  (CS_INVALIDATED, MMAP) event pairs: in-window non-platform exec mmap → emit;
  out-of-window or platform FD → no emit.
- **Server decoder** Rust unit tests: valid `hk_event_cs_finding` round-trips;
  short record → `Err`; unknown `finding` code → typed-quarantine, never panic
  (guardrail #8).

### Bypass tests (guardrail #12 — merge gate; any change under `kernel/macos/` or
`daemon/macos/` needs a corresponding bypass test under `bypass-tests/macos/`)

Following the disabled-but-compiled pattern of the existing
`bypass-tests/macos/dylib_inject.cpp` (compiles now, asserts activate when the
Phase-5 signed fixture + enforcement land). New files under `bypass-tests/macos/`,
all added to `bypass-tests/macos/CMakeLists.txt`:

- `csflags_strip.cpp` — must demonstrate: a fixture launched with CS_KILL/CS_HARD
  cleared (re-signed/ad-hoc, or AMFI weakened in a VM) yields `HK_CS_FLAGS_DRIFT`,
  while a clean notarized launch does NOT.
- `cdhash_swap.cpp` — fixture: ad-hoc resign of a patched executable at the same
  path; assert `HK_CS_CDHASH_MISMATCH` fires; assert an app-translocated clean
  bundle does NOT (FP-gate proof).
- `dynamic_validity_patch.cpp` — fixture mprotects + patches a signed `__TEXT`
  page in memory only (disk untouched); assert `HK_CS_DYNAMIC_INVALID` fires
  after N-of-M, and that a transient JIT region does NOT (single-transient proof).
- `cs_invalidate_mmap.cpp` — fixture CoW-breaks `__TEXT` then PROT_EXEC-mmaps a
  foreign page; assert `HK_CS_INVALIDATED_TAMPER` fires for the correlated pair
  and a benign Sparkle-style self-update does NOT.
- `dylib_teamid_inject.cpp` — extends/complements the existing `dylib_inject.cpp`:
  `DYLD_INSERT_LIBRARIES` a foreign-team dylib into an LV-enabled host; assert
  `HK_CS_LV_TEAMID_DIVERGENCE`; an allowlisted Apple/Steam dylib does NOT fire.
- `amfid_taskport.cpp` — fixture acquires amfid's task port (SIP-off dev box);
  assert it is reported `HK_CS_AMFID_TASKPORT` but **tagged SIP-disabled / scored
  separately**, proving the SIP cross-check gate.
- `amfi_posture_bootarg.cpp` — fixture: VM booted with `amfi_get_out_of_my_way`/
  Developer Mode; assert `HK_CS_AMFI_POSTURE_WEAK` is emitted as a **trust-tier
  input, not a ban** (proves the report-only contract).
- `gatekeeper_xattr_strip.cpp` — fixture strips `com.apple.quarantine`; assert
  `HK_CS_GATEKEEPER_BYPASS` is emitted ONLY when a 119/126 finding co-occurs
  (proves the corroborating-only gate), never standalone.
- `entitlement_inject.cpp` — fixture re-signs adding `get-task-allow` /
  `disable-library-validation`; assert `HK_CS_ENTITLEMENT_DRIFT`; a Rosetta
  OS-injected entitlement does NOT fire (allowlist proof).

Each ships disabled (compiled no-op returning success) until the Phase-5
signed-fixture + daemon-enforcement path exists (`HK_CS_TEST_ENABLED` gate,
mirroring `HK_DYLIB_TEST_ENABLED`). The merge gate is satisfied by their presence
+ compile.

---

## Sequencing

1. **Wire + substrate first.** Land the `event_schema.h` addition
   (`HK_EVENT_CS_FINDING`, the `HK_CS_*` codes, schema-version bump coordinated
   with the win plan), the `CsScan.h` / `CsIntegrityProbe.h` interfaces, the
   `CsScanOrchestrator.cpp` skeleton (PID enumeration, throttle, dedup, sink
   registration), the Rust serde mirror + `CsEvidence`, the `data-categories.md`
   section (guardrail #11 — same PR), and the schema-pin + server-decoder tests.
   Nothing platform-specific beyond the orchestrator scaffold; fully testable
   host-side.
2. **platform_macos.cpp helpers.** Add `read_boot_args` / `csr_active_config` /
   `sip_enabled` behind the `hk::platform` interface (guardrail #1), with the
   SPI-uncertainty flags resolved or stubbed (see Risks). No probe depends on
   real values yet.
3. **Poll-based, default-ON probes (no ES dependency):** signal 118 (CsFlags),
   119 (CdHash), 126 (Entitlement), 120 (DynamicValidity), 124 (AmfiPosture,
   report-only). Each lands with its host-side logic unit tests and its
   bypass-test stub.
4. **ES-driven probes (require `HORKOS_MACOS_ES`):** extend `EsClient.mm`
   subscriptions (NOTIFY_MMAP, NOTIFY_CS_INVALIDATED, NOTIFY_GET_TASK[_READ] —
   all NOTIFY, guardrail #7 invariant re-verified), then land 121 (Correlator),
   122 (DylibTeamId), 123 (AmfidWatch — gated on the debug-entitlement
   resolution).
5. **Corroborating-only, default-OFF:** signal 125 (Gatekeeper), wired last and
   suppressed unless 119/126 co-occur.
6. **Phase 5:** signed test-fixture bundles + daemon enforcement activate the
   bypass-test assertions (`HK_CS_TEST_ENABLED`).

Dependencies: every probe depends on the orchestrator + `event_schema.h`
addition (step 1). 121/122/123 depend on the `EsClient.mm` subscription
extension (step 4). 124 depends on the `platform_macos.cpp` helpers (step 2).
123 cross-checks 124's SIP state; 125 is suppressed unless 119/126 fire. The
server decoder (step 1) gates every finding being interpretable.

---

## Risks & UNCERTAINTY FLAGS

Per guardrail #13, these are flagged for the user **before any probe code is
written**. None of these is a kernel/IRQL/BSOD risk (this domain is entirely
userspace on macOS), but several touch private/SPI surfaces and ES auth/version
semantics where guessing is forbidden:

1. **`csops` operation constants and buffer sizes (signals 118/119/126).**
   `CS_OPS_STATUS`, `CS_OPS_PIDCDHASH`, `CS_OPS_ENTITLEMENTS_BLOB`,
   `CS_OPS_DER_ENTITLEMENTS_BLOB`, `CS_OPS_TEISDISABLED` are declared in
   `<sys/codesign.h>` but parts are effectively SPI and have shifted across macOS
   versions; the exact blob/cdhash buffer sizing and which ops require root /
   the same-team relationship are **uncertain across macOS 12–15**. FLAGGED —
   confirm against the target SDK headers and behavior on each OS version before
   relying on a fixed buffer size.
2. **`csr_check` / `csr_get_active_config` (signal 124).** These SIP-config
   symbols are **private SPI**; availability, signature, and the CSR flag
   meanings are not in a public header and have changed (notably on Apple
   Silicon, where SIP is expressed differently). The Developer-Mode query API is
   likewise not clearly public. FLAGGED — ship signal 124 **report-only behind a
   default-ON-but-degraded** path; do not gate any ban on an SPI read whose
   semantics we have not confirmed. Do not guess the CSR bit layout.
3. **`SecAssessment*` surface (signal 125).** `<Security/SecAssessment.h>`,
   `SecAssessmentCopyResult`, `SecAssessmentTicketLookup` are only partially
   public and the linkable/entitled subset varies. FLAGGED — keep signal 125
   default-OFF and corroborating-only until the linkable API is confirmed.
4. **ES event availability & semantics (signals 121/122/123).** Whether
   `ES_EVENT_TYPE_NOTIFY_GET_TASK` / `..._GET_TASK_READ` actually fire for amfid
   task-port acquisition, the exact `es_event_mmap_t` fields and `signing_id`
   availability on the target ES message version, and whether `NOTIFY_CS_INVALIDATED`
   carries enough context to attribute the invalidated image — all **uncertain
   across ES message versions / macOS 12–15**. FLAGGED. (These are NOTIFY events,
   so there is no auth reply-deadline risk — guardrail #7 is not implicated; but
   the EsClient extension must still preserve the existing unconditional
   AUTH_EXEC reply path untouched.)
5. **`task_get_exception_ports` on amfid (signal 123) requires the daemon's own
   debug entitlement.** Acquiring it for a system daemon is itself
   entitlement-gated and may require SIP off, which would make the probe
   self-defeating on production machines. FLAGGED — confirm the entitlement and
   whether a purely ES-observational variant (watch get-task ON amfid, never
   acquire amfid's port ourselves) is sufficient; prefer the observational
   variant to avoid needing a privileged port.
6. **App-translocation & fat-slice resolution (signal 119).**
   `SecTranslocateCreateOriginalPathForURL` is itself SPI-adjacent and the
   correct executing-slice selection on Universal binaries is fiddly; a wrong
   resolution false-positives on clean Gatekeeper-quarantined or Rosetta-AOT
   bundles. FLAGGED — validate against a clean-machine corpus before enabling.
7. **csflags baseline capture (signal 118).** The "known-good" baseline must be
   the csflags of Horkos's **own shipped, notarized** signature, captured at
   build/sign time — not an absolute mask. If the baseline is wrong, the probe
   false-positives on every clean install. FLAGGED — the baseline-capture step is
   a build/sign-pipeline dependency, not just code.
8. **Schema-version coordination with the Windows integrity plan.** Both plans
   add a finding event type and bump `HK_EVENT_SCHEMA_VERSION`. If they land
   independently, allocate enum values 5 (win) and 6 (macOS) without collision
   and bump the version once per merge. FLAGGED for the reviewer to sequence.

No detection-efficacy or bypass-resistance claims are made here (guardrail #13);
all scoring and ban authority is server-side, and signals 124/125 are explicitly
trust-tier/corroborating inputs, never standalone bans.
