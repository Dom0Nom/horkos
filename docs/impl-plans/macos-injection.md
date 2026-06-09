# macOS — Process Inspection / Injection (`macos-injection`)

Scope: read-only sensors that surface foreign task-port acquisition, executable
mmap/inline-patching, DYLD injection, exception-port and thread hijacks, proc_info
reconnaissance, and debugger attach against a clean game process on macOS. Clients
sample and report only; all ban/trust scoring is server-side.

Catalog signals covered: **109, 110, 111, 112, 113, 114, 115, 116, 117** (the nine
"macOS — Process Inspection / Injection" signals).

Split across two existing planes, per the catalog `Horkos slot:` lines:

- **ES plane** (`kernel/macos/es/EsClient.mm`, userspace, EndpointSecurity): signals
  **109, 110, 111, 112, 115** plus the GET_TASK side-channel half of **113/116**.
- **Daemon poll plane** (`daemon/macos/horkosd.cpp`, userspace, Mach/sysctl/vm APIs):
  signals **113, 114, 116, 117** (exception-port baseline, thread integrity,
  P_TRACED edge, __TEXT W^X scan) plus the per-title mmap baseline manifest for **111**.

Both planes are userspace (the macOS "kernel" layer here means EndpointSecurity, not
a kext). Guardrail #4 (kernel/userspace TU separation) is therefore not in tension on
macOS; the relevant separations are ES-queue vs sink-queue (already established in
`EsClient.mm`) and ES reply-deadline safety (#7).

---

## New files

| Path | Role | Module-comment summary (guardrails #1, #3, #4) |
|---|---|---|
| `daemon/macos/HKExceptionPortBaseline.cpp` | Signal 113 — capture game exception-port set at launch, periodic re-poll, diff for foreign owner | Role: poll `task_get_exception_ports` against the validated game task, diff vs launch baseline. Target: macOS only (built behind `if(APPLE)`). Interface: declares `HKExcPortPoll()` consumed by `horkosd.cpp`; emits `hk_es_exc_port` via the daemon event sink. No platform `#ifdef` — `if(APPLE)` in CMake gates the TU. |
| `daemon/macos/HKExceptionPortBaseline.h` | Declares `HKExcPortBaseline` struct + `HKExcPortPoll()` | Role: interface header for the exception-port poller. Target: macOS. Interface: declares the poll entrypoint and baseline handle; included only by daemon TUs. |
| `daemon/macos/HKThreadIntegrity.cpp` | Signal 114 — enumerate game threads, resolve each entry PC against the dyld image map, flag foreign/anon entries | Role: `task_threads` + `thread_get_state` enumeration, dyld-image-region resolver, foreign-entry flag. Target: macOS (arm64 + x86_64). Interface: declares `HKThreadScan()`; emits `hk_es_thread_origin`. Intersects with the mmap-exec baseline before flagging. |
| `daemon/macos/HKThreadIntegrity.h` | Declares `HKThreadScan()` + image-region resolver | Role: interface header for thread-origin scanning. Target: macOS. Interface: included only by daemon TUs. |
| `daemon/macos/HKTextIntegrity.cpp` | Signal 117 — walk game `__TEXT` via `mach_vm_region_recurse`, flag writable/COW-broken pages, cross-check `csops` | Role: `__TEXT` W^X scanner + code-signature status check. Target: macOS. Interface: declares `HKTextScan()`; emits `hk_es_text_wx`. Resolves `__TEXT` range from on-disk mach-o load commands. |
| `daemon/macos/HKTextIntegrity.h` | Declares `HKTextScan()` + `__TEXT` range resolver | Role: interface header for the `__TEXT` integrity scanner. Target: macOS. Interface: daemon-only. |
| `daemon/macos/HKPtraceWatch.cpp` | Signal 116 — sysctl `KERN_PROC_PID` poll of `p_flag & P_TRACED`, report transition edge | Role: P_TRACED transition-edge detector via `sysctl(CTL_KERN,KERN_PROC,KERN_PROC_PID)`. Target: macOS. Interface: declares `HKPtracePoll()`; emits `hk_es_ptrace`. Correlated server-side with the GET_TASK source from the ES plane. |
| `daemon/macos/HKPtraceWatch.h` | Declares `HKPtracePoll()` | Role: interface header for the ptrace/P_TRACED watcher. Target: macOS. Interface: daemon-only. |
| `daemon/macos/HKGameTaskHandle.cpp` | Shared — resolve and audit-token-validate a privileged handle to the game task (used by 113/114/117) | Role: obtain + validate the game's `task_t` once, share to all daemon pollers. Target: macOS. Interface: declares `HKGameTaskGet()`. Centralises the one privileged `task_for_pid`-equivalent path so the audit-token validation is written once. |
| `daemon/macos/HKGameTaskHandle.h` | Declares `HKGameTaskGet()` / `HKGameTaskRelease()` | Role: interface header for the validated game-task handle. Target: macOS. Interface: daemon-only. |
| `daemon/macos/HKMmapBaseline.cpp` | Signal 111 (baseline half) — per-title manifest of expected exec-map sources + JIT entitlement check | Role: load/maintain the per-title signed-dylib + sanctioned-JIT manifest used to gate MMAP-exec reports. Target: macOS. Interface: declares `HKMmapBaselineMatch()`; consulted by the ES MMAP handler via the daemon. |
| `daemon/macos/HKMmapBaseline.h` | Declares `HKMmapBaselineMatch()` + manifest struct | Role: interface header for the mmap-exec baseline. Target: macOS. Interface: daemon-only. |
| `server/telemetry/src/macos_inject.rs` | Server-side serde mirror + scoring for all `hk_es_*` injection payloads | Role: decode the new injection event payloads, apply FP gates (platform-binary / allowlist / debugger-session), score. Target: server (Rust/tokio). Interface: `thiserror` error type `MacInjectError`; no `unwrap()` outside `#[cfg(test)]` (guardrail #8). |

No new files under `kernel/macos/es/` — signals 109/110/111/112/115 extend the existing
`handle_es_message` switch and `subscriptions[]` in `EsClient.mm` (matching the catalog
`Horkos slot:` lines). New ES payload emit helpers live in that same TU alongside the
existing `emit_process_create`.

---

## Interfaces & data structures

### Wire-schema additions (`sdk/include/horkos/event_schema.h`)

Bump `HK_EVENT_SCHEMA_VERSION` 2 → 3. Append new event types (existing values never
change, per the header's stated rule):

```c
typedef enum hk_event_type {
    /* ... existing 0..4 ... */
    HK_EVENT_ES_GET_TASK     = 5,  /* signals 109, 110 (and 113/116 source attr) */
    HK_EVENT_ES_MMAP         = 6,  /* signal 111 */
    HK_EVENT_ES_DYLD_INJECT  = 7,  /* signal 112 */
    HK_EVENT_ES_PROC_CHECK   = 8,  /* signal 115 */
    HK_EVENT_ES_EXC_PORT     = 9,  /* signal 113 */
    HK_EVENT_ES_THREAD_ORIGIN = 10, /* signal 114 */
    HK_EVENT_ES_PTRACE       = 11, /* signal 116 */
    HK_EVENT_ES_TEXT_WX      = 12, /* signal 117 */
} hk_event_type;
```

**Payload-size constraint.** `ioctl.h` pins `HK_EVENT_PAYLOAD_MAX = 16` and
`hk_event_record == 40`. macOS does NOT use the Windows IOCTL ring — the daemon sink
delivers variable-size records directly to the server transport (see `EsClient.mm`
`HKEsEventSink`, which already takes `payload_bytes`). So the macOS payloads below are
**not** bound by the 16-byte IOCTL envelope. To avoid silently breaking the Windows
`HK_STATIC_ASSERT(sizeof(hk_event_record) == 40)`, keep these new structs out of the
`hk_event_record` union: they ride the macOS sink path only. Document this explicitly
in the schema header so a future reader does not try to widen `HK_EVENT_PAYLOAD_MAX`.

> UNCERTAINTY FLAG (design): the cleanest split is a separate `event_schema_macos.h`
> included only by macOS TUs and the server, leaving `event_schema.h` (and its
> 40-byte IOCTL pin) untouched. I am proposing that rather than widening the shared
> record. Flagging for your call before landing — it changes where the `HK_STATIC_ASSERT`
> size pins live. Recommended: new `sdk/include/horkos/event_schema_macos.h`.

Proposed payload structs (in `event_schema_macos.h` per the flag above; all sizes
pinned with `HK_STATIC_ASSERT`; 8-byte aligned, no implicit padding):

```c
/* Signals 109/110 — task-port acquisition, with control/name/read discrimination. */
typedef struct hk_es_get_task {
    uint32_t source_pid;        /* requester (es_message_t.process) */
    uint32_t target_pid;        /* the game (event.get_task.target) */
    uint32_t flavor;            /* HK_GET_TASK_CONTROL/NAME/READ (signal 110) */
    uint32_t source_flags;      /* HK_ESPROC_PLATFORM_BINARY | _ALLOWLISTED | _DEBUGGER */
    uint8_t  source_team_id[16];   /* truncated team-id, NUL-padded */
    uint8_t  source_signing_id[32];/* truncated signing-id, NUL-padded */
} hk_es_get_task;                  /* 64 bytes */

/* Signal 111 — non-self executable mmap into the game. */
typedef struct hk_es_mmap {
    uint32_t target_pid;
    uint32_t source_pid;
    uint32_t protection;        /* es_event_mmap_t.protection (PROT_EXEC bit) */
    uint32_t flags;             /* es_event_mmap_t.flags (MAP_ANON bit) */
    uint32_t baseline_match;    /* HK_MMAP_BASELINE_KNOWN / _UNKNOWN / _ANON_RWX */
    uint32_t reserved;
    uint8_t  source_path_sha256[32]; /* digest of es_event_mmap_t.source path */
} hk_es_mmap;                   /* 56 bytes */

/* Signal 112 — DYLD_INSERT_LIBRARIES survival past hardened-runtime strip. */
typedef struct hk_es_dyld_inject {
    uint32_t pid;
    uint32_t cs_flags;          /* es_process_t.codesigning_flags (CS_RUNTIME/CS_RESTRICT) */
    uint32_t dyld_var_present;  /* bitmask: INSERT_LIBRARIES | FRAMEWORK_PATH */
    uint32_t injected_load_seen;/* 1 if a non-system dylib actually loaded */
    uint8_t  inserted_path_sha256[32];
} hk_es_dyld_inject;            /* 48 bytes */

/* Signal 115 — proc_info reconnaissance rate/flavor. */
typedef struct hk_es_proc_check {
    uint32_t source_pid;
    uint32_t target_pid;        /* the game */
    uint32_t flavor;            /* es_proc_check_type_t (PROC_PIDREGIONPATHINFO, ...) */
    uint32_t rate_per_window;   /* aggregated count in the sampling window */
    uint32_t flavor_cardinality;/* distinct flavors seen from this source */
    uint32_t source_flags;      /* HK_ESPROC_* as above */
} hk_es_proc_check;             /* 24 bytes */

/* Signal 113 — foreign exception-port owner on the game task. */
typedef struct hk_es_exc_port {
    uint32_t game_pid;
    uint32_t owner_pid;         /* task owning the new exception port (0 = unresolved) */
    uint32_t mask;              /* exception_mask_t bits that changed */
    uint32_t is_foreign;        /* 1 if owner != game and not Apple diagnostics */
} hk_es_exc_port;               /* 16 bytes */

/* Signal 114 — thread with non-bundle entry point. */
typedef struct hk_es_thread_origin {
    uint32_t game_pid;
    uint32_t thread_id;         /* mach thread id for correlation */
    uint64_t entry_pc;          /* arm64 __pc / x86_64 __rip start address */
    uint32_t region_kind;       /* HK_REGION_IMAGE / _ANON / _JIT_SANCTIONED */
    uint32_t reserved;
} hk_es_thread_origin;          /* 24 bytes */

/* Signal 116 — P_TRACED transition edge. */
typedef struct hk_es_ptrace {
    uint32_t game_pid;
    uint32_t tracer_pid;        /* kp_eproc.e_ppid / GET_TASK source if correlated */
    uint32_t traced_now;        /* current p_flag & P_TRACED */
    uint32_t cs_release_signed; /* 1 if release-signed && no get-task-allow */
} hk_es_ptrace;                 /* 16 bytes */

/* Signal 117 — writable / COW-broken page inside signed __TEXT. */
typedef struct hk_es_text_wx {
    uint32_t game_pid;
    uint32_t protection;        /* vm_region_submap_info_64.protection (VM_PROT_WRITE) */
    uint32_t share_mode;        /* SM_COW / SM_PRIVATE — COW-break signal */
    uint32_t csops_valid;       /* csops(CS_OPS_STATUS): 0 if signature invalidated */
    uint64_t region_addr;       /* start of the offending page */
} hk_es_text_wx;                /* 24 bytes */
```

Flavor/flag enums (`HK_GET_TASK_*`, `HK_ESPROC_*`, `HK_MMAP_BASELINE_*`, `HK_REGION_*`)
defined alongside, mirroring the catalog's `es_get_task_type_t`, `is_platform_binary`,
and `es_proc_check_type_t`. Every struct gets a `HK_STATIC_ASSERT(sizeof(...) == N, ...)`
size pin in the same header (matching the existing convention).

### IOCTL additions (`sdk/include/horkos/ioctl.h`)

**None.** These signals never traverse the Windows IOCTL bridge; they reach the server
via the macOS daemon's existing sink → transport path. No `HK_IOCTL_*` codes added, and
`HK_EVENT_PAYLOAD_MAX` / `hk_event_record` are deliberately left at 40 bytes (see the
schema note above). This keeps the Windows wire-size `HK_STATIC_ASSERT`s green.

### Server mirror (`server/telemetry/src/macos_inject.rs`)

`#[repr(C)]` serde mirror of each `hk_es_*` struct, field names and sizes matching the
C header in lockstep (same discipline as the existing schema mirror). Decode + score:
apply per-signal FP gates from the catalog (platform-binary exclusion, signed-allowlist,
debugger-session suppression, rate thresholds for 115). `thiserror`-derived
`MacInjectError`; `?` propagation; no `unwrap()`/`expect()` outside `#[cfg(test)]`.

### Guardrail #11 — `server/api/data-categories.md`

Every new field above is telemetry. The same PR adds a new subsection. Sketch:

> **2b. Process inspection / injection (macOS)**
>
> | Field | Source | Retention | Legal basis | Operator |
> |---|---|---|---|---|
> | `source_pid` / `target_pid` | ES GET_TASK / PROC_CHECK (`hk_es_get_task`, `hk_es_proc_check`) | 90 days | Legitimate interest | Horkos Service Operator |
> | `flavor` (get-task / proc_check) | ES event subtype | 90 days | Legitimate interest | Horkos Service Operator |
> | `source_team_id` / `source_signing_id` | `es_process_t` signing identity | 90 days | Legitimate interest | Horkos Service Operator |
> | `source_path_sha256` / `inserted_path_sha256` (mmap/dyld) | digest of `es_file_t` path | 365 days (rule training) | Legitimate interest | Horkos Service Operator |
> | `cs_flags` / `codesigning_flags` | `es_process_t.codesigning_flags` | 90 days | Legitimate interest | Horkos Service Operator |
> | `owner_pid` / `mask` (exception port) | `task_get_exception_ports` diff (`hk_es_exc_port`) | 90 days | Legitimate interest | Horkos Service Operator |
> | `thread_id` / `entry_pc` / `region_kind` | `task_threads`+`thread_get_state` (`hk_es_thread_origin`) | 90 days | Legitimate interest | Horkos Service Operator |
> | `tracer_pid` / `traced_now` | sysctl `P_TRACED` (`hk_es_ptrace`) | 90 days | Legitimate interest | Horkos Service Operator |
> | `region_addr` / `protection` / `share_mode` / `csops_valid` | `mach_vm_region_recurse`+`csops` (`hk_es_text_wx`) | 90 days | Legitimate interest | Horkos Service Operator |

The reviewer rejects the PR if any `hk_es_*` field is absent from this table.

---

## Mechanism implementation notes

### ES plane — `kernel/macos/es/EsClient.mm` (signals 109, 110, 111, 112, 115)

Add to `subscriptions[]`:
`ES_EVENT_TYPE_NOTIFY_GET_TASK`, `ES_EVENT_TYPE_NOTIFY_GET_TASK_NAME`,
`ES_EVENT_TYPE_NOTIFY_GET_TASK_READ`, `ES_EVENT_TYPE_NOTIFY_MMAP`,
`ES_EVENT_TYPE_NOTIFY_PROC_CHECK`. All are NOTIFY (no reply) — so guardrail #7 is not
triggered by these additions, but the existing AUTH_EXEC reply invariant and the
`default:` fail-safe ALLOW must stay exactly as-is. Do not convert any of these to AUTH.

- **109 / 110 (GET_TASK family).** One handler case per the three event types, all
  routing to a shared `emit_get_task(msg, flavor)`. Pull source from
  `msg->event.get_task.target` (the game) and the requester from `msg->process`. Record
  `is_platform_binary`, `team_id`, `signing_id` from `msg->process` (an `es_process_t`).
  Tag `flavor` = CONTROL / NAME / READ. **Do not flag client-side** — emit all three
  flavors and let the server suppress NAME (signal 110's "must NOT be flagged"). The
  `es_string_token_t` fields (`team_id`, `signing_id`) are pointer+len into the message;
  copy bytes out before the handler returns (the message is freed after) — never retain
  the `es_message_t`.
- **111 (MMAP).** Read `es_event_mmap_t.protection` (PROT_EXEC), `.flags` (MAP_ANON),
  `.source` (`es_file_t` path). Hash the source path; call `HKMmapBaselineMatch()` (daemon
  manifest) to tag `baseline_match`. Heavy FP surface (JIT) — the catalog says gate by
  per-title baseline + `com.apple.security.cs.allow-jit`; the gate lives in the daemon
  manifest + server, not in the ES handler. MMAP is high-volume: keep the handler to a
  bounded copy + `dispatch_async` to the sink (the existing pattern), never hash on the
  ES queue if it can be deferred — but path hashing of a short string is acceptable;
  measure.
- **112 (DYLD inject).** Extend the EXEC handler. Walk `es_exec_env_count(&msg->event.exec)`
  / `es_exec_env(&msg->event.exec, i)` for `DYLD_INSERT_LIBRARIES` /
  `DYLD_FRAMEWORK_PATH`. Cross-check `msg->event.exec.target->codesigning_flags` for
  `CS_RUNTIME` / `CS_RESTRICT`. Emit `hk_es_dyld_inject`; the "actual injected load"
  confirmation (`injected_load_seen`) requires correlating a later non-system image
  load — set it from the server side or from a follow-up image-load event, not inline.
- **115 (PROC_CHECK).** `ES_EVENT_TYPE_NOTIFY_PROC_CHECK`:
  `es_event_proc_check_t.target` (game), `.type` (`es_proc_check_type_t`). Aggregate
  per-source rate over a window in a small daemon-side table (not per-event emit) to avoid
  a telemetry flood; emit `hk_es_proc_check` once per window with `rate_per_window` +
  `flavor_cardinality`. The window aggregator is daemon state, fed from the ES sink.

**ES reply-deadline (guardrail #7).** None of the five new subscriptions are AUTH, so
none require `es_respond_auth_result`. The risk is volume, not deadline: GET_TASK, MMAP,
and PROC_CHECK can be very high-rate. Keep the ES-queue handler O(1) + bounded copy +
`dispatch_async` to `sSinkQueue` exactly as `emit_process_create` does. Do not add I/O,
hashing of large buffers, or manifest lookups on the ES serial queue — defer to the sink
queue or the daemon. A slow ES handler stalls every matching syscall system-wide.

### Daemon poll plane — `daemon/macos/horkosd.cpp` + new modules (signals 113, 114, 116, 117)

These are periodic pollers, not ES events. They run on a dedicated daemon dispatch queue
(NOT the XPC listener queue, NOT the ES queue). Poll cadence is a tradeoff (catch latency
vs CPU); the catalog says "sample at low frequency to bound cost" for 114 — start at
1–2 Hz, configurable, and document the latency window.

- **Shared (`HKGameTaskHandle`).** All three of 113/114/117 need a `task_t` for the game.
  Resolve once via the daemon's privileged path, validate via audit token, cache, refresh
  on game restart. Centralising this means the privileged-handle code is written and
  reviewed once.
- **113 (exception ports).** `task_get_exception_ports(game_task, EXC_MASK_ALL, masks,
  &count, ports, behaviors, flavors)`. Capture a baseline at game launch; re-poll and diff.
  A new non-self port owner ⇒ `is_foreign=1`. Resolve the receiving task to a pid where
  possible (may be unresolved across task boundaries — emit `owner_pid=0` then). Exclude
  the game's own in-process handlers and Apple diagnostics. Correlate server-side with the
  ES GET_TASK source.
- **114 (thread origin).** `task_threads(game_task, &list, &count)`, then per thread
  `thread_get_state(t, ARM_THREAD_STATE64 | x86_THREAD_STATE64, ...)` reading `__pc`/`__rip`.
  Resolve each start address against the dyld image list (`_dyld_get_image_header` /
  image vmaddr+vmsize ranges) — a `dladdr`-equivalent over the game's own image set.
  Flag entries not covered by any known mach-o image region, then intersect with the
  mmap-exec baseline (signal 111): a foreign entry inside a sanctioned JIT region is
  `region_kind = HK_REGION_JIT_SANCTIONED` and not high-signal. **MUST
  `vm_deallocate(mach_task_self(), list, count*sizeof(*list))`** after enumerating —
  `task_threads` returns an allocated array; leaking it is a per-poll memory leak.
- **116 (P_TRACED).** `sysctl(CTL_KERN, KERN_PROC, KERN_PROC_PID, pid)` → `struct
  kinfo_proc`; check `kp_proc.p_flag & P_TRACED`. Report only the **transition edge**
  (untraced→traced), not steady state, with the attaching pid (from `kp_eproc.e_ppid` or
  the correlated GET_TASK source). Gate by build channel: only emit when the binary is
  release-signed with no `get-task-allow` (`cs_release_signed=1`). Self-attach by the
  game's own crash handler does not set P_TRACED.
- **117 (__TEXT W^X).** Resolve the game's `__TEXT` segment vmaddr/vmsize from the on-disk
  mach-o load commands (slide-adjusted via the running image's ASLR slide).
  `mach_vm_region_recurse(game_task, &addr, &size, &depth, &info, &cnt)` across that range;
  flag any page with `info.protection & VM_PROT_WRITE` or a COW-broken `share_mode`
  (`SM_COW`) inside signed `__TEXT`. Cross-check `csops(pid, CS_OPS_STATUS, ...)` for
  signature invalidation. Narrow scope (writable strictly inside signed `__TEXT` of a
  `CS_RUNTIME` binary) keeps FPs low per the catalog.

### Server plane — `server/telemetry/src/macos_inject.rs` (guardrail #8)

Fully async on tokio; decode handlers are CPU-bound and short — run inline, no blocking
syscalls. `thiserror` `MacInjectError` for decode/score failures. No `unwrap()`/`expect()`
outside `#[cfg(test)]`; use `?` and `ok_or(MacInjectError::...)`. Scoring applies the
catalog FP gates: suppress GET_TASK_NAME (110); require non-platform-binary AND not in the
signed diagnostics allowlist AND no debugger session for 109; rate+cardinality threshold
for 115; release-channel gate for 116.

---

## Build wiring

- **ES plane:** no new CMake target. The five new event-type cases compile inside the
  existing `horkos_es` static library (`kernel/macos/es/CMakeLists.txt`), already gated by
  `HORKOS_MACOS_ES` (default **OFF**) and `-Wall -Wextra -Werror -fobjc-arc
  -mmacosx-version-min=12.0`. `ES_EVENT_TYPE_NOTIFY_GET_TASK_READ` requires the macOS 11.3+
  SDK (`es_get_task_type_t`); the lib already targets 12.0, so this is satisfied — note it
  in the CMake comment so a future SDK-floor change does not silently drop READ.
- **Daemon plane:** add the new `.cpp` files to `daemon/macos/CMakeLists.txt`'s `horkosd`
  target, behind the existing `if(APPLE)` guard, with the same `-Wall -Wextra -Werror`.
  Link `-framework Foundation` (already present) covers Mach/`libproc`; no extra framework
  for `task_*`/`mach_vm_*`/`sysctl`/`csops` (all in libSystem). Add a new option
  `HORKOS_MACOS_INJECT_POLLERS` (default **ON** when `APPLE`, but the privileged task-handle
  path is a no-op without the entitlement/root, matching the ES `_PROVISIONED` story).
- **Schema:** new `sdk/include/horkos/event_schema_macos.h` (pending the uncertainty-flag
  decision) added to the `sdk/include` install set and to `target_include_directories` of
  `horkos_es` and `horkosd`. Server adds `macos_inject.rs` to the `server/telemetry` crate
  module tree.
- **Toolchain:** Xcode CLT (clang) for macOS TUs; the Rust server unchanged (cargo). No
  WDK/libbpf/clang-19 involvement — this domain is macOS + server only.

---

## Test strategy

### Unit tests

- **Server (`macos_inject.rs`, `#[cfg(test)]`):** decode round-trip for every `hk_es_*`
  struct (byte buffer → struct, assert field values + size); FP-gate tables — GET_TASK_NAME
  suppressed, platform-binary GET_TASK suppressed, allowlisted team-id suppressed,
  PROC_CHECK below rate threshold suppressed, release-channel gate for ptrace. `unwrap()`
  allowed only here.
- **Daemon resolver units:** `HKThreadIntegrity` image-region resolver (given a synthetic
  image list + a PC, classify IMAGE vs ANON); `HKTextIntegrity` `__TEXT` range parser
  (parse a fixture mach-o, assert vmaddr/vmsize). These are pure-logic and host-runnable
  without a privileged task handle.
- **Schema size pins:** the `HK_STATIC_ASSERT`s are compile-time — a layout drift fails the
  build, which is the test.

### Bypass tests (guardrail #12 — merge gate; one per security-folder change)

Any change under `kernel/macos/es/`, `daemon/macos/`, or the new server module needs a
corresponding bypass test. Extend the existing `bypass-tests/macos/` (currently
`dylib_inject.cpp`, disabled-but-compiled pattern). New fixtures, same gate-green-while-
disabled idiom (`#ifndef HK_*_TEST_ENABLED → pass`):

| Bypass test | Must demonstrate (when enabled) |
|---|---|
| `bypass-tests/macos/task_for_pid_control.cpp` | Acquire the game's task **control** port from a foreign non-platform process ⇒ daemon/server reports a `hk_es_get_task` CONTROL event; a **NAME**-port acquisition in the same test produces **no** flag (signals 109/110). |
| `bypass-tests/macos/mmap_exec_foreign.cpp` | `mmap` a foreign mach-o / RWX anon page into the game ⇒ `hk_es_mmap` with `baseline_match != KNOWN`; a sanctioned-JIT map produces no flag (signal 111). |
| `dylib_inject.cpp` (existing — enable) | Re-signed/entitlement-stripped hardened binary with `DYLD_INSERT_LIBRARIES` set ⇒ `hk_es_dyld_inject` with `cs_flags & CS_RUNTIME` and a real injected load (signal 112). |
| `bypass-tests/macos/proc_info_recon.cpp` | High-rate `proc_pidinfo` VM-region walk of the game from a foreign process ⇒ `hk_es_proc_check` over threshold; single benign `PIDTASKINFO` poll produces no flag (signal 115). |
| `bypass-tests/macos/exc_port_hijack.cpp` | Foreign task installs itself as the game's `EXC_MASK_ALL` handler ⇒ `hk_es_exc_port` `is_foreign=1`; the game's own in-process handler produces no flag (signal 113). |
| `bypass-tests/macos/remote_thread.cpp` | `thread_create_running` in the game from another task with entry in an anon region ⇒ `hk_es_thread_origin` `region_kind=ANON`; a sanctioned-JIT-region thread produces no flag (signal 114). |
| `bypass-tests/macos/ptrace_attach.cpp` | `ptrace(PT_ATTACHEXC)` against a release-signed game ⇒ `hk_es_ptrace` transition edge with tracer pid; a dev/`get-task-allow` build produces no flag (signal 116). |
| `bypass-tests/macos/text_patch.cpp` | `mach_vm_protect` game `__TEXT` to RW + byte-patch ⇒ `hk_es_text_wx` writable/COW-broken page + `csops_valid=0` (signal 117). |

All registered in `bypass-tests/macos/CMakeLists.txt`. Disabled fixtures return 0 so the
gate stays green until the Phase 5 enforcement/correlation path lands; enabling them is the
acceptance criterion for each signal.

---

## Sequencing

1. **Schema first.** Land `event_schema_macos.h` (after the uncertainty-flag decision) with
   all `hk_es_*` structs + size pins, the `HK_EVENT_SCHEMA_VERSION` bump, the server
   `macos_inject.rs` mirror + decode round-trip tests, and the `data-categories.md` section.
   Nothing emits yet — this is the contract both planes build against. (No Windows IOCTL
   surface touched, so Windows wire-size asserts stay green.)
2. **Shared daemon handle.** `HKGameTaskHandle` + `HKMmapBaseline` — prerequisites for the
   pollers (113/114/117) and the MMAP gate (111).
3. **ES plane, low-risk first.** 109/110 (GET_TASK family) and 115 (PROC_CHECK) — pure NOTIFY
   additions, no reply-deadline risk, exercise the sink path. Then 112 (DYLD, extends the
   existing EXEC handler) and 111 (MMAP, needs the baseline from step 2).
4. **Daemon pollers.** 116 (ptrace, simplest — sysctl only), then 113 (exception ports),
   then 117 (`__TEXT` scan), then 114 (thread origin — depends on the 111 mmap baseline for
   the JIT intersection).
5. **Server scoring + correlation.** Wire the FP gates and the GET_TASK↔P_TRACED /
   GET_TASK↔exc-port correlations (113/116 reference the GET_TASK source).
6. **Bypass tests enabled** per signal as each lands — the merge gate for that signal.

Dependency edges: 111-baseline → 111-mmap-gate and 114-JIT-intersection; GET_TASK (109)
source attribution → 113 and 116 correlation; shared task handle → 113/114/117.

---

## Risks & UNCERTAINTY FLAGS

Per guardrail #13, the following are flagged rather than guessed:

1. **Schema split (design decision needed).** I recommend a new
   `sdk/include/horkos/event_schema_macos.h` for the macOS payloads rather than widening
   `HK_EVENT_PAYLOAD_MAX`/`hk_event_record` (which would break the Windows 40-byte
   `HK_STATIC_ASSERT` and the IOCTL ring). **Confirm this split before I touch the shared
   header.** If you'd rather one header, the IOCTL size pins must be reworked.

2. **`task_get_exception_ports` cross-task semantics (113).** UNCERTAIN whether resolving the
   *owning* task of a returned exception port reliably yields a pid across task/namespace
   boundaries, and whether a foreign poller can even read the game's exception ports without
   already holding a control-port-level handle. The validated game-task handle may itself be
   the only way to enumerate — meaning the sensor depends on the daemon's privilege path. Needs
   a hardware/VM spike before committing the poll design.

3. **ES `GET_TASK_READ` SDK floor + volume (109/110/111/115).** `es_get_task_type_t` /
   `GET_TASK_READ` is macOS 11.3+; the lib targets 12.0 so it compiles, but I have NOT
   measured the event **rate** of GET_TASK/MMAP/PROC_CHECK under a real game. If volume is
   high, the bounded-copy-then-dispatch pattern may still back-pressure the sink queue.
   Needs a load measurement; the per-window aggregation for 115 is the mitigation but its
   threshold is unvalidated.

4. **`mach_vm_region_recurse` + ASLR slide for `__TEXT` (117).** UNCERTAIN about correctly
   slide-adjusting the on-disk `__TEXT` vmaddr to the running image, and whether legitimate
   dyld page-in / shared-cache COW states present as `SM_COW` inside `__TEXT` and produce FPs.
   The catalog rates FP "low" but this needs empirical confirmation on Apple Silicon vs Intel.

5. **`thread_get_state` flavor per arch (114).** The arm64 vs x86_64 thread-state flavor and
   the `__pc`/`__rip` field access differ; Rosetta-translated games add a third case. NOT
   certain the entry-PC read is meaningful for a Rosetta'd (x86 under arm64) game task. Flag
   before relying on 114 for Rosetta titles.

6. **Entitlement / SIP dependency.** The whole daemon-poll plane needs a privileged game-task
   handle, which in production needs Apple entitlement approval (mirrors the ES
   `_PROVISIONED` story in `CMakeLists.txt`). Without it, the pollers are no-ops on a
   stock system. This is a known program risk, not a code bug — but it gates whether 113/114/117
   work outside a SIP-disabled dev box.

7. **No client-side trust decisions.** By design every FP gate (platform-binary, allowlist,
   debugger session, rate threshold) is server-side; the client emits raw events. If any gate
   creeps into `EsClient.mm`/the pollers to cut volume, that is a deviation from "clients sample
   and report only" and must be called out in review.
