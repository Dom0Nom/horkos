/*
 * Role: Single source of platform truth for the entire codebase.
 *       Defines HK_PLATFORM_* macros and declares cross-platform abstractions.
 *       Every platform-conditional include or API must route through this header.
 * Target platforms: Windows, Linux, macOS
 * Interface: this IS the platform interface header; backends implement it.
 */

#pragma once

/* -------------------------------------------------------------------------
 * Platform detection — set exactly once, here, never elsewhere.
 * Backends in platform_win.cpp / platform_linux.cpp / platform_macos.cpp
 * are selected by CMake if(WIN32)/if(APPLE)/if(UNIX) and always compile
 * for their matching host, so they do not need these guards at file scope.
 * ------------------------------------------------------------------------- */
#if defined(_WIN32)
#  define HK_PLATFORM_WINDOWS 1
#elif defined(__APPLE__)
#  define HK_PLATFORM_MACOS   1
#elif defined(__linux__)
#  define HK_PLATFORM_LINUX   1
#else
#  error "Unsupported platform"
#endif

#include <cstdint>

namespace hk { namespace platform {

/* Process identifier type. On Windows this is DWORD; on POSIX it is pid_t.
   We expose it as a fixed-width alias so callers never include OS headers. */
using process_id_t    = uint32_t;

/* Opaque handle to a loaded module / shared library. */
using module_handle_t = void*;

/* Returns the OS page size in bytes. */
uint32_t page_size();

/* Returns the calling process's PID. */
process_id_t current_process_id();

/* Returns true if a debugger is currently attached to this process.
   Phase 1 implementation is deliberately weak (system API only).
   Anti-debug hardening lands in a later phase under /tdd. */
bool is_debugger_attached();

/* -------------------------------------------------------------------------
 * macOS platform-trust reads (signal 124). Declared platform-neutrally; the
 * bodies are macOS-only (platform_macos.cpp) and route the IORegistry + csr_*
 * SPI reads through this seam so the AmfiPostureProbe TU never touches OS APIs
 * directly (guardrail #1). On non-macOS backends these are not implemented (the
 * declarations exist so the header stays a single source of truth; only the
 * macOS daemon links the macOS backend).
 *
 * csr_active_config: the raw CSR (System Integrity Protection) configuration
 * bitfield, as returned by the csr_get_active_config SPI. Returns false (and
 * leaves *out_config untouched) if the SPI is unavailable — the caller must NOT
 * treat an unavailable read as "SIP disabled".
 *
 * sip_enabled: a coarse "is SIP active" answer derived from the CSR config.
 * Returns true when the read is unavailable (fail-safe: do not assume a
 * dev/weakened box when we cannot tell).
 *
 * read_boot_args: copies the IORegistry "boot-args" string into the caller's
 * buffer (NUL-terminated, truncated to cap). Returns the number of bytes written
 * (excluding the terminator), or 0 if the property is absent/unreadable.
 * ------------------------------------------------------------------------- */
bool     csr_active_config(uint32_t *out_config);
bool     sip_enabled();
uint32_t read_boot_args(char *out, uint32_t cap);

/* -------------------------------------------------------------------------
 * Client self-integrity read seams (memory-integrity-selfcheck, signals
 * 145-153). Declared platform-neutrally; the bodies are per-OS
 * (platform_win.cpp / _linux.cpp / _macos.cpp) and route the kernel/daemon
 * foreign read of the AC's OWN address space through this seam so the selfcheck
 * sensor TUs never touch an OS API directly (guardrail #1). The authoritative,
 * non-spoofable reads (kernel foreign read / page-share / PTE / DR) cannot be
 * restored-on-read by a usermode hook — that is the whole point of routing them
 * through the kernel/daemon rather than reading our own VA in-process.
 *
 * page_share_state (146): writes per-page private/CoW + dirty counts for the
 * code range [va_base, va_base+va_len) into *out_private / *out_dirty. Returns
 * false (and leaves the outputs untouched) if the per-OS read is unavailable —
 * the caller must NOT treat unavailable as "no evidence" or "clean".
 *
 * module_image_file_name (151): copies the kernel/loader's authoritative backing
 * FILE name for the VA `addr` into `out` (NUL-terminated, truncated to cap).
 * Returns the bytes written (excluding terminator), or 0 if unavailable.
 *
 * selfcheck_kernel_read (145/148/152): issues the self-read request for one of
 * the hk_self_read_kind operations against the caller's OWN image and copies the
 * reply bytes into `out` (cap bytes). Returns the number of bytes written, or 0
 * if the read was refused/unavailable. The Win backend issues HK_IOCTL_SELF_READ_VA
 * to the driver; Linux uses the eBPF/LKM self-read path; macOS uses the daemon's
 * mach_vm_* over the AC's own task port. The kernel/daemon validates caller
 * identity and range containment before honoring the request (see §8 uncertainty).
 * `req_kind` is a hk_self_read_kind; `va_base`/`va_len` bound the request.
 * ------------------------------------------------------------------------- */
bool     page_share_state(uint64_t va_base, uint64_t va_len,
                          uint32_t *out_private, uint32_t *out_dirty);
uint32_t module_image_file_name(uint64_t addr, char *out, uint32_t cap);
uint32_t selfcheck_kernel_read(uint32_t req_kind, uint64_t va_base, uint64_t va_len,
                               void *out, uint32_t cap);

/* -------------------------------------------------------------------------
 * Timing/execution-trace side-channel clock seam (timing-side-channels, signal
 * 156 sibling-thread RDTSCP watchdog; reused by 159/161/162 fenced timing).
 * Declared platform-neutrally so the timing sensor TUs (under ac/src/timing)
 * never touch a raw `__rdtscp` intrinsic or an affinity API directly
 * (guardrail #1). The bodies live per-OS (platform_win.cpp / _linux.cpp /
 * _macos.cpp) and gate the x86 intrinsic behind the arch, returning a 0 aux on
 * non-x86 hosts (e.g. Apple Silicon).
 *
 * rdtscp_aux: serialized timestamp read. Returns the 64-bit TSC and writes the
 * IA32_TSC_AUX value (the OS-programmed logical-core id on x86; 0 where TSC_AUX
 * is unavailable) into *out_aux. On non-x86 it falls back to a monotonic ns
 * clock and sets *out_aux=0 — callers must treat aux==0 as "core id unknown"
 * and not infer a migration from it (see signal-156 notes).
 *
 * pin_thread_to_core / unpin_thread: best-effort affinity for the watchdog
 * thread. Windows/Linux give hard pinning; macOS exposes only affinity *hints*
 * (thread_policy_set), so on macOS this returns false and the watchdog must
 * weight its core-migration discard logic down (plan FLAG signal-156 macOS).
 * Returns true only if a hard pin was applied.
 * ------------------------------------------------------------------------- */
uint64_t rdtscp_aux(uint32_t *out_aux);
bool     pin_thread_to_core(uint32_t core_index);
void     unpin_thread();

} } // namespace hk::platform
