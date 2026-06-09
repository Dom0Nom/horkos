/*
 * kernel/win/src/EtwIntegrity.c
 * Role: kernel ETW provider/logger-session integrity + infinity-hook probe.
 *       Signal 212 (ETW-TI provider liveness: raw-handle read + version-
 *       independent consumer keepalive), 215 (kernel logger-session census vs boot
 *       baseline), 211 (infinity-hook perf-trace callback bounds). Every sensor is
 *       READ-ONLY: it reads ETW state/globals and bounds-checks, then emits
 *       HK_EVENT_INTEGRITY_FINDING; it installs no callback and writes no kernel
 *       state. Runs from the single PASSIVE_LEVEL integrity work item. The
 *       keepalive counter coordinates with the (future) ETW-TI consumer — see the
 *       HK-UNCERTAIN(etw-ti-consumer) note.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkEtwTiLiveness / HkEtwSessionCensus / HkInfinityHookProbe
 *       declared in kernel/win/include/horkos_kernel.h. Each is a no-op stub unless
 *       its HK_WIN_ETW_* build flag is defined. Emits hk_event_integrity_finding.
 */

#include <ntddk.h>
#include <wdf.h>

#include "horkos_kernel.h"

/* Minimum TI events expected within one scan interval before the keepalive is
 * considered stale (signal 212 floor). A quiet box still produces some TI traffic;
 * 0 here means "any advance is liveness" and the floor is conservative. The pure
 * predicate HkKeepaliveStale applies it. */
#ifndef HK_ETW_KEEPALIVE_MIN_DELTA
#  define HK_ETW_KEEPALIVE_MIN_DELTA 0u
#endif

/* =========================================================================
 * Signal 212 — ETW-TI provider liveness.
 * ========================================================================= */
#if defined(HK_WIN_ETW_TI)

_Use_decl_annotations_
void HkEtwTiLiveness(PHK_DEVICE_CONTEXT Ctx)
{
    LONG64 now;
    LONG64 prev;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (Ctx == NULL) {
        return;
    }

    /* (b) Keepalive half — the version-independent, default-ON half (plan: weighted
     * higher than the raw-handle read). Horkos's ETW-TI consumer bumps
     * EtwTiKeepalive per TI event; we check it advanced since the previous scan.
     *
     * HK-UNCERTAIN(etw-ti-consumer): whether the ETW-TI feed is consumed in-kernel
     * or by a user-mode PPL consumer determines WHERE the counter is bumped (plan
     * Risk 7). ETW-TI (Microsoft-Windows-Threat-Intelligence) is a PROTECTED
     * provider: an ordinary KMDF driver CANNOT open a real-time session on it; only
     * a PPL/ELAM-signed user-mode process may. Horkos holds no anti-malware/ELAM
     * cert today, so there is no in-kernel TI consumer to bump this counter. Until
     * the consumption architecture is decided and a consumer exists,
     * EtwKeepaliveArmed stays 0 and this half is correctly UNVERIFIABLE-gated. Do
     * NOT fabricate a kernel ETW-TI consumer. */
    if (InterlockedCompareExchange(&Ctx->EtwKeepaliveArmed, 0, 0) == 0) {
        HkIntegrityEmit(212u, HK_INTEGRITY_UNVERIFIABLE, 0ull);
    } else {
        now = InterlockedCompareExchange64(&Ctx->EtwTiKeepalive, 0, 0);
        prev = Ctx->EtwTiKeepalivePrev;
        if (HkKeepaliveStale((uint64_t)prev, (uint64_t)now,
                             (uint64_t)HK_ETW_KEEPALIVE_MIN_DELTA)) {
            HkIntegrityEmit(212u, HK_INTEGRITY_ETWTI_NO_KEEPALIVE, 0ull);
        }
        Ctx->EtwTiKeepalivePrev = now;
    }

    /* (a) Raw-handle half — default-OFF/offset-gated. HK-UNCERTAIN(etwti-handle):
     * EtwThreatIntProvRegHandle is an unexported global; resolving it needs a
     * per-build offset table or pattern scan (plan Risk 1) — forbidden to guess. If
     * the baseline could not resolve it at arm time (EtwTiHandlePresent stays the
     * default), we do NOT read a guessed address; the keepalive half above stands
     * alone. Wire the offset-table read here only after the strategy is agreed. */
    if (!Ctx->EtwBaseline.Valid) {
        /* No verifiable ETW baseline => the handle half is unverifiable; the
         * keepalive half already reported above. */
        return;
    }
}

#else
_Use_decl_annotations_
void HkEtwTiLiveness(PHK_DEVICE_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
}
#endif /* HK_WIN_ETW_TI */

/* =========================================================================
 * Signal 215 — kernel ETW logger-session census vs boot baseline.
 * ========================================================================= */
#if defined(HK_WIN_ETW_SESSION)

_Use_decl_annotations_
void HkEtwSessionCensus(PHK_DEVICE_CONTEXT Ctx)
{
    ULONG    currentMask;
    uint32_t suppressed;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (Ctx == NULL) {
        return;
    }
    if (!Ctx->EtwBaseline.Valid) {
        HkIntegrityEmit(215u, HK_INTEGRITY_UNVERIFIABLE, 0ull);
        return;
    }

    /* HK-UNCERTAIN(etw-session-query): querying the live logger table from kernel
     * mode (NtTraceControl EtwQueryAllTraces / EVENT_TRACE_PROPERTIES buffer
     * sizing) is undocumented for kernel callers (plan Risk 6). Until the
     * kernel-callable surface is confirmed on-box, currentMask cannot be sampled,
     * so this sensor cannot diff and emits UNVERIFIABLE. Default-OFF. Do NOT call
     * an unconfirmed NtTraceControl path from kernel mode.
     *
     * Once confirmed, currentMask is built by mapping each live security-relevant
     * provider GUID to its HK_ETW_PROVIDER_* bit, then the pure diff runs: */
    currentMask = Ctx->EtwBaseline.SecurityProviderMask; /* placeholder: == baseline. */
    suppressed = HkEtwProviderSuppressed(Ctx->EtwBaseline.SecurityProviderMask,
                                         currentMask, HK_ETW_DEPENDENCY_MASK);
    if (suppressed != 0) {
        /* detail = the suppressed-dependency provider bitmask (no address). */
        HkIntegrityEmit(215u, HK_INTEGRITY_ETW_SESSION_SUPPR, (uint64_t)suppressed);
    } else {
        /* No live query yet => report unverifiable so the server scores no-signal
         * rather than mistaking the placeholder "clean" for a real all-clear. */
        HkIntegrityEmit(215u, HK_INTEGRITY_UNVERIFIABLE, 0ull);
    }
}

#else
_Use_decl_annotations_
void HkEtwSessionCensus(PHK_DEVICE_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
}
#endif /* HK_WIN_ETW_SESSION */

/* =========================================================================
 * Signal 211 — infinity-hook perf-trace callback bounds (default-OFF).
 * ========================================================================= */
#if defined(HK_WIN_ETW_INFINITYHOOK)

_Use_decl_annotations_
void HkInfinityHookProbe(PHK_DEVICE_CONTEXT Ctx, const HK_KERNEL_IMAGE* Img)
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (Ctx == NULL || Img == NULL || !Img->Valid) {
        return;
    }

    /* HK-UNCERTAIN(infinity-hook): the technique repoints the WMI_LOGGER_CONTEXT
     * trace-clock / GetCpuClock callback (reached via HalpPerfInterrupt and
     * EtwpDebuggerData) to attacker code. WMI_LOGGER_CONTEXT internals,
     * EtwpDebuggerData, and HalpPerfInterrupt are ALL undocumented and shift across
     * builds (plan Risk 8, catalog medium FP). The only version-independent
     * corroboration shipped here is the precondition check — whether circular-
     * kernel-trace / high-frequency perf logging was silently enabled — which is
     * gated by the signal-215 session census so xperf/WPR do not false-positive.
     * The callback-target bounds check requires a recognized struct layout; with no
     * validated layout this emits UNVERIFIABLE. Default-OFF until the struct walk is
     * validated. Do NOT walk a guessed WMI_LOGGER_CONTEXT offset. */
    HkIntegrityEmit(211u, HK_INTEGRITY_UNVERIFIABLE, 0ull);
}

#else
_Use_decl_annotations_
void HkInfinityHookProbe(PHK_DEVICE_CONTEXT Ctx, const HK_KERNEL_IMAGE* Img)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Img);
}
#endif /* HK_WIN_ETW_INFINITYHOOK */
