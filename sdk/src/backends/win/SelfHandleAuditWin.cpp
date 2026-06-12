/*
 * Role: Windows userspace self-handle audit (win-handle-memory-access, catalog
 *       signal 70). One tick: NtQuerySystemInformation(SystemExtendedHandleInformation)
 *       to enumerate every Process-type handle in the system, filter to those whose
 *       target is the game pid, and classify each foreign holder by GrantedAccess +
 *       owner signing. A foreign process holding VM_READ/WRITE/OPERATION on the game
 *       is the signal; an unsigned owner weights it up. Read-only; high-FP alone
 *       (legitimate overlays/AV hold handles), so it reports at low base confidence
 *       and the server fuses it with a coinciding kernel Ob/VM event. Ships dark
 *       (HK_WIN_VMWATCH OFF).
 * Target platforms: Windows userspace. Guardrail #1: the NtQuerySystemInformation
 *       call is confined here; the holder_is_dangerous decision core is platform-free
 *       in VmWatchWin.h and host-tested.
 * Interface: implements hk::sdk::vmaccess::sample_self_handles from VmWatchWin.h.
 */

#include "VmWatchWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

namespace hk { namespace sdk { namespace vmaccess {

/* -------------------------------------------------------------------------
 * HK-UNCERTAIN(system-handle-info): SystemExtendedHandleInformation is an
 * NtQuerySystemInformation class that is NOT in the public Windows SDK headers;
 * relying on it needs the exact info-class number (0x40) AND the
 * SYSTEM_HANDLE_INFORMATION_EX / SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX struct shapes
 * confirmed against the target build (the per-entry layout — UniqueProcessId,
 * HandleValue, GrantedAccess, ObjectTypeIndex — has shifted across Windows
 * versions, and the call requires a grow-the-buffer retry loop on
 * STATUS_INFO_LENGTH_MISMATCH). Resolving Process-type entries also needs the live
 * Process ObjectTypeIndex, which is itself version-dependent. Per guardrail #13 this
 * sampler is SCAFFOLD ONLY: the read + classify sequence is laid out and routed
 * through the pure holder_is_dangerous core, but the NtQuerySystemInformation call is
 * a documented stub rather than coded against unverified class numbers / struct
 * layouts. The pure core (the tested part) is unaffected.
 * ------------------------------------------------------------------------- */
int sample_self_handles(uint32_t game_pid)
{
    /* Steps the verified implementation performs (NOT coded here — see HK-UNCERTAIN):
     *   1. NtQuerySystemInformation(SystemExtendedHandleInformation) with the
     *      grow-on-STATUS_INFO_LENGTH_MISMATCH retry loop -> the system handle table.
     *   2. Resolve the Process ObjectTypeIndex for this build (one reference query).
     *   3. For each entry whose ObjectTypeIndex == Process and whose target resolves
     *      to game_pid: read UniqueProcessId (owner) + GrantedAccess.
     *   4. Resolve the owner image's Authenticode signer (wintrust/crypt32) and the
     *      server allow-list bit.
     *   5. ForeignHolderInput{ owner_pid, game_pid, granted_access, owner_signed,
     *      owner_allowlisted } -> holder_is_dangerous(...). On true, queue an
     *      hk_event_foreign_holder finding with the returned flags (low confidence).
     *      HK-TODO(schema): the report-queue type is the kernel-private mirror until
     *      the Schema phase appends HK_EVENT_FOREIGN_HOLDER to event_schema.h.
     */
    (void)game_pid;
    return -1; /* not sampled: SystemExtendedHandleInformation is an on-box stub */
}

} } } // namespace hk::sdk::vmaccess

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
