/*
 * Role: BYOVD (bring-your-own-vulnerable-driver) blocklist lookup. Phase 3
 *       ships the data structure and the lookup entry point with an EMPTY list,
 *       so the answer is always "not blocked". The real list is fetched as a
 *       server-pushed signed bundle (Phase 2 rule-bundle plumbing) and the
 *       enforcement fixture + bypass test land in Phase 5.
 * Target platforms: Windows kernel mode (KMDF).
 * Interface: implements HkWhitelistIsBlockedImage declared in
 *       kernel/win/include/horkos_kernel.h.
 */

#include <ntddk.h>

#include "horkos_kernel.h"

/* A blocklist entry is a SHA-256 of a known-vulnerable driver image. Phase 3
 * carries the type only; the array is intentionally empty. Never commit a real
 * BYOVD binary or its hash sourced from loldrivers.io — the bypass fixture in
 * Phase 5 builds its own deliberately-vulnerable test driver. */
typedef struct _HK_BYOVD_ENTRY {
    UCHAR Sha256[32];
} HK_BYOVD_ENTRY;

static const HK_BYOVD_ENTRY g_Blocklist[] = {
    /* Empty in Phase 3. Populated from the signed rule bundle in a later phase. */
    { { 0 } }
};

/* Count of real entries (the single zero entry above is a placeholder, not a
 * match candidate). */
static const ULONG g_BlocklistCount = 0;

_Use_decl_annotations_
BOOLEAN HkWhitelistIsBlockedImage(PUNICODE_STRING FullImageName)
{
    UNREFERENCED_PARAMETER(FullImageName);

    /* No entries in Phase 3: nothing is ever blocked. Hashing the image and
     * comparing against g_Blocklist lands with the signed-bundle ingestion. */
    if (g_BlocklistCount == 0) {
        return FALSE;
    }

    return FALSE;
}
