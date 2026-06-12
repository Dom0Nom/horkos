/*
 * Role: Signal 202 userspace half — enumerates the game's executable memory
 *       regions (VirtualQueryEx MEM_PRIVATE/MEM_IMAGE + PAGE_EXECUTE_*) and the
 *       PEB Ldr module list, and reports regions absent from both the kernel
 *       image-load set and the PEB Ldr (attributed against known JIT allocator
 *       ranges). The reconcile (kernel notify-set vs userspace region-set) is
 *       SERVER-SIDE; this ships the executable-region inventory.
 *       READ-ONLY.
 * Target platforms: Windows userspace. Guardrail #1: VirtualQuery/PEB confined to
 *       backends/win. NOT COMPILED on non-Windows (if(WIN32)).
 * Interface: hk::sdk::genealogy::collect_exec_regions.
 */

#include <windows.h>

#include <cstdint>
#include <vector>

namespace hk {
namespace sdk {
namespace genealogy {

struct ExecRegion {
    uint64_t base;
    uint64_t size;
    uint32_t type;       /* MEM_PRIVATE / MEM_IMAGE / MEM_MAPPED. */
    uint32_t protect;    /* the PAGE_EXECUTE_* protection. */
};

/* Enumerate the current process's executable regions. (The game enumerates its
 * OWN address space — no foreign VirtualQueryEx, no special rights.) The server
 * diffs these against the kernel image-load set + PEB Ldr to find manual-map
 * artifacts; this only inventories. */
std::vector<ExecRegion> collect_exec_regions()
{
    std::vector<ExecRegion> regions;
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uint8_t* addr = (uint8_t*)si.lpMinimumApplicationAddress;
    uint8_t* end = (uint8_t*)si.lpMaximumApplicationAddress;

    while (addr < end && regions.size() < 4096) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            break;
        }
        DWORD p = mbi.Protect;
        bool exec = (p & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                          PAGE_EXECUTE_WRITECOPY)) != 0;
        if (mbi.State == MEM_COMMIT && exec) {
            ExecRegion r;
            r.base = (uint64_t)(uintptr_t)mbi.BaseAddress;
            r.size = (uint64_t)mbi.RegionSize;
            r.type = mbi.Type;
            r.protect = mbi.Protect;
            regions.push_back(r);
        }
        /* Advance past this region; guard against a zero-size step. */
        if (mbi.RegionSize == 0) {
            break;
        }
        addr += mbi.RegionSize;
    }
    return regions;
}

} // namespace genealogy
} // namespace sdk
} // namespace hk
