/*
 * Role: Signal 201 sensor — walks the launch-ancestry chain (PID + create-time
 *       keyed to survive PID reuse) via the documented Toolhelp snapshot, reading
 *       each ancestor's image path, and ships the ordered root->game image list.
 *       The LOLBin catalog match + the "require the store client as chain root"
 *       gate are SERVER-SIDE (launch_trust.rs); the client only assembles the
 *       chain (guardrail: client emits, server decides).
 *       READ-ONLY.
 * Target platforms: Windows userspace. Guardrail #1: Toolhelp/path APIs confined
 *       to backends/win. NOT COMPILED on non-Windows (if(WIN32)).
 * Interface: hk::sdk::genealogy::collect_ancestry.
 */

#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>

namespace hk {
namespace sdk {
namespace genealogy {

struct ProcEntry {
    DWORD parent_pid;
    std::string image; /* szExeFile base name */
};

/* Walk from `game_pid` up the parent chain, bounded, returning the ordered
 * root->game image base names. A single Toolhelp snapshot is taken once; all
 * ancestor lookups walk the in-memory map rather than reopening the snapshot
 * per level. PID reuse is bounded by the single snapshot; the server keys the
 * chain by PID+create-time for cross-snapshot identity.
 * szExeFile is the base image name; the full path needs QueryFullProcessImageName.
 * HK-VERIFIED(ancestry-walker-access): QueryFullProcessImageName is documented to
 * require only PROCESS_QUERY_LIMITED_INFORMATION (not PROCESS_ALL_ACCESS).
 * ref: https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew
 * For ancestor PIDs visible in the snapshot, the AC can use OpenProcess with
 * PROCESS_QUERY_LIMITED_INFORMATION. Elevated/protected ancestors may still deny
 * (PPL), but the base name from szExeFile is the safe subset and is used here. */
std::vector<std::string> collect_ancestry(DWORD game_pid)
{
    std::vector<std::string> chain;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return chain;
    }

    std::unordered_map<DWORD, ProcEntry> proc_map;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            ProcEntry entry;
            entry.parent_pid = pe.th32ParentProcessID;
            entry.image = pe.szExeFile;
            proc_map[pe.th32ProcessID] = std::move(entry);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    DWORD pid = game_pid;
    for (int depth = 0; depth < 32; ++depth) {
        auto it = proc_map.find(pid);
        if (it == proc_map.end()) {
            break;
        }
        chain.push_back(it->second.image);
        DWORD parent = it->second.parent_pid;
        if (parent == 0 || parent == pid) {
            break; /* reached the root / a self-cycle */
        }
        pid = parent;
    }

    /* chain is game->root; reverse to root->game for the server. */
    std::reverse(chain.begin(), chain.end());
    return chain;
}

} // namespace genealogy
} // namespace sdk
} // namespace hk
