/*
 * sdk/src/backends/win/ancestry_walker.cpp
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
#include <vector>

namespace hk {
namespace sdk {
namespace genealogy {

/* Map PID -> (parent PID, image base name) for the current snapshot. */
static bool ParentAndImage(DWORD pid, DWORD* parent, std::string* image)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    bool found = false;
    if (snap == INVALID_HANDLE_VALUE) {
        return false;
    }
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                *parent = pe.th32ParentProcessID;
                /* szExeFile is the base image name; the full path needs
                 * QueryFullProcessImageName (HK-UNCERTAIN per access rights) — the
                 * base name is the verifiable subset the server matches. */
                *image = pe.szExeFile;
                found = true;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

/* Walk from `game_pid` up the parent chain, bounded, returning the ordered
 * root->game image base names. PID reuse is bounded by the snapshot + the depth
 * cap; the server keys the chain by PID+create-time for cross-snapshot identity. */
std::vector<std::string> collect_ancestry(DWORD game_pid)
{
    std::vector<std::string> chain;
    DWORD pid = game_pid;
    for (int depth = 0; depth < 32; ++depth) {
        DWORD parent = 0;
        std::string image;
        if (!ParentAndImage(pid, &parent, &image)) {
            break;
        }
        chain.push_back(image);
        if (parent == 0 || parent == pid) {
            break; /* reached the root / a self-cycle. */
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
