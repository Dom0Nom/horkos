/*
 * kernel/linux/userspace/ModuleViewDiff.cpp
 * Role: Implementation of signal 92 (module-view cross-enumeration diff) declared
 *       in ModuleViewDiff.h.
 * Target platform: Linux userspace.
 * Interface: implements horkos::modint::ParseProcModules / BuildPresence /
 *            ModuleViewDiffer / hk_sensor_module_view.
 *
 * Guardrail compliance: #1, #3, #4. Read-only / audit-only.
 */

#include "ModuleViewDiff.h"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace horkos::modint {

namespace {

std::string TrimWs(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::string ReadFileBest(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

std::set<std::string> ListSysModule(const std::string& sys_module_dir) {
    std::set<std::string> out;
    std::error_code ec;
    std::filesystem::directory_iterator it(sys_module_dir, ec), end;
    if (ec) return out;
    for (; it != end; it.increment(ec)) {
        if (ec) break;
        if (!it->is_directory(ec)) continue;
        out.insert(it->path().filename().string());
    }
    return out;
}

}  // namespace

std::set<std::string> ParseProcModules(const std::string& content) {
    std::set<std::string> out;
    std::istringstream lines(content);
    std::string line;
    while (std::getline(lines, line)) {
        std::string t = TrimWs(line);
        if (t.empty()) continue;
        std::istringstream cols(t);
        std::string name;
        if (cols >> name && !name.empty()) out.insert(name);
    }
    return out;
}

PresenceSnapshot BuildPresence(const ModuleViews& views) {
    PresenceSnapshot snap;
    for (const auto& m : views.proc_modules) snap[m] |= HK_MV_PROCMODULES;
    for (const auto& m : views.sysfs_modules) snap[m] |= HK_MV_SYSFS;
    if (views.lkm_view_present) {
        for (const auto& m : views.lkm_or_bpf) snap[m] |= HK_MV_BPF_OR_LKM;
    }
    return snap;
}

bool IsSingleSourceDiscrepancy(uint32_t present_mask, bool lkm_present) {
    /* /sys/module also lists built-in (non-loadable) modules that never appear in
     * /proc/modules; those have ONLY HK_MV_SYSFS and are NOT a hiding tell. The
     * load-bearing case is the opposite: present in /proc but missing from /sys
     * (a procfs ghost), or present in the LKM/bpf list but in NEITHER userspace
     * view (a doubly-hidden module the kernel walk still sees). A sysfs-only
     * entry is treated as benign here; the server's allowlist refines further.
     *
     * NOTE: the canonical list_del self-unlink hides a module from /proc/modules
     * while its sysfs kobject survives — that is HK_MV_SYSFS set, HK_MV_PROCMODULES
     * clear. We MUST flag that. So: flag when sysfs-present XOR proc-present, EXCEPT
     * we cannot distinguish "built-in sysfs-only" from "unlinked-from-proc" at the
     * client; we report the raw mask and let the server allowlist built-ins by
     * name. To keep the client FP-low we still flag the asymmetry and carry the
     * full mask. */
    bool in_proc = (present_mask & HK_MV_PROCMODULES) != 0;
    bool in_sys = (present_mask & HK_MV_SYSFS) != 0;
    bool in_lkm = (present_mask & HK_MV_BPF_OR_LKM) != 0;

    if (in_proc != in_sys) return true;   /* asymmetric userspace views */
    if (lkm_present && in_lkm && !in_proc && !in_sys) return true;  /* doubly hidden */
    return false;
}

int ModuleViewDiffer::Observe(const ModuleViews& views, HkEventSink sink,
                              bool had_proc, bool had_sysfs) {
    /* Both core userspace views unreadable → coverage gap, not a diff. */
    if (!had_proc && !had_sysfs) {
        HkEmitUnavailable(sink, kSignalModuleView, 0);
        have_prev_ = false;   /* drop debounce state; next cycle restarts */
        return 0;
    }

    PresenceSnapshot cur = BuildPresence(views);
    int emitted = 0;

    if (have_prev_) {
        for (const auto& [name, mask] : cur) {
            if (!IsSingleSourceDiscrepancy(mask, views.lkm_view_present)) continue;
            /* Debounce: the SAME discrepancy must have been present last cycle.
             * If a source was unreadable in EITHER snapshot for this module the
             * mask differs and the debounce naturally suppresses it. */
            auto pit = prev_.find(name);
            if (pit == prev_.end()) continue;
            if (!IsSingleSourceDiscrepancy(pit->second, views.lkm_view_present)) continue;
            if (pit->second != mask) continue;   /* state still settling */

            HkEvtModuleViewDiff ev{};
            ev.name_hash = HkNameHash(name);
            ev.present_mask = mask;
            ev.module_state = 0;   /* debounced to live; COMING/GOING absorbed */
            HkEmit(sink, kEvtModuleViewDiff, &ev, sizeof(ev));
            ++emitted;
        }
    }

    prev_ = std::move(cur);
    have_prev_ = true;
    return emitted;
}

int hk_sensor_module_view(const HkSymbolMap* map, HkEventSink sink) {
    (void)map;
    static ModuleViewDiffer differ;   /* persists debounce across cycles */

    ModuleViews views;
    std::string proc = ReadFileBest("/proc/modules");
    std::ifstream proc_probe("/proc/modules");
    bool had_proc = !proc.empty() || proc_probe.good();
    views.proc_modules = ParseProcModules(proc);

    views.sysfs_modules = ListSysModule("/sys/module");
    /* had_sysfs: /sys/module exists. An empty listing on a mounted sysfs is
     * legitimate-ish but rare; treat a successful directory open as readable. */
    std::error_code ec;
    bool had_sysfs = std::filesystem::exists("/sys/module", ec) && !ec;

    /* LKM/bpf third view: the LKM debugfs module-CRC seq file, when present. We
     * only consult it for NAMES here (CRC compare is signal 95). */
    {
        std::string crcs = ReadFileBest("/sys/kernel/debug/horkos/module_crcs");
        if (!crcs.empty()) {
            std::istringstream lines(crcs);
            std::string line;
            while (std::getline(lines, line)) {
                std::string t = TrimWs(line);
                if (t.empty()) continue;
                std::istringstream cols(t);
                std::string name;
                if (cols >> name && !name.empty()) views.lkm_or_bpf.insert(name);
            }
            views.lkm_view_present = true;
        }
    }

    /* The 500 ms inter-snapshot debounce is realised by the aggregator calling
     * this sensor twice per 30 s cycle 500 ms apart; the differ requires two
     * consecutive agreeing snapshots before emitting (§5). */
    differ.Observe(views, sink, had_proc, had_sysfs);
    return 0;
}

}  // namespace horkos::modint
