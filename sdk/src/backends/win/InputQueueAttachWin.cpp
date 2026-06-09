/*
 * sdk/src/backends/win/InputQueueAttachWin.cpp
 * Role: Signal 61 (win-input-automation). GUI-thread input-queue-attach sensor.
 *       Reads GetGUIThreadInfo for the game's input thread and compares the
 *       active/focus/capture window ownership + queue-shared state against
 *       expectation; cross-process queue attachment (AttachThreadInput) shows up as a
 *       foreign thread sharing the game's input state. Reports owning_pid +
 *       owning_image of the attaching process with HK_INFLAG_QUEUE_ATTACHED. IMEs /
 *       screen-readers / UI-automation legitimately attach, so the benign signer
 *       allow-list is server-side (catalog) — the client only flags when the attacher
 *       is also unsigned or already flagged by the process/handle sensors.
 * Target platforms: Windows userspace. Guardrail #1: GetGUIThreadInfo /
 *       GetWindowThreadProcessId confined here.
 * Interface: implements hk::sdk::win::sense_input_queue_attach.
 */

#include "InputSensorWin.h"

#if defined(HK_PLATFORM_WINDOWS) || defined(_WIN32)

#include <windows.h>

namespace hk { namespace sdk { namespace win {

int sense_input_queue_attach(std::vector<hk_input_finding>& out)
{
    /* Read the foreground thread's GUI info as the reference point. cbSize MUST be
     * set before the call or it fails (documented contract). This is read-only and
     * self-contained — no input stream needed — but attributing a foreign attach
     * requires the game's OWN input-thread id from the SDK to compare against. */
    GUITHREADINFO gti{};
    gti.cbSize = sizeof(gti);
    const DWORD fg_thread = GetWindowThreadProcessId(GetForegroundWindow(), nullptr);
    if (fg_thread == 0 || GetGUIThreadInfo(fg_thread, &gti) == 0) {
        /* Query failed: stay silent rather than fabricating an attach. */
        (void)out;
        return 0;
    }

    /* HK-TODO(sdk-integration): the comparison that detects a FOREIGN attach needs
     * the game's own GUI input-thread id (from the SDK) to diff against this
     * GUITHREADINFO. Once provided, the folding is:
     *
     *   GUITHREADINFO game{}; game.cbSize = sizeof(game);
     *   GetGUIThreadInfo(game_input_tid, &game);
     *   for each window in {gti.hwndActive, hwndFocus, hwndCapture}:
     *       DWORD pid = 0; DWORD tid = GetWindowThreadProcessId(hwnd, &pid);
     *       if (tid != game_input_tid && shares_queue_with(game_input_tid)) {
     *           finding.flags     = HK_INFLAG_QUEUE_ATTACHED;
     *           finding.owning_pid = pid;          // owning_image rides JSON side-channel
     *           out.push_back(finding);            // server scores against signer allow-list
     *       }
     *
     * The attaching-process signer allow-list (IMEs/screen-readers/UI-automation are
     * benign) is server-side; the client flags only when the attacher is also unsigned
     * or already flagged by the process/handle sensors. Without the game's own
     * input-thread id, we cannot tell a foreign attach from the game's own thread, so
     * we emit nothing rather than mis-attribute. */
    (void)gti;
    (void)out;
    return 0; /* game input-thread id not yet provided by SDK: no attribution fabricated */
}

} } } // namespace hk::sdk::win

#endif /* HK_PLATFORM_WINDOWS || _WIN32 */
