================================================================================
  macOS Anti-Cat Detection: Complete Technical Reference
  EndpointSecurity, Kernel Mechanisms, and Bypass Techniques
  Covers macOS 12 (Monterey) through macOS 15 (Sequoia+)
  Date: 2026-06-09
  Author: Research Document
================================================================================

TABLE OF CONTENTS
------------------
1.  ES Event Type Complete Reference
2.  Code-Signing Attack Surface
3.  Dyld Shared Cache Manipulation
4.  RPC / XPC Injection
5.  task_for_pid Abuse Patterns & TOCTOU
6.  DTrace / kdebug Abuse
7.  IOKit User-Client Attack Surface
8.  Mach VM / Mach Port Manipulation
9.  Objective-C Runtime Manipulation
10. JIT Entitlement Abuse
11. Kauth Scope Monitoring
12. MAC (Mandatory Access Control) Policy
13. EndpointSecurity Performance Tuning
14. Gatekeeper / Notarization Bypass
15. Apple Silicon Specifics

================================================================================
1. ES EVENT TYPE COMPLETE REFERENCE
================================================================================

The EndpointSecurity framework (introduced macOS 10.15, matured 12+) provides
a user-space API for monitoring and authorizing security-relevant system
events. The framework operates via a com.apple.endpointsecurity entitlement
(ES_CLIENT_CONTRACTID).

1.1 AUTH Events (blocking - client must reply)
------------------------------------------------

AUTH_EXEC (ES_EVENT_TYPE_AUTH_EXEC)
  Struct: es_event_exec_t
    es_file_t *target              - the executable being launched
    uint64_t *reserved0             - internal use only
    uint32_t *cookie               - pairs with NOTIFY_EXEC outcome
    uint32_t *dsid                 - DirectoryService Session ID
    es_token_t *build              - source_identity (CDHash, signing info)
    es_token_t *base_determination - cached determination result
    const es_process_t *caller     - process that called exec/fork+exec
    es_fd_t *script_fd             - fd of script body (#! scripts)
    uuid_t *signature              - CMS signature hash
    es_range_t *text_offset_offset - TEXT offset in Mach-O
    bool *is_platform_binary       - Apple-signed binary flag (csflags CS_PLATFORM_BINARY)
    es_token_t *cdhash             - CodeDirectory hash
    const char *executable_path    - resolved path
  Deadline: 60 seconds. If the client doesn't reply in time, the system
  kills the process via SIGKILL in macOS 12+, or Deny-by-Default starting
  in macOS 13.

AUTH_OPEN (ES_EVENT_TYPE_AUTH_OPEN)
  Struct: es_event_open_t
    const es_file_t *file          - file being opened
    int32_t fflag                  - open() flags (O_RDONLY, O_RDWR, O_CREAT, etc.)
    uint32_t reserved[6]           - reserved
  Deadline: 30 seconds

AUTH_MMAP (ES_EVENT_TYPE_AUTH_MMAP)
  Struct: es_event_mmap_t
    int32_t prot                   - protection bits (PROT_READ, PROT_WRITE, PROT_EXEC)
    int32_t flags                  - mmap flags (MAP_PRIVATE, MAP_SHARED, MAP_FIXED, MAP_ANON)
    int64_t file_offset            - offset into the backing file
    uint64_t max_protection        - max protection (as in maxprot)
    const es_file_t *source_file   - the file being mmap'd (NULL for MAP_ANON)
  Note: Also fires for regions passed to mach_vm_map with a file backing

AUTH_RENAME (ES_EVENT_TYPE_AUTH_RENAME)
  Struct: es_event_rename_t
    const es_file_t *source
    es_destination_type_t dest_type (ES_DESTINATION_TYPE_EXISTING_FILE or NEW_FILE)
    union: es_file_t for existing_file

AUTH_UNLINK (ES_EVENT_TYPE_AUTH_UNLINK)
  Struct: es_event_unlink_t
    const es_file_t *target
    uint32_t parent_dir

AUTH_SIGNAL (ES_EVENT_TYPE_AUTH_SIGNAL)
  Struct: es_event_signal_t
    const es_process_t *target     - target process
    int32_t sig                    - signal number

AUTH_MOUNT (ES_EVENT_TYPE_AUTH_MOUNT)
  Struct: es_event_mount_t
    fsid_t fsid
    const es_file_t *mount_point

AUTH_TASK_FOR_PID (ES_EVENT_TYPE_AUTH_TASK_FOR_PID)
  Struct: es_event_task_for_pid_t
    const es_process_t *target     - the process whose task port is requested
    pid_t pid                      - the target PID
  Critical: Only one AUTH reply per lifetime per (caller, target) pair.

AUTH_IOKIT_OPEN (ES_EVENT_TYPE_AUTH_IOKIT_OPEN)
  Struct: es_event_iokit_open_t
    uint32_t user_client_type       - type passed to IOServiceOpen
    uint64_t user_client_class_constant - or variable length string matching

AUTH_MACH_RIGHT (ES_EVENT_TYPE_AUTH_MACH_RIGHT) - macOS 13+
  Struct: es_event_mach_right_t
    const es_process_t *target
    mach_port_name_t right           - port right being manipulated
    uint32_t right_type              - MACH_PORT_TYPE_* constants

AUTH_COPYFILE - macOS 14+
  Struct: es_event_copyfile_t
    const es_file_t *source
    const es_file_t *target_dir
    const es_file_t *target_state

1.2 NOTIFY Events (non-blocking, post-action)
------------------------------------------------

NOTIFY_EXEC (ES_EVENT_TYPE_NOTIFY_EXEC)
  Struct: es_event_exec_t (same as AUTH but read-only post-execution)
  Additional result field (inherited from es_process_t struct):
    uint32_t exit_code              - only populated after process exits
  Fields are cached; snapshot taken at time of event.

NOTIFY_FORK   (ES_EVENT_TYPE_NOTIFY_FORK)
  Struct: es_event_fork_t
    const es_process_t *child       - the new child process

NOTIFY_EXIT   (ES_EVENT_TYPE_NOTIFY_EXIT)
  Struct: es_event_exit_t
    int32_t stat                    - exit status

NOTIFY_CSU_INVALIDATED (ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED) - CS flag only
  Telltale of code-signing bypasses.

NOTIFY_CS_INVALIDATED (ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED)
  Struct: es_event_cs_invalidated_t
    uint64_t pid                    - PID whose CS flags were invalidated
  Fires when kernel invalidates CS cache for a process (e.g., after
  code-signing bypass or when a process is transformed).

NOTIFY_MMAP (ES_EVENT_TYPE_NOTIFY_MMAP)
  Struct: es_event_mmap_t (read-only post-action)

NOTIFY_MPROTECT (ES_EVENT_TYPE_NOTIFY_MPROTECT)
  Struct: es_event_mprotect_t
    void *address
    size_t size
    int32_t prot                    - new protection bits

NOTIFY_SIGNAL (ES_EVENT_TYPE_NOTIFY_SIGNAL)

NOTIFY_RENAME (ES_EVENT_TYPE_NOTIFY_RENAME)

NOTIFY_UNLINK (ES_EVENT_TYPE_NOTIFY_UNLINK)

NOTIFY_OPEN (ES_EVENT_TYPE_NOTIFY_OPEN)

NOTIFY_MACH_MSG (ES_EVENT_TYPE_NOTIFY_MACH_MSG) - macOS 13+
  Struct: es_event_mach_msg_t
    mach_msg_header_t *msg          - the full Mach message header
    const es_process_t *sender
    const es_process_t *receiver
  Critical for detecting RPC injection.

NOTIFY_MACH_RIGHT (ES_EVENT_TYPE_NOTIFY_MACH_RIGHT)

NOTIFY_IPC_MSG (ES_EVENT_TYPE_NOTIFY_IPC_MSG) - macOS 13+
  Struct: es_event_ipc_msg_t       - higher-level than NOTIFY_MACH_MSG

NOTIFY_TRACER
  Fires when a process attempts to ptrace() another process.
  Struct: es_event_tracer_t
    const es_process_t *target
    pid_t target_pid

NOTIFY_REMOTE_THREAD_CREATE - macOS 14+

NOTIFY_PROC_SUSPEND_RESUME - macOS 15+

NOTIFY_GET_TASK - macOS 15+
  Fires on task_read_for_pid and related TFP acquisition.
  Struct: es_event_get_task_t
    const es_process_t *target
    es_get_task_type_t type         - ES_GET_TASK_TYPE_TASK_* enum

1.3 es_process_t Fields (common across events)
------------------------------------------------

typedef struct {
  audit_token_t auditToken;         - (pid, version)
  pid_t pid;                        - process ID
  pid_t ppid;                       - parent process ID
  pid_t original_ppid;              - before reparenting
  pid_t group_pid;                  - process group
  pid_t session_id;                 - session ID
  bool is_es_client;                - is this the ES client itself?
  const char *signing_id;           - signing identifier (teamid.bundleid)
  const char *team_id;              - Apple Developer Team ID
  const cs_blob_t *cs_blob;         - code-signing blob (internal)
  uint32_t cs_flags;                - raw CS_VALID, CS_ADHOC, etc. flags
  bool is_platorm_binary;           - CS_PLATFORM_BINARY set
  bool is_adhoc_signed;             - CS_ADHOC set
  uint8_t cs_signing_id_hash[32];   - SHA-256 of signing identity
  uint8_t cs_team_id_hash[32];      - SHA-256 of team ID
  const cdhash_t cdhash;            - code directory hash
  bool cs_cdhash_trusted;           - trusted by the system
  struct timespec exec_fail_time;   - last exec failure time
  bool exec_done;                   - exec transition complete
  uint64_t executable_path_length;  - (internal)
  const char *executable_path;      - full path to executable
  uint64_t tty_fd;                  - controlling tty
  struct proc_identiier *proc;      - (internal kernel pointer)
  const code_directory *cd;         - code directory data
  es_uthread_t *thread;             - current thread structure (internal)
} es_process_t;


================================================================================
2. CODE-SIGNING ATTACK SURFACE
================================================================================

The kernel stores code-signing flags in the proc_t->p_csflags field.
These flags control what capabilities a process has and whether its
code signature is trusted.

2.1 Core CS Flags (from <sys/codesign.h>)
------------------------------------------

CS_VALID             = 0x00000001  - Code signature is valid
CS_ADHOC             = 0x00000002  - Ad-hoc signed (no CA chain, hash-based)
CS_GET_TASK_ALLOW    = 0x00000004  - Entitled to call task_for_pid()
CS_INSTALLER         = 0x00000008  - Entitled to install packages
CS_INVALID_ALLOWED   = 0x00000010  - Explicit invalidation allowed (debug)
CS_HARD              = 0x00000100  - Don't load invalid pages
CS_KILL              = 0x00000200  - Kill process if invalid
CS_CHECK_EXPIRATION  = 0x00000400  - Check certificate expiration
CS_ENFORCEMENT       = 0x00001000  - Enforce code-signing (disable = allow unsigned)
CS_REQUIRE_LV        = 0x00002000  - Require library validation (library loading)
CS_ENTITLEMENTS_VALIDATED = 0x00004000  - Entitlements blob was validated
CS_RUNTIME           = 0x00010000  - Apply runtime hardening (Apple Silicon)
CS_LINKER_SIGNED     = 0x00020000  - Signed by the dynamic linker
CS_PLATFORM_BINARY   = 0x00400000  - Apple platform binary
CS_PLATFORM_PATH     = 0x00800000  - Platform path (Apple binary in /System)

EXEC_SET variants (written into csflags at exec time, not CS_VALID):
CS_EXEC_SET_HARD        = 0x00100000
CS_EXEC_SET_KILL        = 0x00200000
CS_EXEC_SET_ENFORCEMENT = 0x00400000
CS_EXEC_INHERIT_SIP     = 0x01000000  - Inherit System Integrity Protection status
CS_EXEC_SET_INSTALLER   = 0x02000000

CS_ALLOWED_MACHO        = 0x00020000  - Allowed Mach-O magic numbers mask

2.2 How Cheats Abuse Each Flag
-------------------------------

CS_GET_TASK_ALLOW:
  Cheats ad-hoc sign a binary with a custom entitlement:
    <key>com.apple.security.get-task-allow</key><true/>
  This grants the process task_for_pid() rights to any other process.
  Detection: Watch es_process_t.cs_flags for CS_GET_TASK_ALLOW on
  non-Xcode, non-debugger processes. Cross-reference signing_id against
  known developer tools.

CS_ADHOC + CS_GET_TASK_ALLOW:
  The most common cheat pattern. A binary is ad-hoc signed (no Apple CA
  chain - just a SHA-256 of the code embedded in the binary) with
  CS_GET_TASK_ALLOW. This bypasses distribution signing requirements
  while still gaining TFP access.
  Detection: Auth-exec events where is_adhoc_signed == true &&
  (cs_flags & CS_GET_TASK_ALLOW) && signing_id doesn't match game/editor.

CS_INSTALLER:
  Allows installers to write to SIP-protected paths. Cheats use this
  to install dylibs or kernel extensions.
  Detection AUTH_EXEC with CS_INSTALLER on non-installer apps.

CS_ENFORCEMENT:
  If explicitly *absent* from csflags, the kernel will load unsigned
  pages and unsigned libraries. On SIP-protected systems this normally
  cannot be cleared, but a user-space dylib injection (via
  DYLD_INSERT_LIBRARIES + disable-library-validation) can sometimes
  load signed-but-not-valid *libraries* even on SIP.

CS_REQUIRE_LV (Library Validation):
  Disabling this allows loading libraries without matching the
  executable's code signature. Cheats inject their cheat dylibs by
  triggering this bypass via:
    com.apple.security.cs.disable-library-validation
  Detection: Watch for processes that have this entitlement or have
  loaded libraries that don't match the cdhash.

CS_RUNTIME:
  Runtime hardening on Apple Silicon. Prevents:
    - Writable-and-executable pages in the heap
    - JIT memory without the correct entitlement
    - mmap(MAP_JIT) without allow-jit entitlement
  Cheats need to either:
    (a) Obtain allow-jit entitlement (see Section 10)
    (b) Use MAP_JIT + pthread_jit_write_prot_np_np_np_np_np_np_np_np_np_np_np_np (GC variant)
    (c) Mark pages as RWX via kernel exploit

CS_HARD + CS_KILL:
  These make a process harder to tamper with externally. A cheat might
  want to *remove* these flags via kernel modification, but on Apple
  Silicon with PPL, these kernel structures are protected.

2.3 Detecting CS_ADHOC + CS_GET_TASK_ALLOW Binaries
----------------------------------------------------

In the ES AUTH_EXEC handler:

```c
if (message->process->is_adhoc_signed &&
    (message->process->cs_flags & CS_GET_TASK_ALLOW) &&
    strcmp(message->process->signing_id, "com.valve.Steam") != 0 &&
    strcmp(message->process->signing_id, "com.idsoftware...") != 0) {
    // This is a likely cheat - ad-hoc signed with TFP access
    deny = true;
}
```

Additionally check: if a non-AppStore binary has CS_GET_TASK_ALLOW
without a com.apple.developer.debugger entitlement from Apple, it's
almost certainly a cheat or a vulnerable signed binary being abused.

The approach must be heuristic since legitimate developers do use
CS_GET_TASK_ALLOW during development.


================================================================================
3. DYLD SHARED CACHE MANIPULATION
================================================================================

3.1 Background
---------------

macOS ships most system frameworks in a pre-linked "dyld shared cache"
at /System/Library/dyld/dyld_shared_cache_{x86_64|arm64e|arm64e_v1}.
This is mmap'd into every process at boot. Cheats patch this region
in *their own process* to redirect system function calls (hooking),
or more dangerously, attempt to patch the cache in the target
game process to alter game behavior.

3.2 Address Ranges
-------------------

x86_64 (Intel macOS):
  dyld_shared_cache base: 0x7FFF_0000_0000 (approximate, ASLR slide varies)
  The cache occupies a contiguous region of ~1.4-1.8 GB.
  To find the exact range at runtime:
    _dyld_get_shared_cache_range(&size) - for your own process.
    For another: parse their vmmap output or Mach VM region iteration.

arm64e (Apple Silicon):
  dyld_shared_cache base: 0x0000_0002_0000_0000 or 0x0000_0000_2000_0000
  (depends on ASLR slide; typically near the top of the 48-bit address
  space in the shared cache segment). The exact slide is randomized
  per boot.

  Use mach_vm_region_recurse() on the remote task or examine
  the dyld_all_image_infos in the target process.

3.3 Detection via ES Events
----------------------------

Shared cache mmap events look like any other mmap - you can identify
them by:

1. PATH MATCHING: source_file->path contains
   "/dyld_shared_cache_" - but the shared cache is usually mapped by
   dyld itself, not your ES client (the client subscribes *after*
   the cache is already mapped). You *won't* see it via AUTH_MMAP
   for new processes.

2. PROTECTION CHANGE (mprotect):
   When a cheat patches the dyld shared cache in the game process, it
   must call mprotect() to make the region writable first, then
   patch it, then restore protections. Watch for:

   AUTH_MPROTECT event where:
     address falls within shared cache range
     && (prot & PROT_WRITE)

   This is ALWAYS suspicious - the shared cache should be RX at most.
   Even patterns like: RX → RWX → RX (typical hook pattern) are visible.

3. mmap of the shared cache file with MAP_PRIVATE:
   Normally dyld maps it MAP_SHARED. If a process opens the cache
   with MAP_PRIVATE and modifies the local copy, this is a strong
   indicator of hooking.

3.4 Detection Algorithm
------------------------

```c
// In AUTH_MPROTECT handler:
uint64_t cache_base = get_dyld_shared_cache_base(); // via _dyld or remote inspection
size_t cache_size;

_dyld_get_shared_cache_range(&cache_size);

bool in_cache_range = ((uintptr_t)event->address >= cache_base &&
                       (uintptr_t)event->address < cache_base + cache_size);

if (in_cache_range && (event->prot & PROT_WRITE)) {
    // Shared cache should never be writable in any process
    // This indicates either kernel-level patching or dyld_hook.
    es_respond_auth_result(result, false);  // DENY
    log_suspicious(event->process, "mprotect writes to dyld shared cache");
}
```

3.5 Bypass Techniques Used by Cheats
-------------------------------------

- Patch pages via mach vm write directly (MAP-JIT'd region)
  bypassing mprotect monitoring. This requires TFP first (circular
  dependency: need TFP to patch, but patch to bypass TFP auth).
  On Apple Silicon, PAC provides protection: function pointers
  in the cache have PAC authentication bits, so blindly redirecting
  them crashes the target.

- Use VM Mapping (mach_vm_remap) to create a COW copy of the shared
  cache region with writable permissions without mprotect.
  ES AUTH_MMAP would fire here with MAP_PRIVATE | PROT_WRITE.

================================================================================
4. RPC / XPC INJECTION
================================================================================

4.1 Background
---------------

Many macOS games are sandboxed via XPC services or distributed
as XPC-based apps. The bootstrap port (bootstrap_port) is the
primary inter-process communication mechanism for Mach-based IPC,
including XPC. Cheats inject code or send malicious messages
through this channel.

4.2 ES Coverage
----------------

AUTH_MACH_MSG (macOS 13+):
  Fires on all Mach message sends. The es_event_mach_msg_t contains
  the full mach_msg_header_t. You can inspect:
    msgh_id - message ID (XPC typically uses high IDs)
    msgh_size - total message size
    msgh_remote_port - target port
    msgh_local_port - reply port

  Detection of suspicious injection:
    If msgh_remote_port resolves to a port belonging to the game,
    AND the sender is not an Apple/XPC service or known trusted daemon,
    flag it as suspicious.

NOTIFY_IPC_MSG (macOS 13+):
  Higher-level parsing of IPC messages. Filters on the receiver path
  and sender pid.

AUTH_MACH_RIGHT (macOS 13+):
  Fires when a process requests, copies, or inserts Mach port rights.
  Key for detecting TFP-equivalent attacks where a cheat obtains
  a task port via port-right delegation.

4.3 Detecting XPC Injection
-----------------------------

The typical injection flow:
  1. Attacker looks up the game's bootstrap service via bootstrap_look_up()
  2. Attacker sends a Mach message with crafted MSGH_ID to the game's service
  3. If the game's XPC listener is vulnerable, it processes the message

ES detection:
  AUTH_MACH_MSG fires at step 2. You can programmatically inspect:
    if (event->msg->msgh_id >= 0x1000 &&        // non-standard ID range
        event->msg->msgh_bits & MACH_MSGH_BITS_COMPLEX &&
        event->sender->pid != getppid_of_game() &&
        is_game_port(event->msg->msgh_remote_port)) {
        // Suspicious Mach message to game
    }

4.4 Detecting MACH_MSG_TYPE_COPY_SEND Abuse
--------------------------------------------

A common cheat pattern: a daemonic proxy obtains task_for_pid(),
copies the send right to the bootstrap port, then the cheat sends
messages through the proxy's port:

  mach_port_t game_task;
  task_for_pid(mach_task_self(), game_pid, &game_task);  // AUTH_TASK_FOR_PID fires
  mach_port_t bootstrap;
  task_get_special_port(game_task, ..., &bootstrap);
  // Delegate this bootstrap to a cheater process via mach_msg COPY_SEND

Detection via AUTH_MACH_RIGHT:
  When the bridge process inserts a send right into another process's
  namespace, AUTH_MACH_RIGHT fires. If the right type is
  MACH_PORT_TYPE_COPY_SEND and the target is the game, flag it.

4.5 Specific XPC Attack: bootstrap_look_up + _xpc_connection_create
--------------------------------------------------------------------

Some cheats register a fake boot-strap service to intercept
messages intended for the game:

  bootstrap_check_in(bootstrap_port, "com.game.service", &service_port); // RACES

ES detection: you cannot directly intercept bootstrap_look_up
or bootstrap_check_in in ES (these are not AUTH events). You must:
  Option A: Monitor lookups via Kauth (see Section 11)
  Option B: Watch the /var/run/bootstrap* files (legacy)
  Option C: Use a kernel extension (deprecated, not available on Apple Silicon)


================================================================================
5. TASK_FOR_PID ABUSE PATTERNS & TOCTOU
================================================================================

5.1 The task_for_pid Fundamental Problem
------------------------------------------

task_for_pid(mach_task_self(), pid, &task_port*) is the gateway to
arbitrary memory read/write in another process. It returns a
send right to the target's task port. Once held, the calling process
can:
  - mach_vm_read/mach_vm_write - arbitrary memory R/W (read-only for other procs w/o TFP)
  - mach_vm_allocate/mach_vm_map - allocate/map memory in the target
  - thread_create/terminate - create/terminate threads

5.2 ES AUTH_TASK_FOR_PID
-------------------------

The AUTH event fires *before* the TFP call returns to the caller.
The client must reply with:
  es_respond_auth_result(result, true/false)  - allow or deny

Critical property: Once TFP is authorized, the task port is returned
to the caller and can be used immediately. The AUTH event is
fire-and-forget for *subsequent* TFP calls: ES only fires AUTH_TASK_FOR_PID
*once* per (caller, target) pair. After authorization, all future
TFP calls for that pair succeed without ES involvement.

This is the foundation of the TOCTOU attack.

5.3 TOCTOU (Time-of-check-time-of-use) Attack Patterns
------------------------------------------------------

Attack 1: Stale Authorization
  T0: Attacker process has been AUTHORIZED for task_for_pid(game_pid)
      (e.g., because it's the game's legitimate helper or parent)
  T1: ES client approves AUTH_TASK_FOR_PID
  T2: Game modifies its own security posture (loads new code, patches)
  T3: Attacker uses the STALE task_port to modify the now-updated game
  T4: ES has no visibility - TFP was already fully authorized

Mitigation: ES cannot prevent this. Anti-cheat must:
  - Reset TFP authorization after each use (impossible in userspace)
  - Monitor NOTIFY_MMAP, NOTIFY_MPROTECT on the game for changes
  - Revoke the port via mach_port_deallocate() - only works on your own task

Attack 2: task_read_for_pid (macOS 15+)
  macOS 15 introduces task_read_for_pid() which returns a task_read_t
  task-inspection-only right. This cannot write memory but CAN read it.
  The new NOTIFY_GET_TASK fires on task_read_for_pid.
  ES_AUTH_TASK_FOR_PID does NOT fire for task_read_for_pid - only for
  the full task_for_pid write-access call.

Mitigation: Subscribe to NOTIFY_GET_TASK (macOS 15+) to detect
read-only task access.

Attack 3: task_inspect_for_pid (sometimes available with entitlements)
  Returns a task_inspect_t right. Can read thread state, read memory
  (similar to task_read_t in practice). Also fires NOTIFY_GET_TASK.

Attack 4: Bootstrap-based TFP Delegation
  The bootstrap port (or any Mach port) can be delegated to
  attacker tasks. The attacker gains TFP-equivalent access
  without calling task_for_pid() at all:

    // Victim holds task_port
    mach_msg_send_to_attacker(victim_task_port); // Auth_Mach_right fires here
    // Attacker now has full task access via mach_vm_read/write

ES detection for this: AUTH_MACH_RIGHT where right_type includes
MACH_PORT_TYPE_SEND and the associated Mach port resolves to a
task port (MACH_PORT_TYPE_TASK - requires kernel inspection).

5.4 Mitigation: Port-Right Revocation
--------------------------------------

The anti-cheat daemon can proactively revoke access:
  1. AUTH_TASK_FOR_PID fires - daemon records (caller_pid, target_pid)
  2. Before replying, daemon suspends the target thread in the
     ES_AUTH handler? No - cannot do that in ES handler (deadline).
  3. After allowing, perform in the daemon body:
     - Mach message inspection on the target task port
     - Periodic re-verification of game code integrity

Better approach on macOS 15+:
  Use NOTIFY_GET_TASK to track all task acquisitions. Combine
  with AUTH_MACH_RIGHT for port forwarding. Cross-reference and
  build a graph of who-has-task-access-to-whom.


================================================================================
6. DTRACE / KDEBUG ABUSE
================================================================================

6.1 Background
----------------

DTrace is a dynamic tracing framework that can instrument any kernel
function or user-space probe. Cheats abuse it to:
  - Trace game function calls (to find patterns or memory layout)
  - Instrument system calls made by the game
  - Modify kernel state via destructive DTrace scripts

6.2 ES Detection of DTrace Attachment
---------------------------------------

DTrace user-space requires an implicit ES AUTH. However, ES does NOT
have a separate AUTH_DTRACE event. Detection methods:

Method 1: Monitor /dev/dtracehelper
  Cheats that attach DTrace via syscall interception or via the
  dtracehelper device can be detected by:

    AUTH_OPEN on path "/dev/dtracehelper"
  If a non-Apple-signed, non-developer-tools process opens
  /dev/dtracehelper → highly suspicious.

Method 2: Detect ptrace PT_ATTACHEXC
  DTrace uses a specialized ptrace() for probe attachment. ES
  NOTIFY_TRACER fires on ptrace_attach. If the target is your game,
  and sig/type context matches DTrace probe attachment patterns:
    PT_ATTACHEXC - exclusive access ptrace.

6.3 ES Events for kdebug / kprobe (NOT AVAILABLE)
---------------------------------------------------

kdebug and kprobe are not visible in ES. Neither AUTH nor NOTIFY
events fire for these. This requires:

  Kauth package hooks (legacy, see Section 11) - KAUTH_FILEOP_EXEC
  - but this wouldn't catch kdebug which operates below the VFS level.

  MAC policy hooks (see Section 12) - mpo_proc_check_debug,
  mpo_proc_check_fork - can hook into task-level operations.

  Kernel hooking via an actual kext (NOT SUPPORTED on Apple Silicon,
  except for USB/network drivers with special approval).

6.4 Bypass Techniques
---------------------

Cheats can:
  - Use kdebug_signpost (safe, tracing-only, requires entitlement)
    This does NOT fire any ES event - it's a user-space API.
  - Use os_signpost (replacement for kdebug_signpost) - also invisible
  - Use DTrace via a kernel extension (kext) - not possible on Apple
    Silicon without a kernel exploit
  - Use eBPF (not yet available on macOS as of 15.x)


================================================================================
7. IOKIT USER-CLIENT ATTACK SURFACE
================================================================================

7.1 Background
----------------

IOKit is the macOS device driver framework. User-space processes
communicate with kernel drivers via IOUserClient subclasses.
Cheats use IOKit to:
  - Read/write physical memory (DMA attacks)
  - Access GPU framebuffers (screen capture / overlay)
  - Load kernel extensions (kexts)
  - Access hardware debug interfaces

7.2 ES AUTH_IOKIT_OPEN
-----------------------

Fires when a process calls IOServiceOpen() to open a connection
to an IOKit service. The event struct:

  es_event_iokit_open_t:
    uint32_t user_client_type - the type argument to IOServiceOpen
    uint64_t user_client_class_constant - or variable length string

The user_client_class_constant is the IOUserClient subclass name
(e.g., "AppleSMC", "IOFramebufferSharedUserClient", "IOHIDSystem").

7.3 Dangerous IOUserClient Classes
-----------------------------------

AppleSMC:
  Read/write SMC (System Management Controller) keys. Can modify
  fan speeds, thermal throttling, and potentially other hardware
  settings. Cheats use this to disable thermal throttling for
  higher performance.

IOFramebufferSharedUserClient:
  Direct access to the GPU framebuffer. Cheats use this for:
    - Screen capture (reading the framebuffer)
    - Overlay injection (writing to the framebuffer)
    - DMA-style memory access

IOHIDSystem:
  Human Interface Device system. Can inject keyboard/mouse events.
  Cheats use this for aimbots (synthetic mouse input).

IOAccelerator:
  GPU compute access. Can be used for GPU-based memory scanning.

7.4 Detection Strategy
-----------------------

```c
// In AUTH_IOKIT_OPEN handler:
const char *class_name = event->user_client_class_constant;

if (strcmp(class_name, "IOFramebufferSharedUserClient") == 0 ||
    strcmp(class_name, "AppleSMC") == 0 ||
    strcmp(class_name, "IOAccelerator") == 0) {

    // Check if the caller is a known trusted process
    if (!is_trusted_caller(event->process)) {
        // Deny or flag for investigation
        log_suspicious(event->process, "IOKit open: %s", class_name);
    }
}
```

7.5 IOConnectCallMethod / IOConnectCallAsyncMethod
----------------------------------------------------

These are the actual method invocation APIs. ES does NOT have
AUTH events for individual IOConnectCallMethod invocations - only
AUTH_IOKIT_OPEN fires (at connection open time). Once the connection
is open, the cheat can call any method on the user client.

Mitigation: Deny AUTH_IOKIT_OPEN for dangerous classes entirely,
or monitor the process for suspicious behavior after the open.

7.6 IOConnectMapMemory
-----------------------

Maps device memory into the caller's address space. This is the
primary DMA attack vector:

  IOConnectMapMemory(connection, type, mach_task_self(),
                     &address, &size, kIOMapAnywhere);

After mapping, the cheat can read/write physical memory directly.
This is how some cheats read game memory without task_for_pid().

Detection: AUTH_IOKIT_OPEN + subsequent AUTH_MMAP events where
the source_file is an IOKit device (path starts with /dev/ or
is a kernel memory descriptor).

7.7 Bypass Techniques
----------------------

- Use a signed kext that exposes a benign IOUserClient, then
  exploit the kext to gain kernel R/W. (Not possible on Apple
  Silicon without a kernel exploit.)

- Use a vulnerable signed driver (e.g., an old third-party
  driver with a known vulnerability) to gain kernel access,
  then use that to bypass ES entirely.

- Use IOHIDSystem to inject input events - this is hard to
  distinguish from legitimate input injection (e.g., from
  accessibility tools).


================================================================================
8. MACH VM / MACH PORT MANIPULATION
================================================================================

8.1 Background
----------------

Mach VM APIs (mach_vm_map, mach_vm_protect, mach_vm_write,
mach_vm_read) are the kernel-level equivalents of mmap/mprotect.
They operate on the Mach task's virtual address space directly.

8.2 ES Coverage of Mach VM Operations
---------------------------------------

ES AUTH_MMAP fires for:
  - mmap() → yes
  - mach_vm_map() → YES (the kernel translates mach_vm_map into
    the same internal path as mmap for ES purposes)

ES AUTH_MPROTECT fires for:
  - mprotect() → yes
  - mach_vm_protect() → YES

ES does NOT have AUTH events for:
  - mach_vm_write() - no AUTH event (only NOTIFY_MMAP for the
    underlying mapping)
  - mach_vm_read() - no AUTH event
  - mach_vm_allocate() - no AUTH event (but AUTH_MMAP may fire
    if the allocation is file-backed)

8.3 mach_vm_write Detection
----------------------------

Since there's no AUTH event for mach_vm_write, detection requires:
  - NOTIFY_MMAP: If the target region was recently mmap'd with
    PROT_WRITE, and the process has TFP access to the game, flag it.
  - NOTIFY_MPROTECT: If a region's protection changes to RWX,
    it may indicate code injection.
  - Periodic memory integrity checks from the daemon (read the
    game's memory via task_read_for_pid on macOS 15+).

8.4 mach_port_insert_right Abuse
---------------------------------

mach_port_insert_right() inserts a send or send-once right into
another task's port namespace. This is how task ports are delegated:

  mach_port_t task_port;
  task_for_pid(mach_task_self(), game_pid, &task_port);
  mach_port_insert_right(attacker_task, port_name,
                         task_port, MACH_MSG_TYPE_COPY_SEND);

ES AUTH_MACH_RIGHT fires on this. Detection:
  - Track all AUTH_MACH_RIGHT events
  - If the right_type is MACH_MSG_TYPE_COPY_SEND and the port
    resolves to a task port (requires kernel-level inspection),
    flag it as TFP delegation.

8.5 mach_port_extract_right
----------------------------

The reverse - extracting a port right from another task. Also
fires AUTH_MACH_RIGHT. Less common in cheat scenarios but
relevant for anti-cheat self-protection.

8.6 Mach Port Name Spoofing
----------------------------

Cheats can create Mach ports with names that mimic system ports
to confuse detection. The port name itself is just an integer;
the kernel resolves it to the actual port structure. ES events
contain the resolved port, not the spoofed name, so this is
not a practical bypass for ES-based detection.


================================================================================
9. OBJECTIVE-C RUNTIME MANIPULATION
================================================================================

9.1 Background
----------------

Many macOS games use Objective-C (or Swift, which uses ObjC runtime
internals). Method swizzling - replacing an ObjC method's IMP
(implementation function pointer) - is a common cheat technique.

9.2 Method Swizzling Detection
--------------------------------

ES does NOT have events for ObjC runtime manipulation. Detection
must be done from the anti-cheat daemon:

1. Acquire task_read_for_pid (macOS 15+) or task_for_pid for the game
2. Read the game's __DATA,__objc_classlist section
3. For each class, read the method list (struct objc_method_list)
4. Compare each method's IMP against the expected address
   (from the original binary or from the dyld shared cache)
5. If any IMP points outside the expected range → swizzle detected

The objc runtime structures (from <objc/runtime.h>):

  struct objc_class {
      Class isa;
      Class superclass;
      const char *name;
      long version;
      long info;
      long instance_size;
      struct objc_ivar_list *ivars;
      struct objc_method_list **methodLists;  // ← swizzle target
      struct objc_cache *cache;
      struct objc_protocol_list *protocols;
  };

  struct objc_method {
      SEL method_name;
      char *method_types;
      IMP method_imp;  // ← this is what gets replaced
  };

9.3 Swift Method Swizzling
----------------------------

Swift uses method tables (vtable-style) rather than ObjC-style
method lists. Detection requires:
  - Reading the Swift type metadata from __TEXT,__swift5_types
  - Comparing method pointers against the original binary
  - Swift method pointers also have PAC on Apple Silicon, making
    them harder to forge (see Section 15)

9.4 C++ vtable Hooking
-----------------------

C++ virtual method tables are another target. Detection:
  - Read the game's __DATA,__const section for vtable structures
  - Compare function pointers against the original binary
  - On Apple Silicon, vtable pointers are PAC-signed

9.5 Detection Frequency
------------------------

Full ObjC runtime scanning is expensive. Recommended approach:
  - Scan at game launch (baseline)
  - Periodic scans every 30-60 seconds
  - Event-triggered scans after AUTH_MMAP/AUTH_MPROTECT events
    that affect the game's TEXT segment


================================================================================
10. JIT ENTITLEMENT ABUSE
================================================================================

10.1 Relevant Entitlements
----------------------------

com.apple.security.cs.allow-jit
  Allows the process to use MAP_JIT and mprotect with PROT_EXEC
  on JIT-allocated pages. Required for JavaScript engines, emulators,
  and - unfortunately - cheats that generate code at runtime.

com.apple.security.cs.allow-unsigned-executable-memory
  Allows the process to create executable memory without a code
  signature. This is the most dangerous entitlement for anti-cheat.
  Cheats use this to allocate RWX memory and inject shellcode.

com.apple.security.cs.disable-library-validation
  Allows loading libraries that don't match the executable's code
  signature. Cheats use this to inject their dylibs into the game.

com.apple.security.cs.debugger
  Allows the process to use ptrace() and task_for_pid(). This is
  the entitlement that grants TFP access.

com.apple.security.cs.allow-environment-variables
  Allows DYLD_INSERT_LIBRARIES and other DYLD environment variables
  to be honored. Cheats use this for dylib injection.

10.2 How Cheats Abuse These
-----------------------------

Attack 1: Ad-hoc sign with allow-unsigned-executable-memory
  The cheat binary is ad-hoc signed with:
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key><true/>
  This allows the cheat to allocate RWX memory and execute shellcode
  without any code signature. Combined with task_for_pid (obtained
  via CS_GET_TASK_ALLOW or debugger entitlement), the cheat can
  inject shellcode into the game.

Attack 2: DYLD_INSERT_LIBRARIES + disable-library-validation
  If the game has disable-library-validation (common for games
  that load third-party plugins), a cheat can:
    DYLD_INSERT_LIBRARIES=/path/to/cheat.dylib /path/to/game
  The game loads the cheat dylib at launch. ES AUTH_EXEC fires
  for the game, but the dylib is loaded by dyld, not by exec.

  Detection: After AUTH_EXEC for the game, scan the game's loaded
  dylibs (via task_read_for_pid + _dyld_get_image_name) and check
  for unexpected libraries.

Attack 3: allow-jit for runtime code generation
  Cheats use MAP_JIT to allocate memory, write shellcode, then
  execute it. On Apple Silicon, MAP_JIT pages are automatically
  toggled between RW and RX via pthread_jit_write_protect_np().

10.3 Detection Strategy
-------------------------

In AUTH_EXEC handler:
  1. Read the process's entitlements from the cs_blob
     (es_process_t has cs_blob pointer - internal, but accessible
     via the csops() syscall from the daemon)
  2. Check for the dangerous entitlements listed above
  3. If found, and the process is not the game or a known tool,
     deny or flag

```c
// Check entitlements via csops
uint8_t csblob[8192];
struct cs_blob_entitlement_query eq = {0};
csops(pid, CS_OPS_ENTITLEMENTS_BLOB, csblob, sizeof(csblob));
// Parse the entitlements XML plist from csblob
```

10.4 Entitlement Forgery
-------------------------

Cheats cannot forge entitlements on Apple Silicon because:
  - Entitlements are part of the code signature
  - Code signature is verified by the kernel before exec
  - PPL protects the kernel's code-signing data structures

On Intel Macs with SIP disabled, cheats can modify the kernel's
entitlement checking logic via a kernel exploit.


================================================================================
11. KAUTH SCOPE MONITORING
================================================================================

11.1 Background
----------------

Kauth (Kernel Authorization) is a legacy kernel hooking mechanism
that predates ES. It allows a kernel extension (kext) to register
callbacks for various scopes. While Apple is deprecating kexts,
Kauth is still relevant for:
  - Monitoring file operations that ES doesn't cover
  - Legacy macOS versions (pre-10.15)
  - Operations that ES AUTH events don't intercept

11.2 Kauth Scopes
-------------------

KAUTH_SCOPE_VNODE:
  Intercepts VFS operations on vnodes (files). Callbacks fire for:
    KAUTH_VNODE_READ_DATA
    KAUTH_VNODE_WRITE_DATA
    KAUTH_VNODE_EXECUTE
    KAUTH_VNODE_DELETE
    KAUTH_VNODE_APPEND_DATA
    KAUTH_VNODE_READ_ATTRIBUTES
    KAUTH_VNODE_WRITE_ATTRIBUTES
    KAUTH_VNODE_READ_SECURITY
    KAUTH_VNODE_WRITE_SECURITY
    ... (see <sys/kauth.h> for full list)

  Callback signature:
    int vnode_scope_callback(kauth_cred_t credential,
                              void *idata,
                              kauth_action_t action,
                              uintptr_t arg0,  // vnode
                              uintptr_t arg1,  // parent vnode
                              uintptr_t arg2,  // vfs context
                              uintptr_t arg3); // (unused)

KAUTH_SCOPE_FILEOP:
  Intercepts file-level operations (open, close, rename, etc.)
  at a higher level than VNODE. Callbacks fire for:
    KAUTH_FILEOP_OPEN
    KAUTH_FILEOP_CLOSE
    KAUTH_FILEOP_RENAME
    KAUTH_FILEOP_EXCHANGE
    KAUTH_FILEOP_LINK
    KAUTH_FILEOP_EXEC  - fires on exec(), useful for monitoring

KAUTH_SCOPE_GENERIC:
  Generic kernel authorization checks.

KAUTH_SCOPE_PROCESS:
  Process-level operations (fork, exec, signal).

11.3 Why ES Replaced Kauth
----------------------------

ES is superior to Kauth for most use cases because:
  - ES runs in userspace (no kernel panic risk)
  - ES has structured event data (no raw kernel pointers)
  - ES has AUTH (blocking) capability
  - ES is supported on Apple Silicon (kexts are not)

11.4 When Kauth Is Still Needed
---------------------------------

- Monitoring file xattr changes (ES AUTH_OPEN doesn't cover xattr)
- Monitoring file operations on files that ES doesn't cover
  (e.g., operations inside a container sandbox)
- Monitoring operations that happen before ES is initialized
  (early boot)
- Legacy macOS support (pre-10.15)

11.5 Kauth Registration (Legacy)
---------------------------------

```c
#include <sys/kauth.h>

static kauth_listener_t vnode_listener;

int vnode_scope_callback(kauth_cred_t cred, void *idata,
                          kauth_action_t action,
                          uintptr_t arg0, uintptr_t arg1,
                          uintptr_t arg2, uintptr_t arg3) {
    vnode_t vp = (vnode_t)arg0;
    // Inspect the vnode, action, etc.
    return KAUTH_RESULT_DEFER;  // or ALLOW/DENY
}

// Register:
vnode_listener = kauth_listen_scope(KAUTH_SCOPE_VNODE,
                                     vnode_scope_callback, NULL);

// Unregister:
kauth_unlisten_scope(vnode_listener);
```

Note: This requires a kernel extension, which is NOT SUPPORTED
on Apple Silicon (except for specific driver types).


================================================================================
12. MAC (MANDATORY ACCESS CONTROL) POLICY
================================================================================

12.1 Background
----------------

MAC (Mandatory Access Control) is a kernel-level security framework
that allows registering policy modules. Each policy module provides
a set of hooks (mpo_* functions) that the kernel calls at various
decision points. This is the most powerful - and most dangerous -
anti-cheat mechanism.

12.2 mac_policy_ops Structure
------------------------------

The mac_policy_ops structure (from <security/mac_policy.h>) contains
hundreds of function pointers. Key hooks for anti-cheat:

Process hooks:
  mpo_proc_check_debug          - ptrace() authorization
  mpo_proc_check_fork           - fork() authorization
  mpo_proc_check_get_task       - task_for_pid() authorization
  mpo_proc_check_get_task_name  - task name access
  mpo_proc_check_task_for_pid   - TFP authorization (legacy)
  mpo_proc_check_run_cs_invalid - code-signing invalidation

File hooks:
  mpo_vnode_check_create        - file creation
  mpo_vnode_check_unlink        - file deletion
  mpo_vnode_check_write         - file write
  mpo_vnode_check_exec          - exec authorization
  mpo_vnode_check_rename        - rename authorization

Network hooks:
  mpo_socket_check_bind         - socket bind
  mpo_socket_check_connect      - socket connect
  mpo_socket_check_listen       - socket listen

Mach IPC hooks:
  mpo_port_labeling             - Mach port labeling
  mpo_port_check_copy_send      - Mach message send
  mpo_port_check_move_send      - Mach message send-once

12.3 MAC Policy Registration
-----------------------------

```c
#include <security/mac_policy.h>

static struct mac_policy_ops mpo = {
    .mpo_proc_check_debug = anti_cheat_ptrace_check,
    .mpo_proc_check_get_task = anti_cheat_tfp_check,
    .mpo_vnode_check_exec = anti_cheat_exec_check,
    // ... other hooks
};

static struct mac_policy_conf mpc = {
    .mpc_name = "com.anticheat.policy",
    .mpc_fullname = "Anti-Cheat MAC Policy",
    .mpc_labelname = NULL,
    .mpc_labelnames = NULL,
    .mpc_ops = &mpo,
    .mpc_loadtime_flags = 0,
    .mpc_field_off = NULL,
    .mpc_runtime_flags = 0,
};

// Register:
mac_policy_register(&mpc, &policy_handle, NULL);

// Unregister:
mac_policy_unregister(policy_handle);
```

12.4 mac_policy_list and mac_policy_mtx
-----------------------------------------

The kernel maintains:
  struct mac_policy_list - a list of all registered policies
  struct mac_policy_mtx   - a mutex protecting the list

Policies are evaluated in order. The first policy that returns
EACCES (deny) wins. If all policies return 0 (allow), the
operation proceeds.

12.5 Why Apple Is Deprecating MAC Policies
--------------------------------------------

- MAC policies require kernel extensions (kexts)
- Kexts are not supported on Apple Silicon (except for specific types)
- Kexts can cause kernel panics
- ES provides a safer userspace alternative for most use cases

Replacement: ES + System Extensions + Network Extension.
For anti-cheat specifically, ES AUTH events + NOTIFY events
cover most of what MAC policies were used for.

12.6 When MAC Policies Are Still Needed
-----------------------------------------

- Operations that ES doesn't cover (e.g., raw socket access,
  kernel-level process monitoring)
- Operations that need to happen before ES is initialized
- Operations that need to be enforced at the kernel level
  (not just monitored)

Note: On Apple Silicon, MAC policies are essentially unavailable
for anti-cheat purposes. The entire anti-cheat architecture must
be ES-based.


================================================================================
13. ENDPOINTSECURITY PERFORMANCE TUNING
================================================================================

13.1 AUTH Reply Deadlines
---------------------------

ES AUTH events have strict deadlines. If the client doesn't reply
in time, the system takes action:

AUTH_EXEC: 60 seconds
  If no reply: SIGKILL the process (macOS 12+)
  Starting macOS 13: Deny-by-Default for new AUTH events
  (existing clients grandfathered)

AUTH_OPEN: 30 seconds
AUTH_MMAP: 30 seconds
AUTH_TASK_FOR_PID: 30 seconds
AUTH_IOKIT_OPEN: 30 seconds
AUTH_MACH_RIGHT: 30 seconds (macOS 13+)
AUTH_COPYFILE: 30 seconds (macOS 14+)

13.2 Reply Functions
---------------------

es_respond_auth_result(result, bool allow)
  For AUTH_EXEC, AUTH_OPEN, AUTH_MMAP, AUTH_TASK_FOR_PID, etc.
  'result' is the es_event_*_t pointer from the message.
  'allow' is true to allow, false to deny.

es_respond_flags_result(result, uint32_t flags)
  For AUTH_OPEN with flags (e.g., allow open but strip O_WRONLY).

es_respond_file_modification(result, bool allow)
  For AUTH_RENAME, AUTH_UNLINK, AUTH_COPYFILE.

13.3 Batching Replies
----------------------

ES supports batching: you can defer replies and send them all at once.
This is critical for performance:

```c
// Process events in batches
es_message_t *batch[MAX_BATCH];
int batch_count = 0;

void handle_event(es_message_t *msg) {
    if (msg->action_type == ES_ACTION_TYPE_AUTH) {
        batch[batch_count++] = msg;
        if (batch_count >= MAX_BATCH) {
            flush_batch(batch, batch_count);
            batch_count = 0;
        }
    }
}

void flush_batch(es_message_t **msgs, int count) {
    for (int i = 0; i < count; i++) {
        es_respond_auth_result(msgs[i], true);  // or false
    }
}
```

13.4 es_message_t Lifetime
----------------------------

es_message_t is reference-counted. You MUST call:
  es_release_message(msg) - when done with the message
  es_retain_message(msg) - if you need to keep it beyond the handler

Failure to release causes memory leaks in the kernel ES queue.

13.5 Memory Pressure from ES Event Queues
-------------------------------------------

The kernel maintains a per-client event queue. If the client
doesn't process events fast enough, the queue fills up and:
  - New events are dropped (NOTIFY events)
  - AUTH events trigger Deny-by-Default (macOS 13+)
  - The client is disconnected by the kernel

Queue size: ~10,000 events (varies by macOS version).
To monitor: es_get_client_state() returns queue utilization.

13.6 Performance Best Practices
---------------------------------

1. Process events on a dedicated high-priority thread
2. Use a ring buffer for event queuing
3. Batch AUTH replies (see above)
4. Minimize work in the event handler - defer to worker threads
5. Use es_copy_message() to snapshot events for later analysis
6. Subscribe only to events you need (reduces queue pressure)
7. Use es_clear_cache() to clear stale cached results
8. Set QOS_CLASS_USER_INTERACTIVE for the ES processing thread

13.7 es_new_client Setup
-------------------------

```c
es_client_t *client;
es_new_client_result_t result = es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
    // Event handler - keep this FAST
    switch (msg->event_type) {
        case ES_EVENT_TYPE_AUTH_EXEC:
            handle_auth_exec(msg);
            break;
        // ...
    }
});

if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
    // Handle error: ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED,
    //              ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED,
    //              ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED,
    //              ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS
}
```

13.8 es_subscribe / es_unsubscribe
-----------------------------------

Subscribe to specific events:
  es_subscribe(client, event_types[], event_count);

Unsubscribe:
  es_unsubscribe(client, event_types[], event_count);

Unsubscribe all:
  es_unsubscribe_all(client);

Important: You must subscribe AFTER es_new_client. The initial
subscription set is empty.

13.9 es_mute_process / es_mute_path
-------------------------------------

Mute specific processes or paths to reduce noise:
  es_mute_process(client, &audit_token);
  es_mute_path(client, "/path/to/noisy/file", ES_MUTE_PATH_TYPE_LITERAL);

This is critical for performance - muting the game's own
frequent file operations prevents queue saturation.


================================================================================
14. GATEKEEPER / NOTARIZATION BYPASS
================================================================================

14.1 Background
----------------

Gatekeeper is macOS's application verification system. It checks:
  - Code signature validity
  - Notarization status (Apple's automated malware scan)
  - Quarantine flag (com.apple.quarantine extended attribute)

14.2 Bypass Techniques
-----------------------

Technique 1: Remove com.apple.quarantine xattr
  xattr -d com.apple.quarantine /path/to/app
  This removes the quarantine flag, bypassing Gatekeeper's
  "unidentified developer" prompt.

  ES detection: AUTH_OPEN on the app's executable + check for
  xattr operations. ES does NOT have AUTH events for xattr
  operations - this requires Kauth or MAC policy.

Technique 2: spctl --master-disable
  sudo spctl --master-disable
  Disables Gatekeeper entirely. Requires root.

  ES detection: AUTH_EXEC on /usr/sbin/spctl with args
  containing "--master-disable".

Technique 3: Modify /var/db/SystemPolicy-prefs.plist
  Writing to this plist can change Gatekeeper settings.
  Requires root or SIP bypass.

  ES detection: AUTH_OPEN with O_WRONLY on this path.

Technique 4: Ad-hoc signing
  codesign -s - /path/to/binary
  Ad-hoc signs the binary, bypassing notarization requirements.
  The binary still shows "unidentified developer" but can be
  launched with a right-click → Open.

  ES detection: AUTH_EXEC where is_adhoc_signed == true.

Technique 5: Dylib injection via DYLD_INSERT_LIBRARIES
  If the target binary has com.apple.security.cs.allow-environment-variables,
  DYLD_INSERT_LIBRARIES is honored even with Gatekeeper enabled.

  ES detection: AUTH_EXEC - check the environment variables
  in the exec event (es_event_exec_t has env data).

14.3 ES Detection of Gatekeeper Bypasses
------------------------------------------

```c
// In AUTH_EXEC handler:
if (message->process->is_adhoc_signed &&
    !is_known_adhoc_app(message->process->signing_id)) {
    // Likely Gatekeeper bypass via ad-hoc signing
    log_suspicious(message->process, "Ad-hoc signed binary");
}

// Check for DYLD_INSERT_LIBRARIES in environment
const char **env = message->event.exec.env;
for (int i = 0; env[i] != NULL; i++) {
    if (strstr(env[i], "DYLD_INSERT_LIBRARIES") != NULL) {
        log_suspicious(message->process, "DYLD injection attempt");
    }
}
```

14.4 Notarization Check
------------------------

Gatekeeper checks the notarization ticket (stapled to the binary
or fetched online). Cheats can:
  - Remove the ticket: codesign --remove-signature + ad-hoc re-sign
  - Use a binary that was never notarized (ad-hoc signed)
  - Exploit a vulnerability in the notarization verification

ES detection: Check the CS_RUNTIME flag and notarization status
in the code directory. The cs_blob contains a field for
notarization status (CS_LINKER_SIGNED indicates the binary was
processed by the linker, which includes notarization checks).


================================================================================
15. APPLE SILICON SPECIFICS
================================================================================

15.1 PAC (Pointer Authentication Code)
----------------------------------------

PAC is an ARM64 feature that signs function pointers and return
addresses with a cryptographic MAC. Key implications for anti-cheat:

- Function pointer forgery is detected: If a cheat tries to
  replace an ObjC IMP or C++ vtable entry with a forged pointer,
  the CPU generates an exception (BRK #0xC471) when the pointer
  is used.

- PAC keys: APIAKey (user-space A-key), APIBKey (user-space B-key),
  APDAKey (kernel A-key), etc. Each key is per-process and
  per-boot randomized.

- PAC instructions: PACIA, PACIB, AUTIA, AUTIB, etc.
  These are emitted by the compiler for:
    - Function pointers (PACIA - sign with A-key)
    - Return addresses (PACIASP - sign return address on stack)
    - Data pointers (PACDA - sign data pointer with A-key)

- Cheat impact: Method swizzling and vtable hooking are
  significantly harder because the replacement pointer must
  have a valid PAC signature. The cheat would need to either:
  (a) Know the PAC key (impossible - it's in kernel-only registers)
  (b) Use a gadget that already has a valid PAC signature
  (c) Disable PAC via kernel exploit (requires PPL bypass)

15.2 APRR (Apple Page Readonly/Read-Write)
-------------------------------------------

APRR is Apple's hardware-enforced page permission system on
Apple Silicon. It provides:

- Hardware-enforced W^X: Pages cannot be simultaneously writable
  and executable. This is enforced by the hardware, not just
  the kernel. Even a kernel exploit cannot create RWX pages
  without also modifying APRR registers (which are PPL-protected).

- APRR registers: APRR0-APRR7 (8 regions), each controlling
  permission for a range of the address space. These registers
  are only writable in EL1 (kernel) and are protected by PPL.

- JIT memory: MAP_JIT pages use a special APRR configuration
  that allows toggling between RW and RX via
  pthread_jit_write_protect_np(). This is the ONLY way to
  have executable memory that was previously writable.

- Cheat impact: Shellcode injection is much harder. The cheat
  must either:
  (a) Use MAP_JIT (requires allow-jit entitlement)
  (b) Use ROP/JOP chains (existing code gadgets)
  (c) Exploit a vulnerability in the APRR configuration

15.3 PPL (Page Protection Layer)
---------------------------------

PPL is Apple's kernel memory protection system on Apple Silicon.
It protects:

- Kernel code pages: Read-only, even from the kernel itself
- Kernel data structures: proc_t, task_t, vm_map_entry_t, etc.
  are in PPL-protected regions
- The PAC keys: Stored in PPL-protected registers
- The APRR registers: PPL-protected

PPL is enforced by a combination of hardware (ARM64 memory
attributes) and software (PPL page tables). Even with a
kernel exploit, modifying PPL-protected pages requires
a separate PPL bypass.

Cheat impact:
  - Kernel-level memory modification (e.g., patching the
    process list to hide a cheat process) is extremely difficult
  - Direct kernel object manipulation (DKOM) attacks are
    blocked by PPL
  - The only viable attack path is through a kernel exploit
    that also bypasses PPL (e.g., CVE-2023-23536 type bugs)

15.4 Threat Model Changes: Apple Silicon vs Intel
---------------------------------------------------

Intel Macs:
  - No PAC: Function pointers can be freely forged
  - No APRR: Kernel can create RWX pages
  - No PPL: Kernel memory is fully writable
  - Kexts: Can be loaded (with SIP disabled or user approval)
  - Threat model: Kernel-level cheats are feasible

Apple Silicon:
  - PAC: Function pointer forgery detected
  - APRR: Hardware W^X enforcement
  - PPL: Kernel memory protected
  - Kexts: Not supported (except specific driver types)
  - Threat model: Cheats are limited to:
    (a) User-space attacks (dylib injection, code signing bypass)
    (b) Exploiting signed drivers with vulnerabilities
    (c) Full kernel + PPL exploit chain (rare, high-value)

15.5 ARM64e vs ARM64
----------------------

macOS on Apple Silicon uses the ARM64e ABI, which includes:
  - PAC instructions in all compiled code
  - PACIASP in function prologues (return address signing)
  - BTI (Branch Target Identification) in some configurations

Standard ARM64 (without 'e') does not include PAC. macOS
uses ARM64e exclusively on Apple Silicon.

15.6 Anti-Cheat Implications Summary
--------------------------------------

On Apple Silicon, the anti-cheat threat model is significantly
reduced compared to Intel:

1. Kernel-level cheats: Effectively impossible without a
   kernel + PPL exploit chain (rare, patched quickly)

2. Function pointer manipulation: Detected by PAC (crash)

3. Shellcode injection: Blocked by APRR (no RWX pages)

4. Dylib injection: Still possible via code signing bypass
   (ad-hoc signing + disable-library-validation)

5. task_for_pid: Still possible via entitlements
   (CS_GET_TASK_ALLOW, debugger entitlement)

6. IOKit attacks: Still possible (user-client access is
   not hardware-protected)

7. ES-based detection: Fully functional on Apple Silicon
   (ES is the primary anti-cheat mechanism)

The primary remaining attack surface on Apple Silicon is:
  - User-space code injection via entitlements
  - IOKit user-client exploitation
  - Mach port delegation
  - DYLD manipulation (within the cheat's own process)


================================================================================
APPENDIX A: ES EVENT TYPE CONSTANTS QUICK REFERENCE
================================================================================

AUTH Events:
  ES_EVENT_TYPE_AUTH_EXEC              = 0x0001
  ES_EVENT_TYPE_AUTH_OPEN              = 0x0002
  ES_EVENT_TYPE_AUTH_MMAP              = 0x0003
  ES_EVENT_TYPE_AUTH_RENAME            = 0x0004
  ES_EVENT_TYPE_AUTH_UNLINK            = 0x0005
  ES_EVENT_TYPE_AUTH_SIGNAL            = 0x0006
  ES_EVENT_TYPE_AUTH_MOUNT             = 0x0007
  ES_EVENT_TYPE_AUTH_TASK_FOR_PID      = 0x0008
  ES_EVENT_TYPE_AUTH_IOKIT_OPEN        = 0x0009
  ES_EVENT_TYPE_AUTH_MACH_RIGHT        = 0x000A  (macOS 13+)
  ES_EVENT_TYPE_AUTH_COPYFILE          = 0x000B  (macOS 14+)

NOTIFY Events:
  ES_EVENT_TYPE_NOTIFY_EXEC            = 0x8001
  ES_EVENT_TYPE_NOTIFY_FORK            = 0x8002
  ES_EVENT_TYPE_NOTIFY_EXIT            = 0x8003
  ES_EVENT_TYPE_NOTIFY_CSU_INVALIDATED = 0x8004
  ES_EVENT_TYPE_NOTIFY_MMAP            = 0x8005
  ES_EVENT_TYPE_NOTIFY_MPROTECT        = 0x8006
  ES_EVENT_TYPE_NOTIFY_SIGNAL          = 0x8007
  ES_EVENT_TYPE_NOTIFY_RENAME          = 0x8008
  ES_EVENT_TYPE_NOTIFY_UNLINK          = 0x8009
  ES_EVENT_TYPE_NOTIFY_OPEN            = 0x800A
  ES_EVENT_TYPE_NOTIFY_MACH_MSG        = 0x800B  (macOS 13+)
  ES_EVENT_TYPE_NOTIFY_MACH_RIGHT      = 0x800C  (macOS 13+)
  ES_EVENT_TYPE_NOTIFY_IPC_MSG         = 0x800D  (macOS 13+)
  ES_EVENT_TYPE_NOTIFY_TRACER          = 0x800E
  ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD   = 0x800F  (macOS 14+)
  ES_EVENT_TYPE_NOTIFY_PROC_SUSPEND    = 0x8010  (macOS 15+)
  ES_EVENT_TYPE_NOTIFY_GET_TASK        = 0x8011  (macOS 15+)


================================================================================
APPENDIX B: CS FLAGS QUICK REFERENCE
================================================================================

CS_VALID                    = 0x00000001
CS_ADHOC                    = 0x00000002
CS_GET_TASK_ALLOW           = 0x00000004
CS_INSTALLER                = 0x00000008
CS_INVALID_ALLOWED          = 0x00000010
CS_HARD                     = 0x00000100
CS_KILL                     = 0x00000200
CS_CHECK_EXPIRATION         = 0x00000400
CS_ENFORCEMENT              = 0x00001000
CS_REQUIRE_LV               = 0x00002000
CS_ENTITLEMENTS_VALIDATED   = 0x00004000
CS_RUNTIME                  = 0x00010000
CS_LINKER_SIGNED            = 0x00020000
CS_PLATFORM_BINARY          = 0x00400000
CS_PLATFORM_PATH            = 0x00800000
CS_EXEC_SET_HARD            = 0x00100000
CS_EXEC_SET_KILL            = 0x00200000
CS_EXEC_SET_ENFORCEMENT     = 0x00400000
CS_EXEC_INHERIT_SIP         = 0x01000000
CS_EXEC_SET_INSTALLER       = 0x02000000
CS_ALLOWED_MACHO            = 0x00020000


================================================================================
APPENDIX C: DANGEROUS ENTITLEMENTS QUICK REFERENCE
================================================================================

com.apple.security.cs.allow-jit
com.apple.security.cs.allow-unsigned-executable-memory
com.apple.security.cs.disable-library-validation
com.apple.security.cs.debugger
com.apple.security.cs.allow-environment-variables
com.apple.security.get-task-allow
com.apple.security.cs.allow-dyld-environment-variables


================================================================================
APPENDIX D: DANGEROUS IOKIT USER CLIENT CLASSES
================================================================================

AppleSMC
IOFramebufferSharedUserClient
IOHIDSystem
IOAccelerator
IOGPUDevice
IOMobileFramebuffer


================================================================================
END OF DOCUMENT
================================================================================
