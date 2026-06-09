/*
 * kernel/macos/es/ExceptionPortAudit.mm
 * Role: Signal 160 — Mach exception-port ownership audit (timing-side-channels, macOS).
 *       For a process observed on the ES path, audits the registered Mach exception
 *       ports for EXC_MASK_BREAKPOINT | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_BAD_ACCESS
 *       and resolves the owning task vs self / the OS default catcher. A foreign or
 *       unsigned owner of EXC_BREAKPOINT is the stepping-debugger tell. Raw audit only —
 *       the client emits the owner classification; the server scores (ReportCrash + the
 *       game's signed crash handler are allowlisted server-side).
 * Target platform: macOS ES (userspace). Built into horkos_es under HORKOS_MACOS_ES.
 * Interface: HkExceptionPortAudit(pid, audit_token, out) — invoked from EsClient.mm's
 *       process-handling path. Returns evidence by out-param; the caller emits it on the
 *       async sink, NEVER on the ES serial queue, and the audit NEVER gates the ES reply
 *       (guardrail #7): the AUTH reply is sent before/independently of this call.
 *
 * Guardrail compliance: #1 (no HK_PLATFORM macros — CMake selects this on macOS only),
 * #3 (this comment), #4 (pure userspace; no kernel headers), #7 (the audit cannot gate
 * the ES reply — it is read-only and side-effect-free, and the caller replies first),
 * #8-spirit (non-blocking: the port reads are bounded mach calls, but to stay off the
 * deadline-bound ES queue the CALLER dispatches this onto the sink queue).
 *
 * HK-UNCERTAIN(es-foreign-taskport): whether task_get_exception_ports can be called
 * against a FOREIGN (game) task from within an EndpointSecurity client, and which task
 * port the es_message_t process context legitimately yields, is UNVERIFIED. ES clients
 * are not general task-port holders; obtaining a target task port may require
 * task_name_for_pid (a NAME port, which is INSUFFICIENT for task_get_exception_ports —
 * that needs a control port) or processor_set introspection, or it may not be possible
 * without additional entitlement. Per guardrail #13 the foreign-task port acquisition is
 * NOT guessed: HkExceptionPortAudit audits ONLY mach_task_self() (the daemon's own task,
 * always available) as a structural proof-of-mechanism, and leaves the foreign-task
 * resolution a documented stub that returns HK_EXCPORT_RESULT_UNAVAILABLE. Resolve the
 * task-port acquisition path on-box before auditing a foreign task.
 */

#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <mach/exception_types.h>
#include <stdint.h>
#include <string.h>

/* Result classification for the audited target. */
enum {
    HK_EXCPORT_RESULT_UNAVAILABLE = 0, /* could not acquire the target task port */
    HK_EXCPORT_RESULT_DEFAULT     = 1, /* no third-party catcher (OS default / none) */
    HK_EXCPORT_RESULT_SELF        = 2, /* the target catches its own (signed crash handler) */
    HK_EXCPORT_RESULT_FOREIGN     = 3, /* a foreign task owns an audited exception port */
};

/* Out-param: which audited masks had a non-default owner + the coarse classification.
 * Owner identity (signed/allowlisted) is a server-side determination; the client ships
 * the foreign_owner_mask + result and lets the server allowlist ReportCrash / the
 * game's signed handler. */
typedef struct HkExcPortAudit {
    uint32_t result;            /* one of HK_EXCPORT_RESULT_* */
    uint32_t foreign_owner_mask;/* bits of EXC_MASK_* with a foreign/non-default owner */
    uint32_t breakpoint_foreign;/* 1 if EXC_MASK_BREAKPOINT specifically has a foreign owner */
    uint32_t audited_self;      /* 1 if this audit covered our OWN task only (stub mode) */
} HkExcPortAudit;

/* The masks we audit (plan §160). EXC_MASK_BREAKPOINT is the stepping-debugger tell;
 * BAD_INSTRUCTION / BAD_ACCESS catch decoy/illegal-op interposers. */
#define HK_AUDIT_EXC_MASKS \
    (EXC_MASK_BREAKPOINT | EXC_MASK_BAD_INSTRUCTION | EXC_MASK_BAD_ACCESS)

/*
 * Audit the exception ports registered on `task` for the audited masks. Sets
 * out->foreign_owner_mask for any mask whose handler port is non-null AND not the OS
 * default. "Foreign vs self" requires comparing the owning task of each handler port
 * against `task` — which is itself part of the HK-UNCERTAIN above (resolving a port's
 * owning task from an ES client). Here we only record WHETHER a non-default handler is
 * installed per mask; the self/foreign discrimination is left to the server using the
 * port's signed-owner correlation (the client cannot trust an in-process answer).
 */
static void audit_task_ports(task_t task, HkExcPortAudit *out)
{
    exception_mask_t       masks[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = 0;
    exception_port_t       ports[EXC_TYPES_COUNT];
    exception_behavior_t   behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t  flavors[EXC_TYPES_COUNT];

    memset(masks, 0, sizeof(masks));
    memset(ports, 0, sizeof(ports));
    memset(behaviors, 0, sizeof(behaviors));
    memset(flavors, 0, sizeof(flavors));

    kern_return_t kr = task_get_exception_ports(
        task, HK_AUDIT_EXC_MASKS, masks, &count, ports, behaviors, flavors);
    if (kr != KERN_SUCCESS) {
        out->result = HK_EXCPORT_RESULT_UNAVAILABLE;
        return;
    }

    uint32_t foreign = 0u;
    for (mach_msg_type_number_t i = 0; i < count; ++i) {
        /* A non-null, non-default handler port means SOMETHING is catching this
         * exception class. MACH_PORT_NULL = no catcher (OS default unwinds). We cannot
         * trust an in-process "is it me" comparison, so we record the mask as
         * non-default and let the server resolve the owner via signed-port correlation. */
        if (ports[i] != MACH_PORT_NULL) {
            foreign |= (uint32_t)masks[i];
        }
    }

    out->foreign_owner_mask = foreign;
    out->breakpoint_foreign = (foreign & (uint32_t)EXC_MASK_BREAKPOINT) ? 1u : 0u;
    /* DEFAULT if nothing is registered; otherwise SELF as the conservative class for an
     * OWN-task audit (the daemon legitimately may have handlers). For a foreign-task
     * audit (once the port path is resolved) this becomes FOREIGN. */
    out->result = (foreign == 0u) ? HK_EXCPORT_RESULT_DEFAULT : HK_EXCPORT_RESULT_SELF;
}

/*
 * HkExceptionPortAudit — entry point invoked from the ES process-handling path.
 *
 * pid          : the observed target's pid (from the es_message_t process context).
 * audit_token  : the target's audit token (reserved for the server-side owner
 *                correlation; not used to acquire the task port here — see HK-UNCERTAIN).
 * out          : filled with the audit result. Always written (never left uninitialised),
 *                so a caller that emits unconditionally has a well-defined record.
 *
 * GUARDRAIL #7: this function is read-only and side-effect-free; it NEVER replies to or
 * gates an ES auth message. The EsClient AUTH reply is sent independently and first.
 */
extern "C" void HkExceptionPortAudit(int pid,
                                     const audit_token_t *audit_token,
                                     HkExcPortAudit *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    (void)pid;
    (void)audit_token;

    /* HK-UNCERTAIN(es-foreign-taskport): acquiring the GAME task's control port from an
     * ES client is unverified (see file header). Until resolved, audit our OWN task as a
     * structural proof-of-mechanism and mark the record audited_self=1 so the server
     * does NOT treat a self-audit as a foreign-debugger finding. task_for_pid / a NAME
     * port is deliberately NOT used (a NAME port cannot drive task_get_exception_ports,
     * and task_for_pid needs entitlement/SIP posture we do not assert here). */
    out->audited_self = 1u;
    audit_task_ports(mach_task_self(), out);

    /* The foreign-task branch (resolve the game's control port, then audit_task_ports on
     * it, then set result=HK_EXCPORT_RESULT_FOREIGN when a non-self owner holds
     * EXC_MASK_BREAKPOINT) is intentionally NOT implemented — it rides the HK-UNCERTAIN
     * task-port acquisition above. */
}
