# Windows Kernel Anti-Cheat Detection Techniques — Deep Dive

> **Audience**: Experienced Windows kernel developers. Assumes familiarity with NT kernel internals, WDK conventions, and x64 calling convention.
> **Scope**: Windows 10 1607+ through Windows 11 24H2. Offsets target x64. Version-dependency warnings called out explicitly.

---

## 1. Memory Scanning in Kernel — VAD Tree Walking

### 1.1 VAD Fundamentals

The Virtual Address Descriptor (VAD) tree is a self-balancing binary tree rooted at `EPROCESS.VadRoot` (. `VadRoot` is of type `MM_AVL_TABLE` (an RTL_AVL_TABLE wrapper). Each node is an `MMVAD_SHORT` (or `MMVAD` for VADs with names/file backings).

**Key structures (Windows 10+ x64):**

```
EPROCESS.VadRoot (offset varies; ~0x7d8 on Win10 21H2, ~0x808 on Win11 24H2)
  └── MMVAD_SHORT (node in AVL tree)
      +0x000 VadNode         : RTL_BALANCED_NODE
      +0x018 StartingVpn     : ULONG64      // Starting VPN (Virtual Page Number)
      +0x018 StartingVpnHigh : UCHAR        // Win11: high bits folded in
      +0x020 EndingVpn       : ULONG64      // Ending VPN
      +0x020 EndingVpnHigh   : UCHAR
      +0x028 VadFlags        : ULONG        // Commit type, protection, etc.
      +0x030 PushLock        : EX_PUSH_LOCK
      +0x038 Event           : KEVENT
      +0x040 ControlArea     : Pointer     // Only for MMVAD (long form)
      +0x048 FirstPrototypePte: Pointer
      +0x050 LastContiguousPte: Pointer
      +0x058 ViewLinks       : LIST_ENTRY
      +0x068 Subsection      : Pointer
```

> **CRITICAL**: The exact offsets shift between builds. The `VadFlags` field encodes the page protection in bits configured as `MMVAD_FLAGS`. On Win10 RS2+ this is 32 bits; on Win2004+ it was split into `MMVAD_FLAGS` (low 32) and `MMVAD_FLAGS1` (high 32 in a union). Never hardcode — resolve dynamically or use `NtQueryInformationProcess` as an alternative.

### 1.2 Traversal Algorithm

```c
// Walk VAD tree in-order to enumerate all VADs for a process
// IRQL: Must be APC_LEVEL or below. VAD tree walks MUST NOT be done at DISPATCH_LEVEL.

typedef struct _VAD_ENUM_CONTEXT {
    PDEVICE_OBJECT TargetDevice;
    ULONG_PTR MinimumProtection;  // e.g., PAGE_EXECUTE_READWRITE
} VAD_ENUM_CONTEXT;

// Use MmGetVirtualForPhysical for validating physical mappings
// — only valid at IRQL <= APC_LEVEL
NTSTATUS WalkVadTree(PEPROCESS Process, VAD_ENUM_CONTEXT* Ctx)
{
    PMMVAD_SHORT VadRoot = *(PMMVAD_SHORT*)((PUCHAR)Process + EPROCESS_VadRoot_Offset);
    if (!VadRoot) return STATUS_INVALID_PARAMETER;

    // Recursive AVL traversal
    return TraverseVadNode(VadRoot, Ctx);
}

NTSTATUS TraverseVadNode(PMMVAD_SHORT Node, VAD_ENUM_CONTEXT* Ctx)
{
    if (!Node) return STATUS_SUCCESS;

    // Check protection in VadFlags
    ULONG Flags = Node->VadFlags;
    if (IsExecutable(Flags) && IsWritable(Flags)) {
        // RWX region — flag for inspection
        ULONG64 Start = ((ULONG64)Node->StartingVpn) << PAGE_SHIFT;
        ULONG64 End   = (((ULONG64)Node->EndingVpn) + 1) << PAGE_SHIFT;
        ReportSuspiciousRegion(Start, End, Flags);
    }

    // Left child
    if (Node->VadNode.Left)
        TraverseVadNode(CONTAINING_RECORD(Node->VadNode.Left, MMVAD_SHORT, VadNode), Ctx);

    // Right child
    if (Node->VadNode.Right)
        TraverseVadNode(CONTAINING_RECORD(Node->VadNode.Right, MMVAD_SHORT, VadNode), Ctx);

    return STATUS_SUCCESS;
}
```

### 1.3 Detecting Hollowed Sections

```c
// Compare memory regions against on-disk PE headers for discrepancies
NTSTATUS ValidateDllIntegrity(PEPROCESS Process, PVOID BaseAddress, SIZE_T RegionSize)
{
    NTSTATUS status;
    SIZE_T bytesRead;

    // Read PE header from target process memory
    IMAGE_DOS_HEADER localDosHeader;
    status = MmCopyVirtualMemory(
        Process,                         // SourceProcess
        BaseAddress,                     // SourceAddress
        PsGetCurrentProcess(),           // TargetProcess
        &localDosHeader,                 // TargetAddress
        sizeof(IMAGE_DOS_HEADER),        // BufferSize
        KernelMode,                      // PreviousMode — CRITICAL: use KernelMode
        &bytesRead                       // ReturnSize
    );

    if (!NT_SUCCESS(status)) return status;

    if (localDosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        return STATUS_INVALID_IMAGE_HASH;

    // Read NT headers
    IMAGE_NT_HEADERS64 localNtHeaders;
    status = MmCopyVirtualMemory(
        Process,
        (PUCHAR)BaseAddress + localDosHeader.e_lfanew,
        PsGetCurrentProcess(),
        &localNtHeaders,
        sizeof(IMAGE_NT_HEADERS64),
        KernelMode,
        &bytesRead
    );

    // Compare section headers against disk
    // A hollowed DLL will have:
    //   - Correct headers in memory (copied from original)
    //   - But .text section body replaced with malicious code
    //   - Checksum mismatch between in-memory and on-disk IMAGE_OPTIONAL_HEADER.CheckSum
    //   - SizeOfImage may differ if sections were added/removed

    return ValidateSectionHashes(Process, BaseAddress, &localNtHeaders);
}
```

### 1.4 BSOD Pitfalls

| Pitfall | Cause | BSOD Code |
|---|---|---|
| VAD walk at `DISPATCH_LEVEL` | `MmGetVirtualForPhysical` raises IRQL | `IRQL_NOT_LESS_OR_EQUAL` (0xA) |
| Accessing freed VAD | Process exits during traversal; no reference held | `KERNEL_MODE_HEAP_CORRUPTION` (0x13A) |
| `PreviousMode = UserMode` in `MmCopyVirtualMemory` | ProbeForRead/Write triggers access violation on invalid addresses | `KERNEL_SECURITY_CHECK_FAILURE` (0x139) |
| Stack overflow from deep recursion | VAD tree can be thousands of nodes deep on heavy processes | `KERNEL_STACK_INPAGE_ERROR` (0x77) |
| PTE corruption | Reading PTEs for freed/transitioned pages | `PAGE_FAULT_IN_NONPAGED_AREA` (0x50) |

**Mitigation**: Use iterative traversal (explicit stack on pool) instead of recursion. Always hold a reference to the target process (`ObReferenceObject`). Use `MmCopyVirtualMemory` with `KernelMode` — never `UserMode` from a kernel thread.

---

## 2. Module List vs. Disk Validation

### 2.1 PsLoadedModuleList Walking

`PsLoadedModuleList` is the head of a doubly-linked list of `KLDR_DATA_TABLE_ENTRY` structures (not `LDR_DATA_TABLE_ENTRY` — the kernel variant). This list contains all loaded kernel modules.

```c
// PsLoadedModuleList is exported by ntoskrnl.exe
extern PLIST_ENTRY PsLoadedModuleList;

typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;        // +0x000
    LIST_ENTRY InInitializationOrderLinks; // +0x008 (Win10+: +0x010 due to padding)
    LIST_ENTRY InMemoryOrderLinks;       // +0x010 (Win10+: +0x020)
    PVOID ExceptionTable;                // +0x018 (deprecated, usually 0)
    ULONG ExceptionTableSize;            // +0x020
    PVOID GpValue;                       // +0x028
    PNPAGED_LOOKASIDE_LIST Lookaside;    // +0x030
    ULONG Version[2];                    // +0x038
    PVOID DllBase;                       // +0x040
    PVOID EntryPoint;                    // +0x048
    ULONG SizeOfImage;                   // +0x050
    UNICODE_STRING FullDllName;          // +0x058
    UNICODE_STRING BaseDllName;          // +0x060 (Win10+: +0x068)
    ULONG Flags;                         // +0x068
    USHORT LoadCount;                    // +0x070
    USHORT TlsIndex;                     // +0x072
    union {
        LIST_ENTRY HashLinks;            // +0x078
        struct {
            PVOID SectionPointer;        // +0x078
            ULONG CheckSum;              // +0x080
        };
    };
    ULONG TimeDateStamp;                 // +0x088
    PVOID LoadedImports;                 // +0x090
    PVOID EntryPointActivationContext;   // +0x098
    PVOID PatchInformation;              // +0x0A0
    // ... more fields, version-dependent
} KLDR_DATA_TABLE_ENTRY, *PKLDR_DATA_TABLE_ENTRY;
```

> **WARNING**: The `InMemoryOrderLinks` offset shifted from `+0x010` to `+0x020` between Windows 7 and Windows 10 due to the insertion of new fields. Always resolve dynamically.

### 2.2 Detection: Unsigned Driver Loaded

```c
NTSTATUS ScanLoadedModulesForAnomalies(void)
{
    for (PLIST_ENTRY pEntry = PsLoadedModuleList->Flink;
         pEntry != PsLoadedModuleList;
         pEntry = pEntry->Flink)
    {
        PKLDR_DATA_TABLE_ENTRY pModule =
            CONTAINING_RECORD(pEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        // Check 1: Is the module backed by a file on disk?
        if (pModule->FullDllName.Length == 0 || pModule->FullDllName.Buffer == NULL) {
            // Module loaded without a file path — suspicious
            ReportUnsignedOrReconstructedModule(pModule);
            continue;
        }

        // Check 2: Validate digital signature via CI.dll
        // Use CiValidateImageHeader (exported by ci.dll on Win10+)
        // IRQL: PASSIVE_LEVEL only
        NTSTATUS ciStatus = CiValidateImageHeader(
            pModule->DllBase,
            pModule->SizeOfImage,
            0,  // Flags
            &ciPolicyInfo
        );
        if (!NT_SUCCESS(ciStatus)) {
            ReportUnsignedModule(pModule);
        }

        // Check 3: Cross-reference with MmUnloadSystemImage
        // If a module claims to be loaded but its section object is gone,
        // it may have been manually mapped
        if (pModule->SectionPointer == NULL && pModule->DllBase != NULL) {
            ReportSectionlessModule(pModule);
        }
    }
    return STATUS_SUCCESS;
}
```

### 2.3 Detecting Manually-Mapped Drivers

A manually-mapped driver (loaded via `NtLoadDriver` or manual mapping) will:
- Appear in `PsLoadedModuleList` but lack a valid `SectionPointer`
- Have `FullDllName` pointing to a non-existent or deleted file
- Have `TimeDateStamp` inconsistent with the file on disk
- Have `DllBase` pointing to pool memory (tag `'CM'` or `'Mm'`) rather than a mapped section

```c
BOOLEAN IsManuallyMappedDriver(PKLDR_DATA_TABLE_ENTRY Entry)
{
    // Check if the base address falls within a known system module range
    // or if it's in dynamically-allocated pool
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T returnLength;

    NTSTATUS status = ZwQueryVirtualMemory(
        ZwCurrentProcess(),
        Entry->DllBase,
        MemoryBasicInformation,
        &mbi,
        sizeof(mbi),
        &returnLength
    );

    if (NT_SUCCESS(status)) {
        // If type is MEM_PRIVATE (0x20000) rather than MEM_IMAGE (0x1000000),
        // the module was manually mapped into private memory
        if (mbi.Type == MEM_PRIVATE)
            return TRUE;
    }

    return FALSE;
}
```

---

## 3. Thread Internals — ETHREAD Analysis

### 3.1 Key ETHREAD Fields

```c
// ETHREAD offsets (Windows 10 21H2 x64 — ALWAYS verify for your build)
// Use dt nt!_ETHREAD in WinDbg to confirm

typedef struct _ETHREAD {
    THTREAD Tcb;                              // +0x000 — KTHREAD
    LARGE_INTEGER CreateTime;                  // +0x3xx
    // ...
    PVOID StartAddress;                        // +0x450 (Win10 21H2) — actual start
    union {
        PVOID Win32StartAddress;               // +0x458 — user-reported start
    };
    // ...
    CLIENT_ID Cid;                             // +0x460 (Win10 21H2)
    //   Cid.UniqueProcess  : HANDLE
    //   Cid.UniqueThread   : HANDLE
    // ...
    UCHAR State;                               // +0x490 — KTHREAD_STATE
    //   Running = 0, Ready = 1, Waiting = 5, etc.
    UCHAR WaitReason;                          // +0x491 — KWAIT_REASON
    // ...
    KAPC_STATE ApcState;                       // +0x498
    // ...
    BOOLEAN UserApcPending;                    // +0x4C0 (approx)
    // ...
} ETHREAD, *PETHREAD;
```

### 3.2 Detecting Suspicious Thread Start Addresses

```c
NTSTATUS ScanThreadsForInjection(PEPROCESS TargetProcess)
{
    // Enumerate threads via NtQuerySystemInformation(SystemProcessInformation)
    // or directly via thread ID enumeration

    for (each thread in TargetProcess) {
        PETHREAD pThread;
        NTSTATUS status = PsLookupThreadByThreadId(ThreadId, &pThread);
        if (!NT_SUCCESS(status)) continue;

        // Method 1: Check StartAddress against known module ranges
        PVOID startAddr = *(PVOID*)((PUCHAR)pThread + ETHREAD_StartAddress_Offset);

        if (!IsAddressInKnownModule(startAddr, TargetProcess)) {
            // Thread starts in unknown memory — possible injection
            ReportSuspiciousThread(pThread, startAddr);
        }

        // Method 2: Use NtQueryInformationThread with ThreadQuerySetWin32StartAddress
        // This returns the Win32-specific start address (different from StartAddress)
        PVOID win32StartAddr = NULL;
        ULONG returnLen;
        status = NtQueryInformationThread(
            ThreadHandle,
            ThreadQuerySetWin32StartAddress,
            &win32StartAddr,
            sizeof(PVOID),
            &returnLen
        );

        if (NT_SUCCESS(status) && !IsAddressInKnownModule(win32StartAddr, TargetProcess)) {
            ReportSuspiciousWin32Start(pThread, win32StartAddr);
        }

        // Method 3: Check thread state for suspended-thread injection
        UCHAR state = *(PUCHAR)((PUCHAR)pThread + ETHREAD_State_Offset);
        UCHAR waitReason = *(PUCHAR)((PUCHAR)pThread + ETHREAD_WaitReason_Offset);

        if (state == Waiting && waitReason == Suspended) {
            // Thread is in suspended state — check if it was legitimately suspended
            ReportSuspendedThread(pThread);
        }

        ObDereferenceObject(pThread);
    }
    return STATUS_SUCCESS;
}
```

### 3.3 Detecting Thread Hijacking

Thread hijacking (also called "context hijacking") modifies an existing thread's context to redirect execution:

```c
// Check if a thread's context has been modified
// IRQL: Must be at THREAD_LEVEL (via KeSetSystemAffinityThread) or use
//       PsGetContextThread / PsSetContextThread

BOOLEAN IsThreadContextHijacked(PETHREAD Thread)
{
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;

    // Get thread context
    NTSTATUS status = PsGetContextThread(Thread, &ctx, KernelMode);
    if (!NT_SUCCESS(status)) return FALSE;

    // Check if RIP points to an unexpected module
    if (!IsAddressInKnownModule((PVOID)ctx.Rip, PsGetThreadProcess(Thread))) {
        return TRUE;
    }

    // Check for stack pivot (RSP pointing outside thread stack range)
    PVOID stackBase = Thread->Tcb.StackBase;
    PVOID stackLimit = Thread->Tcb.StackLimit;

    if (ctx.Rx < (ULONG64)stackLimit || ctx.Rx > (ULONG64)stackBase) {
        return TRUE;  // Stack pivot detected
    }

    return FALSE;
}
```

---

## 4. Handle Table Analysis

### 4.1 Handle Table Structure

```c
// EPROCESS.ObjectTable points to a HANDLE_TABLE
typedef struct _HANDLE_TABLE {
    ULONG NextHandleNeedingPool;          // +0x000
    LONG ExtraInfoPages;                   // +0x004
    volatile ULONG_PTR TableCode;          // +0x008
    // TableCode & 0x3 indicates level:
    //   0 = single level (TableCode & ~0x3 = array of HANDLE_TABLE_ENTRY)
    //   1 = two levels (TableCode & ~0x3 = array of pointers to arrays)
    //   2 = three levels (for > 512K handles)
    PEPROCESS QuotaProcess;                // +0x010
    LIST_ENTRY HandleTableList;            // +0x018 — global list of all handle tables
    ULONG UniqueProcessId;                 // +0x028
    // ... flags, handle contention event, etc.
} HANDLE_TABLE, *PHANDLE_TABLE;

typedef struct _HANDLE_TABLE_ENTRY {
    union {
        volatile LONG_PTR Object;          // +0x000 — pointer to object header
        ULONG ObAttributes;                //   or object attributes
        // Bit 0x03 (KERNEL_HANDLE_FLAG = 0x08 on x64) indicates kernel handle
    };
    union {
        ULONG GrantedAccess;               // +0x008
        struct {
            USHORT GrantedAccessIndex;
            USHORT CreatorBackTraceIndex;
        };
        LONG NextFreeTableEntry;
    };
} HANDLE_TABLE_ENTRY, *PHANDLE_TABLE_ENTRY;
```

### 4.2 Enumerating Handles to Target Process

```c
// IRQL: PASSIVE_LEVEL only (ExEnumHandleTable can be called at APC_LEVEL
// but the callback runs at the caller's IRQL)

NTSTATUS CountHandlesToProcess(
    PEPROCESS TargetProcess,
    PULONG OutKernelHandles,
    PULONG OutUserHandles
)
{
    PEPROCESS SystemProcess = PsInitialSystemProcess;
    PHANDLE_TABLE ObjectTable = *(PHANDLE_TABLE*)((PUCHAR)SystemProcess + EPROCESS_ObjectTable_Offset);

    HANDLE_ENUM_CONTEXT ctx = { 0 };
    ctx.TargetProcess = TargetProcess;
    ctx.KernelHandleCount = 0;
    ctx.UserHandleCount = 0;

    // ExEnumHandleTable walks every handle in the system handle table
    // Signature (undocumented):
    //   BOOLEAN ExEnumHandleTable(
    //       PHANDLE_TABLE HandleTable,
    //       PEX_ENUM_HANDLE_CALLBACK EnumHandleProcedure,
    //       PVOID EnumContext,
    //       PHANDLE_ENUMERATION_HANDLE  // optional, for resuming
    //   );

    BOOLEAN completed = ExEnumHandleTable(
        ObjectTable,
        EnumHandleCallback,
        &ctx,
        NULL  // No resume handle
    );

    *OutKernelHandles = ctx.KernelHandleCount;
    *OutUserHandles = ctx.UserHandleCount;

    return completed ? STATUS_SUCCESS : STATUS_MORE_ENTRIES;
}

BOOLEAN EnumHandleCallback(
    PHANDLE_TABLE HandleTable,
    PHANDLE_TABLE_ENTRY HandleTableEntry,
    HANDLE Handle,
    PVOID EnumContext
)
{
    HANDLE_ENUM_CONTEXT* ctx = (HANDLE_ENUM_CONTEXT*)EnumContext;

    // Object field encodes the object pointer
    // Low 3 bits are used for flags on x64 (handle is 4-byte aligned)
    PVOID Object = (PVOID)(HandleTableEntry->Object & ~0x7);

    if (Object == NULL) return FALSE;  // Continue enumeration

    // Get the object type
    POBJECT_HEADER ObjHeader = OBJECT_TO_OBJECT_HEADER(Object);
    if (ObjHeader == NULL) return FALSE;

    // Check if this handle points to our target process
    PEPROCESS HandleProcess = (PEPROCESS)Object;
    if (HandleProcess == ctx->TargetProcess) {
        // Check if it's a kernel handle (bit 3 set in ObAttributes)
        if (HandleTableEntry->ObAttributes & OBJ_KERNEL_HANDLE) {
            ctx->KernelHandleCount++;
        } else {
            ctx->UserHandleCount++;
        }
    }

    return FALSE;  // Continue enumeration
}
```

### 4.3 Detecting Handle Table Anomalies

```c
// A cheat tool opening > N handles to the game process is suspicious
#define SUSPICIOUS_HANDLE_THRESHOLD 5

// Also check for handle duplication attacks:
// Tools like ProcessHacker duplicate handles via NtDuplicateObject
// Look for handles with PROCESS_ALL_ACCESS (0x1FFFFF0000) granted access

BOOLEAN IsHandleSuspicious(PHANDLE_TABLE_ENTRY Entry, HANDLE Handle)
{
    ULONG grantedAccess = Entry->GrantedAccess;

    // Check for full access
    if ((grantedAccess & PROCESS_ALL_ACCESS) == PROCESS_ALL_ACCESS) {
        return TRUE;
    }

    // Check for specific dangerous access rights
    if (grantedAccess & (PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD)) {
        return TRUE;
    }

    return FALSE;
}
```

### 4.4 BSOD Risks with Handle Table Walking

| Risk | Cause | Mitigation |
|---|---|---|
| Deadlock | `ExEnumHandleTable` acquires handle table lock; callback tries to acquire it again | Never call `ExEnumHandleTable` from within a callback |
| Use-after-free | Handle closed during enumeration | `ExEnumHandleTable` handles this internally, but don't cache `Object` pointers |
| IRQL violation | Calling at `DISPATCH_LEVEL` | Must be `PASSIVE_LEVEL` or `APC_LEVEL` |
| Stack overflow | Deep handle tables (millions of entries) | Use iterative approach; limit enumeration depth |

---

## 5. IRP Monitoring — IOCTL Interception

### 5.1 Anti-Cheat Device Object Setup

Anti-cheats create a device object and register dispatch routines:

```c
// Typical anti-cheat driver initialization
NTSTATUS CreateAntiCheatDevice(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\AntiCheatDevice");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\DosDevices\\AntiCheatDevice");

    PDEVICE_OBJECT DeviceObject;
    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,                    // DeviceExtensionSize
        &devName,
        FILE_DEVICE_UNKNOWN,  // DeviceType
        0,                    // DeviceCharacteristics
        FALSE,                // Exclusive
        &DeviceObject
    );

    if (!NT_SUCCESS(status)) return status;

    // Set dispatch routines
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = AntiCheatCreateDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = AntiCheatCloseDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AntiCheatIoctlDispatch;
    DriverObject->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = AntiCheatIoctlDispatch;

    // Create symbolic link for user-mode access
    IoCreateSymbolicLink(&symLink, &devName);

    return STATUS_SUCCESS;
}
```

### 5.2 Detecting IOCTL Tampering

```c
// In the anti-cheat's IOCTL dispatch, validate the request origin
NTSTATUS AntiCheatIoctlDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;

    // Check 1: Validate input buffer length
    ULONG inputLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    if (inputLen < sizeof(ANTICHEAT_REQUEST_HEADER)) {
        Irp->IoStatus.Status = STATUS_INVALID_BUFFER_SIZE;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_BUFFER_SIZE;
    }

    // Check 2: Validate the calling process
    PEPROCESS callingProcess = IoGetRequestorProcess(Irp);
    if (callingProcess != PsGetCurrentProcess()) {
        // IRP was forwarded from another process — suspicious
        ReportIrpForwarding(Irp);
    }

    // Check 3: Validate IOCTL code hasn't been hooked
    // Compare the dispatch function pointer against the known good value
    if (DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] != AntiCheatIoctlDispatch) {
        // Someone hooked our dispatch routine
        ReportDispatchHook();
    }

    // Check 4: Detect direct kernel manipulation (DKOM on IRP)
    // Verify the IRP's stack location hasn't been tampered with
    if (irpStack->MajorFunction != IRP_MJ_DEVICE_CONTROL &&
        irpStack->MajorFunction != IRP_MJ_INTERNAL_DEVICE_CONTROL) {
        ReportIrpTampering(Irp);
    }

    // Process the IOCTL...
    return ProcessAntiCheatIoctl(Irp, ioctlCode);
}
```

### 5.3 Detecting ProcessHacker-style Direct IOCTL

Tools like ProcessHacker load a kernel driver (`kprocesshacker.sys`) that sends direct IOCTLs to manipulate processes. Detection strategies:

```c
// Monitor for drivers that register process handles with full access
// via NtOpenProcess from kernel (ZwOpenProcess with KernelMode)

// Hook detection: Check if NtOpenProcess has been hooked
// by comparing the function prologue against the known bytes

BOOLEAN IsNtOpenProcessHooked(void)
{
    // Read the first 16 bytes of NtOpenProcess
    PUCHAR funcBytes = (PUCHAR)ZwOpenProcess;

    // Check for common hook patterns:
    // JMP rel32 (0xE9 xx xx xx xx)
    // JMP [rip+offset] (0xFF 0x25 xx xx xx xx)
    // PUSH ret (0x68 xx xx xx xx 0xC3)
    // MOV RAX, addr; JMP RAX (0x48 0xB8 ... 0xFF 0xE0)

    if (funcBytes[0] == 0xE9) return TRUE;  // Relative JMP
    if (funcBytes[0] == 0xFF && funcBytes[1] == 0x25) return TRUE;  // Indirect JMP
    if (funcBytes[0] == 0x68 && funcBytes[5] == 0xC3) return TRUE;  // PUSH/RET

    return FALSE;
}
```

---

## 6. APC Injection Internals

### 6.1 APC Structure and Queuing

```c
// KAPC structure (partial)
typedef struct _KAPC {
    UCHAR Type;                    // +0x000 — 0x12 on Win10 (APC_OBJECT)
    UCHAR SpareByte0;
    UCHAR Size;                    // +0x002 — 0x58 on Win10 x64
    UCHAR SpareByte1;
    ULONG SpareLong0;
    struct _KTHREAD* Thread;       // +0x008
    LIST_ENTRY ApcListEntry;       // +0x010
    PKNORMAL_ROUTINE NormalRoutine; // +0x020 — callback function
    PVOID NormalContext;           // +0x028 — first arg to NormalRoutine
    PVOID SystemArgument1;         // +0x030
    PVOID SystemArgument2;         // +0x038
    CCHAR ApcIndex;                // +0x040 — which APC slot
    KPROCESSOR_MODE ApcMode;       // +0x044 — KernelMode or UserMode
    UCHAR Inserted;                // +0x045 — TRUE if queued
} KAPC, *PKAPC;

// KAPC_STATE within ETHREAD
typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[2];     // [0]=KernelMode, [1]:UserMode
    struct _KPROCESS* Process;
    BOOLEAN KernelApcInProgress;
    BOOLEAN KernelApcPending;
    BOOLEAN UserApcPending;        // ← KEY FIELD for detection
} KAPC_STATE, *PKAPC_STATE;
```

### 6.2 Detecting Queued User APCs

```c
// Scan all threads in target process for queued user APCs
// IRQL: APC_LEVEL (to safely access APC lists)

NTSTATUS ScanForQueuedApcs(PEPROCESS TargetProcess)
{
    for (each thread in TargetProcess) {
        PETHREAD pThread = ...;
        PKAPC_STATE apcState = (PKAPC_STATE)((PUCHAR)pThread + ETHREAD_ApcState_Offset);

        // Check UserApcPending flag
        if (apcState->UserApcPending) {
            // User APCs are pending — enumerate them
            PLIST_ENTRY head = &apcState->ApcListHead[UserMode];

            for (PLIST_ENTRY entry = head->Flink; entry != head; entry = entry->Flink) {
                PKAPC Apc = CONTAINING_RECORD(entry, KAPC, ApcListEntry);

                // Check if the NormalRoutine points to a known module
                if (!IsAddressInKnownModule(Apc->NormalRoutine, TargetProcess)) {
                    // APC callback in unknown memory — likely injection
                    ReportMaliciousApc(pThread, Apc);
                }

                // Check ApcMode — user-mode APCs injected from kernel
                // will have ApcMode == KernelMode but be in the user APC list
                if (Apc->ApcMode == KernelMode && Apc->ApcIndex == UserMode) {
                    ReportKernelInjectedUserApc(pThread, Apc);
                }
            }
        }

        // Also check kernel APCs (less common for injection but still relevant)
        if (apcState->KernelApcPending) {
            PLIST_ENTRY head = &apcState->ApcListHead[KernelMode];
            for (PLIST_ENTRY entry = head->Flink; entry != head; entry = entry->Flink) {
                PKAPC Apc = CONTAINING_RECORD(entry, KAPC, ApcListEntry);
                if (!IsAddressInKnownModule(Apc->NormalRoutine, TargetProcess)) {
                    ReportMaliciousKernelApc(pThread, Apc);
                }
            }
        }
    }
    return STATUS_SUCCESS;
}
```

### 6.3 Distinguishing Legitimate vs. Malicious APCs

| Characteristic | Legitimate (I/O Completion) | Malicious (Injection) |
|---|---|---|
| `NormalRoutine` | Points to I/O completion routine in known driver | Points to shellcode in RWX region |
| `NormalContext` | I/O request context (IRP-related) | Arbitrary pointer (often module base) |
| `ApcMode` | KernelMode for kernel APCs | KernelMode APC in user APC list |
| `ApcIndex` | Matches ApcMode | Mismatched (kernel APC in user slot) |
| Trigger | I/O completion | `KeInsertQueueApc` from external driver |

### 6.4 KiUserApcDispatcher Monitoring

`KiUserApcDispatcher` (in ntdll.dll) is the user-mode entry point for APCs. Anti-cheats can:

1. **Hook ntdll.dll's `KiUserApcDispatcher`** — detect by comparing in-memory ntdll against disk
2. **Monitor `NtQueueApcThread` syscalls** — detect via syscall hooking or ETW
3. **Check for `NtQueueApcThreadEx`** — newer API that supports user-mode APCs with context

```c
// Detect ntdll.dll hooking of KiUserApcDispatcher
BOOLEAN IsKiUserApcDispatcherHooked(PVOID NtdllBase)
{
    // Find KiUserApcDispatcher in ntdll export table
    PVOID dispatcherAddr = RtlFindExportedRoutineByName(NtdllBase, "KiUserApcDispatcher");

    // Read first 16 bytes and check for hooks
    PUCHAR bytes = (PUCHAR)dispatcherAddr;

    // KiUserApcDispatcher typically starts with:
    //   mov r11, rcx        (4C 8B D1)
    //   mov rcx, rdx        (48 8B CA)
    //   ...
    // If it starts with a JMP, it's hooked
    if (bytes[0] == 0xE9 || bytes[0] == 0xEB || bytes[0] == 0xFF)
        return TRUE;

    return FALSE;
}
```

---

## 7. Kernel Pool Tag Scanning

### 7.1 Pool Header Structure

```c
// POOL_HEADER (Windows 10+ x64)
typedef struct _POOL_HEADER {
    union {
        struct {
            USHORT PreviousSize : 8;   // 0x000:0-7
            USHORT PoolIndex   : 8;    // 0x000:8-15
            USHORT BlockSize   : 8;    // 0x001:0-7
            USHORT PoolType    : 8;    // 0x001:8-15
        };
        ULONG ULong1;
    };
    ULONG PoolTag;                     // +0x004 — 4-byte tag like 'ChEaT'
    union {
        PEPROCESS ProcessBilled;       // +0x008
        struct {
            USHORT AllocatorBackTraceIndex;
            USHORT PoolTagHash;
        };
    };
} POOL_HEADER, *PPOOL_HEADER;

// Allocation layout:
// [POOL_HEADER][User Data]
// The pool tag is at offset +0x04 from the start of the header
// On Win10+ with pool tracking, additional tracking info may precede POOL_HEADER
```

### 7.2 Programmatic Pool Scanning

```c
// Method 1: Use NtQuerySystemInformation with SystemPoolTagInformation
// This is the documented (but undocumented-in-header) way to get pool tag stats

typedef struct _SYSTEM_POOLTAG {
    union {
        UCHAR Tag[4];
        ULONG TagUlong;
    };
    ULONG PagedAllocs;
    ULONG PagedFrees;
    SIZE_T PagedUsed;
    ULONG NonPagedAllocs;
    ULONG NonPagedFrees;
    SIZE_T NonPagedUsed;
} SYSTEM_POOLTAG, *PSYSTEM_POOLTAG;

NTSTATUS ScanPoolForCheatTags(void)
{
    ULONG bufferSize = 0x100000;  // Start with 1MB
    PSYSTEM_POOLTAG buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'tQSN');

    NTSTATUS status = NtQuerySystemInformation(
        SystemPoolTagInformation,  // 0x16
        buffer,
        bufferSize,
        &bufferSize
    );

    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        ExFreePoolWithTag(buffer, 'tQSN');
        buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'tQSN');
        status = NtQuerySystemInformation(SystemPoolTagInformation, buffer, bufferSize, NULL);
    }

    if (!NT_SUCCESS(status)) return status;

    // First ULONG is the number of pool tag entries
    ULONG tagCount = *(ULONG*)buffer;
    PSYSTEM_POOLTAG tags = (PSYSTEM_POOLTAG)((PUCHAR)buffer + sizeof(ULONG));

    // Known cheat engine pool tags (partial list)
    static const ULONG CheatTags[] = {
        'ChEaT',  // Cheat Engine
        'GameC',  // Generic game cheat
        'Hack',   // Generic hack tool
        'T3rH',   // TeraHacker
        'PChc',   // Process Hacker (kprocesshacker.sys)
        'PROCH',  // Process Hacker alternate
        'HxT',    // HxD memory editor
        'RWE',    // Read-Write-Execute tool
    };

    for (ULONG i = 0; i < tagCount; i++) {
        for (ULONG j = 0; j < ARRAYSIZE(CheatTags); j++) {
            if (tags[i].TagUlong == CheatTags[j]) {
                ReportCheatPoolTag(&tags[i]);
            }
        }
    }

    ExFreePoolWithTag(buffer, 'tQSN');
    return STATUS_SUCCESS;
}
```

### 7.3 Direct Pool Memory Scanning (Advanced)

```c
// Method 2: Scan non-paged pool directly for known patterns
// IRQL: DISPATCH_LEVEL (we're scanning non-paged pool)
// WARNING: This is extremely dangerous and can cause BSODs

// Use MmGetPhysicalMemoryRanges to enumerate physical memory
// Then map each range and scan for pool headers with known tags

typedef struct _PHYSICAL_MEMORY_RANGE {
    PHYSICAL_ADDRESS BaseAddress;
    LARGE_INTEGER NumberOfBytes;
} PHYSICAL_MEMORY_RANGE, *PPHYSICAL_MEMORY_RANGE;

NTSTATUS ScanPhysicalPoolForTags(void)
{
    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    if (!ranges) return STATUS_UNSUCCESSFUL;

    for (int i = 0; ranges[i].QuadPart != 0; i++) {
        PHYSICAL_ADDRESS physAddr = ranges[i].BaseAddress;
        SIZE_T rangeSize = (SIZE_T)ranges[i].NumberOfBytes.QuadPart;

        // Map physical memory
        PVOID mapped = MmMapIoSpace(physAddr, rangeSize, MmNonCached);
        if (!mapped) continue;

        // Scan for pool headers
        // Pool allocations are 16-byte aligned on x64
        for (SIZE_T offset = 0; offset < rangeSize; offset += 16) {
            PPOOL_HEADER header = (PPOOL_HEADER)((PUCHAR)mapped + offset);

            // Validate pool header
            if (header->PoolType == 0) continue;  // Free pool

            // Check for known tags
            if (IsKnownCheatTag(header->PoolTag)) {
                ReportPoolAllocation(header, physAddr.QuadPart + offset);
            }
        }

        MmUnmapIoSpace(mapped, rangeSize);
    }

    ExFreePool(ranges);
    return STATUS_SUCCESS;
}
```

### 7.4 BSOD Risks in Pool Scanning

| Risk | Cause | Mitigation |
|---|---|---|
| Accessing freed pool | Allocation freed between scan and access | Use `ExFreezeAllWorkerThreads` or suspend target process |
| Invalid physical mapping | `MmMapIoSpace` on non-pool memory | Validate pool headers before dereferencing |
| Race condition | Pool tag changes during scan | Use `KeEnterCriticalRegion` / `KeLeaveCriticalRegion` |
| Infinite loop | Corrupted pool linked lists | Set maximum iteration count |

---

## 8. DPC (Deferred Procedure Call) Inspection

### 8.1 DPC Structure

```c
// KDPC structure
typedef struct _KDPC {
    UCHAR Type;                    // +0x000 — 0x13 (DPC_OBJECT) or 0x17 (THREADED_DPC)
    UCHAR Importance;              // +0x001 — Low, Medium, High
    volatile USHORT Number;        // +0x002 — Processor number (for threaded DPC)
    LIST_ENTRY DpcListEntry;       // +0x008 — Links into PRCB.DpcListHead
    PKDEFERRED_ROUTINE DeferredRoutine; // +0x018 — The DPC function
    PVOID DeferredContext;         // +0x020
    PVOID SystemArgument1;         // +0x028
    PVOID SystemArgument2;         // +0x030
    PVOID DpcData;                 // +0x038 — Points to KDPC_DATA
} KDPC, *PKDPC;

// PRCB (Processor Control Block) DPC-related fields
// KiProcessorBlock[n]->Prcb->DpcListHead — head of DPC queue
// KiProcessorBlock[n]->Prcb->DpcRoutineActive — currently executing DPC
// KiProcessorBlock[n]->Prcb->DpcRequestScheduled — DPC scheduled flag
```

### 8.2 Detecting Anomalous DPCs

```c
// Scan DPC queues for DPCs from unknown modules
// IRQL: Must raise to DISPATCH_LEVEL on each processor

NTSTATUS ScanDpcQueues(void)
{
    ULONG numProcessors = KeQueryActiveProcessorCount(NULL);

    for (ULONG proc = 0; proc < numProcessors; proc++) {
        // Raise IRQL to DISPATCH_LEVEL on target processor
        KIRQL oldIrql;
        KeSetSystemAffinityThread((KAFFINITY)(1ULL << proc));
        KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

        // Get PRCB for this processor
        PKPRCB prcb = KiProcessorBlock[proc];

        // Walk DPC list
        PLIST_ENTRY head = &prcb->DpcListHead[prcb->DpcQueueDepth > 0 ? 0 : 0];
        // Note: DpcListHead is a LIST_ENTRY; the actual queue may be
        // in a separate structure depending on Windows version

        for (PLIST_ENTRY entry = head->Flink; entry != head; entry = entry->Flink) {
            PKDPC Dpc = CONTAINING_RECORD(entry, KDPC, DpcListEntry);

            // Check if DeferredRoutine points to a known module
            if (!IsAddressInKnownSystemModule(Dpc->DeferredRoutine)) {
                ReportAnomalousDpc(Dpc, proc);
            }

            // Check DPC rate — if a module queues DPCs at an abnormal rate,
            // it may be using DPCs for timing or synchronization
            static volatile ULONG DpcCountByModule[256] = {0};
            // ... track and report
        }

        KeLowerIrql(oldIrql);
        KeRevertToUserAffinityThread();
    }

    return STATUS_SUCCESS;
}
```

### 8.3 Detecting DPC-based Timing Attacks

Cheat engines sometimes use DPCs for precise timing (e.g., for DMA attacks or memory scanning):

```c
// Monitor DPC rates per processor
// Normal system: ~100-1000 DPCs/sec per processor
// Cheat engine: May queue 10,000+ DPCs/sec

typedef struct _DPC_RATE_TRACKER {
    ULONG ProcessorNumber;
    ULONG64 LastCheckTick;
    ULONG DpcCount;
    ULONG DpcRate;  // DPCs per second
} DPC_RATE_TRACKER;

#define DPC_RATE_THRESHOLD 5000  // DPCs/sec — suspicious if exceeded

VOID MonitorDpcRate(PKDPC Dpc, PVOID DeferredContext, PVOID SysArg1, PVOID SysArg2)
{
    DPC_RATE_TRACKER* tracker = (DPC_RATE_TRACKER*)DeferredContext;
    tracker->DpcCount++;

    ULONG64 currentTick = KeQueryPerformanceCounter(NULL).QuadPart;
    ULONG64 elapsed = currentTick - tracker->LastCheckTick;

    if (elapsed >= KeQueryTimeIncrement()) {
        tracker->DpcRate = (ULONG)(tracker->DpcCount * 10000000ULL / elapsed);

        if (tracker->DpcRate > DPC_RATE_THRESHOLD) {
            ReportHighDpcRate(tracker);
        }

        tracker->DpcCount = 0;
        tracker->LastCheckTick = currentTick;
    }
}
```

---

## 9. Object Reference/Dereference Anomalies

### 9.1 Detecting Abnormal Handle Open Rates

```c
// Monitor ObReferenceObjectByHandle calls for the game process
// This detects tools that rapidly open/close handles to the game

typedef struct _PROCESS_HANDLE_TRACKER {
    PEPROCESS GameProcess;
    ULONG64 LastHandleOpenTick;
    ULONG HandleOpenCount;
    ULONG HandleOpenRate;  // Opens per second
} PROCESS_HANDLE_TRACKER;

#define HANDLE_OPEN_RATE_THRESHOLD 100  // Opens/sec — suspicious

// Hook or callback-based detection
// Register a ObRegisterCallbacks pre-operation callback:

OB_PREOP_CALLBACK_STATUS HandlePreOperationCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    if (OperationInformation->ObjectType != *PsProcessType)
        return OB_PREOP_SUCCESS;

    PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;

    if (targetProcess == GameProcess) {
        // Track handle open rate
        PPROCESS_HANDLE_TRACKER tracker = (PPROCESS_HANDLE_TRACKER)RegistrationContext;
        tracker->HandleOpenCount++;

        ULONG64 currentTick = KeQueryPerformanceCounter(NULL).QuadPart;
        ULONG64 elapsed = currentTick - tracker->LastHandleOpenTick;

        if (elapsed >= KeQueryTimeIncrement()) {
            tracker->HandleOpenRate = (ULONG)(tracker->HandleOpenCount * 10000000ULL / elapsed);

            if (tracker->HandleOpenRate > HANDLE_OPEN_RATE_THRESHOLD) {
                // Get the process that's opening handles
                PEPROCESS opener = PsGetCurrentProcess();
                ReportAbnormalHandleRate(opener, tracker);
            }

            tracker->HandleOpenCount = 0;
            tracker->LastHandleOpenTick = currentTick;
        }
    }

    return OB_PREOP_SUCCESS;
}

// Register the callback:
NTSTATUS RegisterHandleMonitor(PEPROCESS GameProcess)
{
    OB_CALLBACK_REGISTRATION callbackReg = { 0 };
    OB_OPERATION_REGISTRATION operationReg = { 0 };

    operationReg.ObjectType = PsProcessType;
    operationReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationReg.PreOperation = HandlePreOperationCallback;
    operationReg.PostOperation = NULL;

    callbackReg.Version = OB_FLT_REGISTRATION_VERSION;
    callbackReg.OperationCount = 1;
    callbackReg.RegistrationContext = &HandleTracker;
    callbackReg.OperationRegistration = &operationReg;

    UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"321000");  // Below most anti-cheats

    return ObRegisterCallbacks(&callbackReg, &CallbackHandle);
}
```

### 9.2 Detecting Kernel-Mode Handle Manipulation

```c
// Detect ZwOpenProcess calls from kernel drivers
// This catches tools that open handles directly from kernel

// Method: Hook ZwOpenProcess or use minifilter
// IRQL: PASSIVE_LEVEL for ZwOpenProcess

// Alternative: Monitor handle table growth rate
// A process whose handle table grows rapidly is suspicious

typedef struct _HANDLE_TABLE_GROWTH_TRACKER {
    HANDLE ProcessId;
    ULONG LastHandleCount;
    ULONG64 LastCheckTime;
    ULONG GrowthRate;  // Handles per second
} HANDLE_TABLE_GROWTH_TRACKER;

VOID MonitorHandleTableGrowth(PEPROCESS Process)
{
    PHANDLE_TABLE ObjectTable = *(PHANDLE_TABLE*)((PUCHAR)Process + EPROCESS_ObjectTable_Offset);
    ULONG currentHandleCount = ObjectTable->NextHandleNeedingPool;

    // Compare with previous count
    // If growing > 100 handles/sec, flag it
}
```

---

## 10. Driver Signature Enforcement (DSE) Bypass Detection

### 10.1 Checking Boot Configuration

```c
// Check if test signing is enabled (allows unsigned drivers)
// SystemBootEnvironmentInformation = 0x59

typedef struct _SYSTEM_BOOT_ENVIRONMENT_INFORMATION {
    GUID BootIdentifier;
    ULONG64 FirmwareType;
    ULONG64 BootFlags;
    // ... more fields
} SYSTEM_BOOT_ENVIRONMENT_INFORMATION;

BOOLEAN IsTestSigningEnabled(void)
{
    SYSTEM_BOOT_ENVIRONMENT_INFORMATION bootInfo;
    NTSTATUS status = NtQuerySystemInformation(
        SystemBootEnvironmentInformation,  // 0x59
        &bootInfo,
        sizeof(bootInfo),
        NULL
    );

    if (!NT_SUCCESS(status)) return FALSE;

    // Check for TESTSIGNING boot option
    // This is also visible in BCD: {globalsettings} testsigning Yes
    // The exact flag location varies by Windows version

    // Alternative: Check the CI.dll g_CiOptions variable
    return CheckCiOptionsForTestSigning();
}
```

### 10.2 Detecting DSE Patching via CiValidateImageHeader

On Windows 10+, Driver Signature Enforcement is enforced by `ci.dll` (Code Integrity). The key variable is `g_CiOptions`:

```c
// g_CiOptions is a bitmask controlling CI behavior:
//   0x00000001 = CI_OPTION_ENABLE_DSE          (DSE enabled)
//   0x00000002 = CI_OPTION_ENABLE_DSE_FOR_TEST  (DSE for test signing)
//   0x00000004 = CI_OPTION_ENABLE_DSE_FOR_UMCI  (DSE for UMCI)
//   0x00000006 = CI_OPTIONS_DEFAULT             (default on Win10+)
//   0x00000000 = DSE_DISABLED                   (all checks disabled)

// To detect DSE patching:
// 1. Find ci.dll's base address (it's a known system module)
// 2. Locate g_CiOptions via pattern scan or export
// 3. Verify it matches expected value

ULONG GetCiOptions(void)
{
    // ci.dll is loaded in the system process
    UNICODE_STRING ciName = RTL_CONSTANT_STRING(L"ci.dll");
    PVOID ciBase = GetSystemModuleBase(&ciName);

    if (!ciBase) return (ULONG)-1;

    // g_CiOptions is typically found via a pattern scan
    // Pattern for Win10 21H2: 48 8B 05 ?? ?? ?? ?? 8B ?? ?? ?? ?? ?? 89
    // (mov rax, [g_CiOptions]; mov ..., [rax+...])

    PUCHAR patternAddr = FindPattern(ciBase, "g_CiOptions_Pattern");
    if (!patternAddr) return (ULONG)-1;

    // Read the value
    ULONG ciOptions = *(ULONG*)(patternAddr + g_CiOptions_Offset);
    return ciOptions;
}

BOOLEAN IsDsePatched(void)
{
    ULONG ciOptions = GetCiOptions();

    // If g_CiOptions is 0, DSE is completely disabled
    if (ciOptions == 0) {
        return TRUE;
    }

    // If the expected bits are cleared, DSE has been tampered with
    if (!(ciOptions & CI_OPTION_ENABLE_DSE)) {
        return TRUE;
    }

    return FALSE;
}
```

### 10.3 Detecting CiValidateImageHeader Callback Unregistration

Cheat drivers may unregister CI callbacks to bypass signature checks:

```c
// CiRegisterSiloMonitor was introduced in Win10 1703
// Earlier: CiRegisterCatRootCallback / CiRegisterFileVersionCallback

// The CI callback chain can be walked to detect unregistration
// This requires finding the callback list head in ci.dll

typedef struct _CI_CALLBACK_NODE {
    LIST_ENTRY ListEntry;
    PVOID CallbackFunction;
    PVOID Context;
    ULONG Flags;
} CI_CALLBACK_NODE;

BOOLEAN AreCiCallbacksIntact(void)
{
    // Find the CI callback list in ci.dll
    // This is version-dependent and requires reverse engineering

    // On Win10 21H2, the callback list is at a known offset from ci.dll base
    PLIST_ENTRY callbackList = (PLIST_ENTRY)((PUCHAR)ciBase + CI_CALLBACK_LIST_OFFSET);
    PLIST_ENTRY expectedCallbacks = GetExpectedCiCallbackList();

    // Compare the actual list against the expected list
    // If any expected callback is missing, it was unregistered
    for (PLIST_ENTRY expected = expectedCallbacks->Flink;
         expected != expectedCallbacks;
         expected = expected->Flink)
    {
        BOOLEAN found = FALSE;
        for (PLIST_ENTRY actual = callbackList->Flink;
             actual != callbackList;
             actual = actual->Flink)
        {
            if (CONTAINING_RECORD(actual, CI_CALLBACK_NODE, ListEntry)->CallbackFunction ==
                CONTAINING_RECORD(expected, CI_CALLBACK_NODE, ListEntry)->CallbackFunction)
            {
                found = TRUE;
                break;
            }
        }

        if (!found) {
            ReportMissingCiCallback(CONTAINING_RECORD(expected, CI_CALLBACK_NODE, ListEntry));
            return FALSE;
        }
    }

    return TRUE;
}
```

### 10.4 Detecting DSE Bypass via Boot Configuration

```c
// Check for common DSE bypass techniques:

// 1. Vulnerable driver loading (BYOVD — Bring Your Own Vulnerable Driver)
//    Tools load a signed but vulnerable driver to gain kernel access
//    Then use it to patch g_CiOptions or disable DSE

// 2. Hypervisor-based DSE bypass
//    Some cheats use a hypervisor to intercept CI calls
//    Detect via CPUID hypervisor presence check

BOOLEAN IsHypervisorPresent(void)
{
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);

    // Check hypervisor present bit (bit 31 of ECX)
    if (cpuInfo[2] & (1 << 31)) {
        return TRUE;
    }

    // Also check hypervisor vendor ID
    __cpuid(cpuInfo, 0x40000000);
    if (cpuInfo[0] >= 0x40000000) {
        char vendor[13];
        *(int*)&vendor[0] = cpuInfo[1];
        *(int*)&vendor[4] = cpuInfo[2];
        *(int*)&vendor[8] = cpuInfo[3];
        vendor[12] = '\0';

        // Known hypervisors used for cheating:
        // "KVMKVMKVM" — KVM
        // "Microsoft Hv" — Hyper-V (legitimate)
        // "VMwareVMware" — VMware (legitimate)
        // "XenVMMXenVMM" — Xen

        if (strncmp(vendor, "KVMKVMKVM", 12) == 0) {
            ReportSuspiciousHypervisor(vendor);
            return TRUE;
        }
    }

    return FALSE;
}

// 3. Check for known vulnerable drivers
//    Maintain a database of known vulnerable signed drivers
//    Cross-reference against loaded modules

typedef struct _VULNERABLE_DRIVER_ENTRY {
    WCHAR DriverName[64];
    ULONG TimeDateStamp;
    ULONG SizeOfImage;
    UCHAR Sha256[32];
} VULNERABLE_DRIVER_ENTRY;

// Known BYOVD drivers (partial list):
// - RTCore64.sys (MSI Afterburner) — CVE-2019-16098
// - DBUtil_2_3.sys (Dell) — CVE-2021-36276
// - AsIO.sys (ASUS) — Arbitrary physical memory read/write
// - WinRing0x64.sys (OpenHardwareMonitor) — Full kernel R/W
// - MsIo64.sys (MSI) — Arbitrary physical memory access

BOOLEAN IsVulnerableDriverLoaded(void)
{
    for (PLIST_ENTRY pEntry = PsLoadedModuleList->Flink;
         pEntry != PsLoadedModuleList;
         pEntry = pEntry->Flink)
    {
        PKLDR_DATA_TABLE_ENTRY pModule =
            CONTAINING_RECORD(pEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        for (ULONG i = 0; i < ARRAYSIZE(VulnerableDriverList); i++) {
            if (RtlEqualUnicodeString(&pModule->BaseDllName, &VulnerableDriverList[i].Name, TRUE)) {
                // Verify it's the vulnerable version (not patched)
                if (pModule->TimeDateStamp == VulnerableDriverList[i].VulnerableTimestamp) {
                    ReportVulnerableDriver(pModule);
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}
```

---

## 11. Cross-Technique Correlation Engine

### 11.1 Combining Signals for Higher Confidence

No single technique is sufficient. A robust anti-cheat correlates multiple signals:

```c
typedef enum _CHEAT_INDICATOR {
    CHEAT_INDICATOR_RWX_MEMORY           = 0x0001,
    CHEAT_INDICATOR_UNSIGNED_MODULE      = 0x0002,
    CHEAT_INDICATOR_SUSPICIOUS_THREAD    = 0x0004,
    CHEAT_INDICATOR_ABNORMAL_HANDLES     = 0x0008,
    CHEAT_INDICATOR_APC_INJECTION        = 0x0010,
    CHEAT_INDICATOR_CHEAT_POOL_TAG       = 0x0020,
    CHEAT_INDICATOR_ANOMALOUS_DPC        = 0x0040,
    CHEAT_INDICATOR_DSE_DISABLED         = 0x0080,
    CHEAT_INDICATOR_HYPERVISOR           = 0x0100,
    CHEAT_INDICATOR_VULNERABLE_DRIVER    = 0x0200,
    CHEAT_INDICATOR_NTDLL_HOOK           = 0x0400,
    CHEAT_INDICATOR_DISPATCH_HOOK        = 0x0800,
} CHEAT_INDICATOR;

#define CHEAT_CONFIDENCE_THRESHOLD 3  // Require 3+ indicators

typedef struct _CHEAT_DETECTION_RESULT {
    PEPROCESS SuspectProcess;
    ULONG IndicatorCount;
    CHEAT_INDICATOR Indicators;
    LARGE_INTEGER DetectionTime;
} CHEAT_DETECTION_RESULT;

VOID EvaluateCheatConfidence(PCHEAT_DETECTION_RESULT Result)
{
    ULONG count = __popcnt(Result->Indicators);

    if (count >= CHEAT_CONFIDENCE_THRESHOLD) {
        // High confidence — take action
        ReportCheatDetected(Result);
    } else if (count >= 2) {
        // Medium confidence — increase monitoring
        IncreaseMonitoringLevel(Result->SuspectProcess);
    } else {
        // Low confidence — log for later analysis
        LogSuspiciousActivity(Result);
    }
}
```

---

## 12. IRQL Quick Reference

| Operation | Max IRQL | Notes |
|---|---|---|
| VAD tree walking | `APC_LEVEL` | `MmGetVirtualForPhysical` requires ≤ APC_LEVEL |
| `MmCopyVirtualMemory` | `APC_LEVEL` | With `KernelMode`; `UserMode` requires `PASSIVE_LEVEL` |
| `PsGetContextThread` | `APC_LEVEL` | Must target a thread in the current process or use care |
| `ExEnumHandleTable` | `APC_LEVEL` | Callback runs at caller's IRQL |
| `ObRegisterCallbacks` | `PASSIVE_LEVEL` | Registration only; callbacks run at `PASSIVE_LEVEL` |
| `NtQuerySystemInformation` | `PASSIVE_LEVEL` | Most information classes require passive |
| Pool tag scanning (SystemPoolTagInformation) | `PASSIVE_LEVEL` | Via `NtQuerySystemInformation` |
| Direct pool memory scanning | `DISPATCH_LEVEL` | Physical memory mapping |
| DPC queue inspection | `DISPATCH_LEVEL` | Must raise IRQL on target processor |
| APC list walking | `APC_LEVEL` | Must be at or below APC level |
| `CiValidateImageHeader` | `PASSIVE_LEVEL` | CI operations require passive level |
| `ZwOpenProcess` | `PASSIVE_LEVEL` | Kernel mode handle operations |
| `KeInsertQueueApc` | `DISPATCH_LEVEL` | Can queue at dispatch, but user APCs need care |

---

## 13. Version Dependency Matrix

| Technique | Win7 | Win8.1 | Win10 1607 | Win10 21H2 | Win11 24H2 |
|---|---|---|---|---|---|
| VAD tree walking | ✅ | ✅ | ✅ | ✅ | ✅ (offsets changed) |
| `MmCopyVirtualMemory` | ❌ | ❌ | ✅ | ✅ | ✅ |
| `PsLoadedModuleList` | ✅ | ✅ | ✅ | ✅ | ✅ (offsets changed) |
| `ETHREAD.StartAddress` | ✅ | ✅ | ✅ | ✅ | ✅ (offset changed) |
| `ExEnumHandleTable` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `ObRegisterCallbacks` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `CiValidateImageHeader` | ❌ | ❌ | ✅ | ✅ | ✅ |
| `g_CiOptions` | ❌ | ❌ | ✅ | ✅ | ✅ (offset changed) |
| `SystemPoolTagInformation` | ✅ | ✅ | ✅ | ✅ | ✅ |
| `KiUserApcDispatcher` | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## 14. Common BSOD Codes and Causes

| Bug Check | Name | Common Cause in Anti-Cheat |
|---|---|---|
| 0xA | `IRQL_NOT_LESS_OR_EQUAL` | Accessing paged memory at elevated IRQL |
| 0x1E | `KMODE_EXCEPTION_NOT_HANDLED` | Unhandled exception in driver code |
| 0x50 | `PAGE_FAULT_IN_NONPAGED_AREA` | Dereferencing freed/invalid pointer |
| 0x7E | `SYSTEM_THREAD_EXCEPTION_NOT_HANDLED` | Exception in system thread |
| 0x9F | `DRIVER_POWER_STATE_FAILURE` | Power IRP handling error |
| 0x133 | `DPC_WATCHDOG_VIOLATION` | DPC running too long (from DPC scanning) |
| 0x139 | `KERNEL_SECURITY_CHECK_FAILURE` | Stack cookie corruption, invalid callback |
| 0x13A | `KERNEL_MODE_HEAP_CORRUPTION` | Pool corruption from double-free or overflow |
| 0x1E0 | `INVALID_LOCK_RELEASE` | Improper lock release during VAD/handle walking |
| 0x4000008A | `THREAD_STUCK_IN_DEVICE_DRIVER` | Infinite loop in driver dispatch |

---

## 15. Implementation Checklist

When implementing these techniques in a production anti-cheat driver:

- [ ] **Dynamic offset resolution**: Never hardcode struct offsets. Use `NtQuerySystemInformation`, `RtlGetVersion`, or pattern scanning.
- [ ] **IRQL validation**: Assert IRQL requirements at the start of each detection routine.
- [ ] **Exception handling**: Wrap all memory access in `__try`/`__except` (SEH) to prevent BSODs.
- [ ] **Reference counting**: Always `ObReferenceObject` before accessing EPROCESS/ETHREAD.
- [ ] **Synchronization**: Use `ExAcquirePushLockShared`/`Exclusive` for VAD access; `KeEnterCriticalRegion` for APC access.
- [ ] **Rate limiting**: Don't scan continuously. Use timer-based scanning with appropriate intervals.
- [ ] **False positive mitigation**: Whitelist known legitimate software (debuggers, overlays, etc.).
- [ ] **Tamper resistance**: Protect your own driver's code and data from modification.
- [ ] **Logging**: Use `WPP tracing` or `ETW` for detection events — never `DbgPrint` in production.
- [ ] **Testing**: Test on all supported Windows versions with Driver Verifier enabled.

---

*Document compiled for internal use. All offsets are approximate and must be verified against target Windows builds using WinDbg (`dt nt!_STRUCTURE_NAME`).*
