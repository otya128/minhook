/* Enough implementation of kernel32.dll to make this library work. */
#include "minkernel32.h"

void* __cdecl memcpy(void* _Dst, void const* _Src, size_t _Size)
{
    return RtlCopyMemory(_Dst, _Src, _Size);
}
void* __cdecl memset(
    _Out_writes_bytes_all_(_Size) void*  _Dst,
    _In_                          int    _Val,
    _In_                          size_t _Size
)
{
    return RtlFillMemory(_Dst, _Size, _Val);
}

VOID WINAPI SetLastError(_In_ DWORD dwErrCode)
{
    RtlSetLastWin32Error(dwErrCode);
}

VOID WINAPI BaseSetLastNTError(DWORD status)
{
    RtlSetLastWin32ErrorAndNtStatusFromNtStatus(status);
}

BOOL
WINAPI
CloseHandle(
    _In_ HANDLE hObject
)
{
    return NT_SUCCESS(NtClose(hObject));
}

HANDLE WINAPI GetCurrentProcess(void)
{
    return NtCurrentProcess();
}

BOOL
WINAPI
FlushInstructionCache(
    _In_ HANDLE hProcess,
    _In_reads_bytes_opt_(dwSize) LPCVOID lpBaseAddress,
    _In_ SIZE_T dwSize
)
{
    return NT_SUCCESS(NtFlushInstructionCache(hProcess, lpBaseAddress, dwSize));
}

HMODULE WINAPI GetModuleHandleW(LPCWSTR lpModuleName)
{
    UNICODE_STRING uni;
    HMODULE mod;
    RtlInitUnicodeString(&uni, lpModuleName);
    if (!NT_SUCCESS(LdrGetDllHandle(NULL, 0, &uni, &mod)))
    {
        return NULL;
    }
    return mod;
}
FARPROC WINAPI GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    ANSI_STRING proc_name;
    LPVOID proc;
    RtlInitAnsiString(&proc_name, lpProcName);
    if (!NT_SUCCESS(LdrGetProcedureAddress(hModule, &proc_name, 0, (void**)&proc)))
    {
        return NULL;
    }
    return proc;
}

typedef struct
{
    SIZE_T Count;
    SIZE_T Offset;
    THREADENTRY32 Snapshot[0];
} THREAD_SNAPSHOT;

static NTSTATUS AllocSection(SIZE_T Size, PHANDLE phSection)
{
    OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
    NTSTATUS Status;
    LARGE_INTEGER SSize;
    SSize.QuadPart = Size;

    Status = NtCreateSection(phSection,
        SECTION_ALL_ACCESS,
        NULL,
        &SSize,
        PAGE_READWRITE,
        SEC_COMMIT,
        NULL);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }
    return STATUS_SUCCESS;
}

static LPVOID MapSection(HANDLE hSection)
{
    LARGE_INTEGER SOffset;
    SOffset.QuadPart = 0;
    SIZE_T ViewSize = 0;
    LPVOID Snapshot = NULL;

    NTSTATUS Status = NtMapViewOfSection(hSection,
        NtCurrentProcess(),
        &Snapshot,
        0,
        0,
        &SOffset,
        &ViewSize,
        ViewShare,
        0,
        PAGE_READWRITE);
    if (!NT_SUCCESS(Status))
    {
        return NULL;
    }
    return Snapshot;
}

HANDLE
WINAPI
CreateToolhelp32Snapshot(
    DWORD dwFlags,
    DWORD th32ProcessID
)
{
    if (dwFlags != TH32CS_SNAPTHREAD || th32ProcessID != 0)
        return 0;
    SYSTEM_PROCESS_INFORMATION sys_info_stack;
    ULONG len = 0;
    ULONG sys_info_len = sizeof(sys_info_stack);
    PSYSTEM_PROCESS_INFORMATION sys_info = &sys_info_stack;
    NTSTATUS result = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x39/* SystemExtendedProcessInformation */, (PVOID)sys_info, sys_info_len, &len);
    sys_info_len = len;
    sys_info = (PSYSTEM_PROCESS_INFORMATION)RtlAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, sys_info_len);
    while (TRUE)
    {
        NTSTATUS result = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)0x39, (PVOID)sys_info, sys_info_len, &len);
        if (result == STATUS_INFO_LENGTH_MISMATCH)
        {
            sys_info_len = len + 1000;
            sys_info = (PSYSTEM_PROCESS_INFORMATION)RtlReAllocateHeap(RtlGetProcessHeap(), HEAP_ZERO_MEMORY, (PVOID)sys_info, sys_info_len);
        }
        else
            break;
    }
    PSYSTEM_PROCESS_INFORMATION cur = sys_info;
    SIZE_T count = 0;
    while (cur - sys_info < len)
    {
        PSYSTEM_EXTENDED_THREAD_INFORMATION threads = (PSYSTEM_EXTENDED_THREAD_INFORMATION)(cur + 1);
        count += cur->NumberOfThreads;
        if (cur->NextEntryOffset == 0)
            break;
        cur = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)cur + cur->NextEntryOffset);
    }
    HANDLE hSnap = NULL;
    if (!NT_SUCCESS(AllocSection(sizeof(THREAD_SNAPSHOT) + sizeof(THREADENTRY32) * count, &hSnap)))
    {
        goto exit;
    }

    THREAD_SNAPSHOT *snap = MapSection(hSnap);
    cur = sys_info;
    SIZE_T off = 0;
    while (cur - sys_info < len)
    {
        PSYSTEM_EXTENDED_THREAD_INFORMATION threads = (PSYSTEM_EXTENDED_THREAD_INFORMATION)(cur + 1);
        for (ULONG i = 0; i < cur->NumberOfThreads && off < count; i++)
        {
            snap->Snapshot[off].dwSize = sizeof(THREADENTRY32);
            snap->Snapshot[off].th32OwnerProcessID = HandleToUlong(threads[i].ThreadInfo.ClientId.UniqueProcess);
            snap->Snapshot[off].th32ThreadID = HandleToUlong(threads[i].ThreadInfo.ClientId.UniqueThread);
            snap->Snapshot[off].tpBasePri = threads[i].ThreadInfo.BasePriority;
            off++;
        }
        if (cur->NextEntryOffset == 0)
            break;
        cur = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)cur + cur->NextEntryOffset);
    }
    snap->Count = off;
    NtUnmapViewOfSection(NtCurrentProcess(), (PVOID)snap);
exit:
    RtlFreeHeap(RtlGetProcessHeap(), 0, sys_info);
    return hSnap;
}
BOOL
WINAPI
Thread32Next(
    HANDLE hSnapshot,
    LPTHREADENTRY32 lpte
)
{
    if (lpte->dwSize != sizeof(*lpte))
    {
        return FALSE;
    }
    THREAD_SNAPSHOT *snap = (THREAD_SNAPSHOT*)MapSection(hSnapshot);
    if (snap->Offset >= snap->Count)
    {
        NtUnmapViewOfSection(NtCurrentProcess(), (PVOID)snap);
        return FALSE;
    }
    *lpte = snap->Snapshot[snap->Offset];
    snap->Offset++;
    NtUnmapViewOfSection(NtCurrentProcess(), (PVOID)snap);
    return TRUE;
}

BOOL
WINAPI
Thread32First(
    HANDLE hSnapshot,
    LPTHREADENTRY32 lpte
)
{
    THREAD_SNAPSHOT *snap = (THREAD_SNAPSHOT*)MapSection(hSnapshot);
    snap->Offset = 0;
    NtUnmapViewOfSection(NtCurrentProcess(), (PVOID)snap);
    return Thread32Next(hSnapshot, lpte);
}

DWORD WINAPI GetCurrentThreadId(VOID)
{
    return HandleToUlong(((CLIENT_ID*)((LPBYTE)NtCurrentTeb() + 0x40 /* ClientId */))->UniqueThread);
}

DWORD WINAPI GetCurrentProcessId(VOID)
{
    return HandleToUlong(((CLIENT_ID*)((LPBYTE)NtCurrentTeb() + 0x40 /* ClientId */))->UniqueProcess);
}

PVOID WINAPI HeapAlloc(
    HANDLE Heap,
    ULONG Flags,
    SIZE_T Size
)
{
    return RtlAllocateHeap(Heap, Flags, Size);
}

BOOL
WINAPI
HeapFree(
    HANDLE Heap,
    DWORD Flags,
    LPVOID Address
)
{
    return RtlFreeHeap(Heap, Flags, Address);
}

PVOID WINAPI
HeapReAlloc(HANDLE Heap,
    ULONG Flags,
    PVOID Address,
    SIZE_T Size)
{
    return RtlReAllocateHeap(Heap, Flags, Address, Size);
}

/* ReactOS implementation */
PLARGE_INTEGER
WINAPI
BaseFormatTimeOut(OUT PLARGE_INTEGER Timeout,
    IN DWORD dwMilliseconds)
{
    /* Check if this is an infinite wait, which means no timeout argument */
    if (dwMilliseconds == INFINITE) return NULL;

    /* Otherwise, convert the time to NT Format */
    Timeout->QuadPart = dwMilliseconds * -10000LL;
    return Timeout;
}

/*
 * @implemented
 */
VOID
WINAPI
Sleep(IN DWORD dwMilliseconds)
{
    LARGE_INTEGER Time;
    PLARGE_INTEGER TimePtr;

    /* Convert the timeout */
    TimePtr = BaseFormatTimeOut(&Time, dwMilliseconds);
    if (!TimePtr)
    {
        /* Turn an infinite wait into a really long wait */
        Time.LowPart = 0;
        Time.HighPart = 0x80000000;
        TimePtr = &Time;
    }

    /* Do the delay */
    NtDelayExecution(FALSE, TimePtr);

    return;
}

HANDLE
WINAPI
HeapCreate(DWORD flOptions,
    SIZE_T dwInitialSize,
    SIZE_T dwMaximumSize)
{
    HANDLE hRet;
    ULONG Flags;

    Flags = (flOptions & (HEAP_GENERATE_EXCEPTIONS | HEAP_NO_SERIALIZE)) | HEAP_CLASS_1;

    /* Check if heap is growable and ensure max size is correct */
    if (dwMaximumSize == 0)
        Flags |= HEAP_GROWABLE;

    /* Call RTL Heap */
    hRet = RtlCreateHeap(Flags,
        NULL,
        dwMaximumSize,
        dwInitialSize,
        NULL,
        NULL);

    /* Set the last error if we failed, and return the pointer */
    if (!hRet) SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return hRet;
}

BOOL
WINAPI
HeapDestroy(HANDLE hHeap)
{
    /* Return TRUE if the heap was destroyed */
    if (!RtlDestroyHeap(hHeap)) return TRUE;

    /* Otherwise, we got the handle back, so fail */
    SetLastError(ERROR_INVALID_HANDLE);
    return FALSE;
}


/*
 * @implemented
 */
HANDLE
WINAPI
OpenThread(IN DWORD dwDesiredAccess,
    IN BOOL bInheritHandle,
    IN DWORD dwThreadId)
{
    NTSTATUS Status;
    HANDLE ThreadHandle;
    OBJECT_ATTRIBUTES ObjectAttributes;
    CLIENT_ID ClientId;

    ClientId.UniqueProcess = 0;
    ClientId.UniqueThread = ULongToHandle(dwThreadId);

    InitializeObjectAttributes(&ObjectAttributes,
        NULL,
        (bInheritHandle ? OBJ_INHERIT : 0),
        NULL,
        NULL);

    Status = NtOpenThread(&ThreadHandle,
        dwDesiredAccess,
        &ObjectAttributes,
        &ClientId);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return NULL;
    }

    return ThreadHandle;
}

/*
 * @implemented
 */
DWORD
WINAPI
ResumeThread(IN HANDLE hThread)
{
    ULONG PreviousResumeCount;
    NTSTATUS Status;

    Status = NtResumeThread(hThread, &PreviousResumeCount);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return -1;
    }

    return PreviousResumeCount;
}

/*
 * @implemented
 */
DWORD
WINAPI
SuspendThread(IN HANDLE hThread)
{
    ULONG PreviousSuspendCount;
    NTSTATUS Status;

    Status = NtSuspendThread(hThread, &PreviousSuspendCount);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return -1;
    }

    return PreviousSuspendCount;
}

/*
 * @implemented
 */
BOOL
WINAPI
GetThreadContext(IN HANDLE hThread,
    OUT LPCONTEXT lpContext)
{
    NTSTATUS Status;

    Status = NtGetContextThread(hThread, lpContext);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}

/*
 * @implemented
 */
BOOL
WINAPI
SetThreadContext(IN HANDLE hThread,
    IN CONST CONTEXT *lpContext)
{
    NTSTATUS Status;

    Status = NtSetContextThread(hThread, (PCONTEXT)lpContext);
    if (!NT_SUCCESS(Status))
    {
        BaseSetLastNTError(Status);
        return FALSE;
    }

    return TRUE;
}

VOID
WINAPI
GetSystemInfoInternal(IN PSYSTEM_BASIC_INFORMATION2 BasicInfo,
    IN PSYSTEM_PROCESSOR_INFORMATION ProcInfo,
    OUT LPSYSTEM_INFO SystemInfo)
{
    RtlZeroMemory(SystemInfo, sizeof(SYSTEM_INFO));
    SystemInfo->wProcessorArchitecture = ProcInfo->ProcessorArchitecture;
    SystemInfo->wReserved = 0;
    SystemInfo->dwPageSize = BasicInfo->PageSize;
    SystemInfo->lpMinimumApplicationAddress = (PVOID)BasicInfo->MinimumUserModeAddress;
    SystemInfo->lpMaximumApplicationAddress = (PVOID)BasicInfo->MaximumUserModeAddress;
    SystemInfo->dwActiveProcessorMask = BasicInfo->ActiveProcessorsAffinityMask;
    SystemInfo->dwNumberOfProcessors = BasicInfo->NumberOfProcessors;
    SystemInfo->wProcessorLevel = ProcInfo->ProcessorLevel;
    SystemInfo->wProcessorRevision = ProcInfo->ProcessorRevision;
    SystemInfo->dwAllocationGranularity = BasicInfo->AllocationGranularity;

    switch (ProcInfo->ProcessorArchitecture)
    {
    case PROCESSOR_ARCHITECTURE_INTEL:
        switch (ProcInfo->ProcessorLevel)
        {
        case 3:
            SystemInfo->dwProcessorType = PROCESSOR_INTEL_386;
            break;
        case 4:
            SystemInfo->dwProcessorType = PROCESSOR_INTEL_486;
            break;
        default:
            SystemInfo->dwProcessorType = PROCESSOR_INTEL_PENTIUM;
        }
        break;

    case PROCESSOR_ARCHITECTURE_AMD64:
        SystemInfo->dwProcessorType = PROCESSOR_AMD_X8664;
        break;

    case PROCESSOR_ARCHITECTURE_IA64:
        SystemInfo->dwProcessorType = PROCESSOR_INTEL_IA64;
        break;

    default:
        SystemInfo->dwProcessorType = 0;
        break;
    }

}

/*
 * @implemented
 */
VOID
WINAPI
GetSystemInfo(IN LPSYSTEM_INFO lpSystemInfo)
{
    SYSTEM_BASIC_INFORMATION2 BasicInfo;
    SYSTEM_PROCESSOR_INFORMATION ProcInfo;
    NTSTATUS Status;

    Status = NtQuerySystemInformation(SystemBasicInformation,
        &BasicInfo,
        sizeof(BasicInfo),
        0);
    if (!NT_SUCCESS(Status)) return;

    Status = NtQuerySystemInformation(SystemProcessorInformation,
        &ProcInfo,
        sizeof(ProcInfo),
        0);
    if (!NT_SUCCESS(Status)) return;

    GetSystemInfoInternal(&BasicInfo, &ProcInfo, lpSystemInfo);
}
/*
 * @implemented
 */
LPVOID
NTAPI
VirtualAllocEx(IN HANDLE hProcess,
    IN LPVOID lpAddress,
    IN SIZE_T dwSize,
    IN DWORD flAllocationType,
    IN DWORD flProtect)
{
    NTSTATUS Status;

    /* Handle any possible exceptions */
    _SEH2_TRY
    {
        /* Allocate the memory */
        Status = NtAllocateVirtualMemory(hProcess,
                                         &lpAddress,
                                         0,
                                         &dwSize,
                                         flAllocationType,
                                         flProtect);
    }
    _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER)
    {
        Status = _SEH2_GetExceptionCode();
    }
    _SEH2_END;

    /* Check for status */
    if (!NT_SUCCESS(Status))
    {
        /* We failed */
        BaseSetLastNTError(Status);
        return NULL;
    }

    /* Return the allocated address */
    return lpAddress;
}

/*
 * @implemented
 */
LPVOID
NTAPI
VirtualAlloc(IN LPVOID lpAddress,
    IN SIZE_T dwSize,
    IN DWORD flAllocationType,
    IN DWORD flProtect)
{
    /* Call the extended API */
    return VirtualAllocEx(GetCurrentProcess(),
        lpAddress,
        dwSize,
        flAllocationType,
        flProtect);
}
/*
 * @implemented
 */
BOOL
NTAPI
VirtualFreeEx(IN HANDLE hProcess,
    IN LPVOID lpAddress,
    IN SIZE_T dwSize,
    IN DWORD dwFreeType)
{
    NTSTATUS Status;

    /* Validate size and flags */
    if (!(dwSize) || !(dwFreeType & MEM_RELEASE))
    {
        /* Free the memory */
        Status = NtFreeVirtualMemory(hProcess,
            &lpAddress,
            &dwSize,
            dwFreeType);
        if (!NT_SUCCESS(Status))
        {
            /* We failed */
            BaseSetLastNTError(Status);
            return FALSE;
        }

        /* Return success */
        return TRUE;
    }

    /* Invalid combo */
    BaseSetLastNTError(STATUS_INVALID_PARAMETER);
    return FALSE;
}

/*
 * @implemented
 */
BOOL
NTAPI
VirtualFree(IN LPVOID lpAddress,
    IN SIZE_T dwSize,
    IN DWORD dwFreeType)
{
    /* Call the extended API */
    return VirtualFreeEx(GetCurrentProcess(),
        lpAddress,
        dwSize,
        dwFreeType);
}

/*
 * @implemented
 */
BOOL
NTAPI
VirtualProtect(IN LPVOID lpAddress,
    IN SIZE_T dwSize,
    IN DWORD flNewProtect,
    OUT PDWORD lpflOldProtect)
{
    /* Call the extended API */
    return VirtualProtectEx(GetCurrentProcess(),
        lpAddress,
        dwSize,
        flNewProtect,
        lpflOldProtect);
}

/*
 * @implemented
 */
BOOL
NTAPI
VirtualProtectEx(IN HANDLE hProcess,
    IN LPVOID lpAddress,
    IN SIZE_T dwSize,
    IN DWORD flNewProtect,
    OUT PDWORD lpflOldProtect)
{
    NTSTATUS Status;

    /* Change the protection */
    Status = NtProtectVirtualMemory(hProcess,
        &lpAddress,
        &dwSize,
        flNewProtect,
        (PULONG)lpflOldProtect);
    if (!NT_SUCCESS(Status))
    {
        /* We failed */
        BaseSetLastNTError(Status);
        return FALSE;
    }

    /* Return success */
    return TRUE;
}


/*
 * @implemented
 */
SIZE_T
NTAPI
VirtualQuery(IN LPCVOID lpAddress,
    OUT PMEMORY_BASIC_INFORMATION lpBuffer,
    IN SIZE_T dwLength)
{
    /* Call the extended API */
    return VirtualQueryEx(NtCurrentProcess(),
        lpAddress,
        lpBuffer,
        dwLength);
}

/*
 * @implemented
 */
SIZE_T
NTAPI
VirtualQueryEx(IN HANDLE hProcess,
    IN LPCVOID lpAddress,
    OUT PMEMORY_BASIC_INFORMATION lpBuffer,
    IN SIZE_T dwLength)
{
    NTSTATUS Status;
    SIZE_T ResultLength;

    /* Query basic information */
    Status = NtQueryVirtualMemory(hProcess,
        (LPVOID)lpAddress,
        MemoryBasicInformation,
        lpBuffer,
        dwLength,
        &ResultLength);
    if (!NT_SUCCESS(Status))
    {
        /* We failed */
        BaseSetLastNTError(Status);
        return 0;
    }

    /* Return the length returned */
    return ResultLength;
}
