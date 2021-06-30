#pragma once
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#undef RtlCopyMemory
#undef RtlFillMemory
void* NTAPI RtlCopyMemory(
    _Out_writes_bytes_all_(_Size) void* _Dst,
    _In_reads_bytes_(_Size)       void const* _Src,
    _In_                          size_t      _Size
);
void* NTAPI RtlFillMemory(
    _Out_writes_bytes_all_(_Size) void*  _Dst,
    _In_                          size_t _Size,
    _In_                          int    _Val
);
VOID NTAPI RtlSetLastWin32Error(IN ULONG LastError);
VOID NTAPI RtlSetLastWin32ErrorAndNtStatusFromNtStatus(IN ULONG LastError);

typedef void *PRTL_HEAP_PARAMETERS;
NTSYSAPI
PVOID
NTAPI
RtlCreateHeap(
    IN ULONG Flags,
    IN PVOID HeapBase OPTIONAL,
    IN SIZE_T ReserveSize OPTIONAL,
    IN SIZE_T CommitSize OPTIONAL,
    IN PVOID Lock OPTIONAL,
    IN PRTL_HEAP_PARAMETERS Parameters OPTIONAL
);

#define HEAP_CLASS_1                    0x00001000

NTSYSAPI
PVOID
NTAPI
RtlDestroyHeap(
    IN PVOID HeapHandle
);
PVOID
NTAPI
RtlAllocateHeap(
    HANDLE Heap,
    ULONG Flags,
    SIZE_T Size
);

BOOLEAN
NTAPI
RtlFreeHeap(
    HANDLE Heap,
    ULONG Flags,
    PVOID Address
);
PVOID NTAPI
RtlReAllocateHeap(HANDLE Heap,
    ULONG Flags,
    PVOID Address,
    SIZE_T Size);

#define NtCurrentProcess()                      ((HANDLE)(LONG_PTR)-1)
NTSTATUS
NTAPI
NtFlushInstructionCache(
    _In_ HANDLE ProcessHandle,
    _In_ LPCVOID BaseAddress,
    _In_ SIZE_T NumberOfBytesToFlush
);
NTSTATUS
NTAPI
NtYieldExecution(VOID);

NTSYSCALLAPI NTSTATUS NTAPI NtProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID *BaseAddress,
    _In_ SIZE_T *NumberOfBytesToProtect,
    _In_ ULONG NewAccessProtection,
    _Out_ PULONG OldAccessProtection
);

NTSYSCALLAPI NTSTATUS NTAPI NtAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ _Outptr_result_buffer_(*RegionSize) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
);
NTSYSCALLAPI
NTSTATUS
NTAPI
NtFreeVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ __drv_freesMem(Mem) PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
);

typedef enum { MemoryBasicInformation } MEMORY_INFORMATION_CLASS;
NTSTATUS
NTAPI
NtQueryVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID Address,
    _In_ MEMORY_INFORMATION_CLASS VirtualMemoryInformationClass,
    _Out_ PVOID VirtualMemoryInformation,
    _In_ SIZE_T Length,
    _Out_opt_ PSIZE_T ResultLength
);
NTSYSCALLAPI
NTSTATUS
NTAPI
NtSetContextThread(
    _In_ HANDLE ThreadHandle,
    _In_ PCONTEXT Context
);

NTSTATUS
NTAPI
NtGetContextThread(
    _In_ HANDLE ThreadHandle,
    _Out_ PCONTEXT Context
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtSuspendThread(
    _In_ HANDLE ThreadHandle,
    _In_ PULONG PreviousSuspendCount
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenThread(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ CLIENT_ID *ClientId
);
NTSYSCALLAPI
NTSTATUS
NTAPI
NtResumeThread(
    _In_ HANDLE ThreadHandle,
    _Out_opt_ PULONG SuspendCount
);

typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION
{
    SYSTEM_THREAD_INFORMATION ThreadInfo;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID Win32StartAddress;
    PVOID TebBase;
    ULONG_PTR Reserved2;
    ULONG_PTR Reserved3;
    ULONG_PTR Reserved4;
} SYSTEM_EXTENDED_THREAD_INFORMATION, *PSYSTEM_EXTENDED_THREAD_INFORMATION;

NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateSection(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle
);
typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;
NTSYSCALLAPI
NTSTATUS
NTAPI
NtMapViewOfSection(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG AccessProtection
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtUnmapViewOfSection(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtDelayExecution(
    _In_ BOOLEAN Alertable,
    _In_ LARGE_INTEGER *Interval
);
#define NtCurrentPeb() (NtCurrentTeb()->ProcessEnvironmentBlock)
#if defined(_M_X64) || defined(__x86_64__)
#define RtlGetProcessHeap() (*(PVOID*)((LPBYTE)NtCurrentPeb() + 0x30))
#else
#define RtlGetProcessHeap() (*(PVOID*)((LPBYTE)NtCurrentPeb() + 0x18))
#endif
typedef struct _SYSTEM_BASIC_INFORMATION2
{
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG_PTR MinimumUserModeAddress;
    ULONG_PTR MaximumUserModeAddress;
    ULONG_PTR ActiveProcessorsAffinityMask;
    CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION2, *PSYSTEM_BASIC_INFORMATION2;
// Class 1
typedef struct _SYSTEM_PROCESSOR_INFORMATION
{
    USHORT ProcessorArchitecture;
    USHORT ProcessorLevel;
    USHORT ProcessorRevision;
#if (NTDDI_VERSION < NTDDI_WIN8)
    USHORT Reserved;
#else
    USHORT MaximumProcessors;
#endif
    ULONG ProcessorFeatureBits;
} SYSTEM_PROCESSOR_INFORMATION, *PSYSTEM_PROCESSOR_INFORMATION;

#define SystemProcessorInformation 1
NTSYSAPI NTSTATUS NTAPI LdrGetDllHandle(
    _In_opt_ PWSTR DllPath,
    _In_ PULONG DllCharacteristics,
    _In_ PUNICODE_STRING DllName,
    _Out_ PVOID *DllHandle
);

NTSYSAPI NTSTATUS NTAPI LdrGetProcedureAddress(
    _In_ PVOID BaseAddress,
    _In_ PANSI_STRING Name,
    _In_ ULONG Ordinal,
    _Out_ PVOID *ProcedureAddress
);
#define _SEH2_TRY __try
#define _SEH2_EXCEPT __except
#define _SEH2_GetExceptionCode GetExceptionCode
#define _SEH2_END
