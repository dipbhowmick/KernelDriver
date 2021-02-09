#pragma once
#include "pch.h"

#if LOG
#define Print(x, ...) DbgPrintEx(0, 0,"[ITzDIP] " x, __VA_ARGS__)
#else
#define Print(x, ...)
#endif // LOG


NTSTATUS NTAPI MmCopyVirtualMemory(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

PVOID NTKERNELAPI PsGetProcessSectionBaseAddress(
	__in PEPROCESS Process
);

PPEB NTKERNELAPI PsGetProcessPeb(
	IN PEPROCESS Process
);

NTSTATUS NTSYSAPI NTAPI ZwProtectVirtualMemory(
	__in HANDLE ProcessHandle,
	__inout PVOID* BaseAddress,
	__inout PSIZE_T RegionSize,
	__in ULONG NewProtect,
	__out PULONG OldProtect
);

NTSTATUS WINAPI ZwQuerySystemInformation(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength
);
/*
NTSTATUS NTSYSCALLAPI NTAPI NtCreateThreadEx(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ PVOID StartRoutine, // PUSER_THREAD_START_ROUTINE
	_In_opt_ PVOID Argument,
	_In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
	_In_ SIZE_T ZeroBits,
	_In_ SIZE_T StackSize,
	_In_ SIZE_T MaximumStackSize,
	_In_opt_ PPS_ATTRIBUTE_LIST AttributeList
);
*/
NTSTATUS KGetProcessId(
	PWCH ProcessName, 
	PULONGLONG ProcessId
);

NTSTATUS KGetImageBase(
	ULONGLONG ProcessId, 
	PULONGLONG ImageBase
);

NTSTATUS KGetModuleBase(
	ULONGLONG ProcessId,
	PWCH ModuleName,
	PULONGLONG ModuleBase,
	PULONG ModuleSize
);

NTSTATUS KQueryVirtualMemory(
	ULONGLONG ProcessId,
	ULONGLONG BaseAddress,
	PMEMORY_BASIC_INFORMATION MBI
);

NTSTATUS KProtectVirtualMemory(
	ULONGLONG ProcessId, 
	PULONGLONG BaseAddress, 
	PSIZE_T RegionSize, 
	ULONG NewProtect, 
	PULONG OldProtect
);

NTSTATUS KReadWriteVirtualMemory(
	ULONGLONG ProcessId,
	ULONGLONG BaseAddress,
	ULONGLONG Buffer,
	SIZE_T BufferSize,
	PSIZE_T NumberOfBytesReadWrite,
	COPYMODE CopyMode
);

NTSTATUS KAllocateVirtualMemory(
	ULONGLONG ProcessId,
	PULONGLONG BaseAddress,
	ULONGLONG ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
);

NTSTATUS KFreeVirtualMemory(
	ULONGLONG ProcessId, 
	PULONGLONG BaseAddress, 
	PSIZE_T RegionSize, 
	ULONG FreeType
);

/*
NTSTATUS KCreateThreadEx(
	ULONGLONG ProcessId,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PVOID StartRoutine, // PUSER_THREAD_START_ROUTINE
	PVOID Argument,
	ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	PPS_ATTRIBUTE_LIST AttributeList,
	PHANDLE ThreadHandle
);
*/