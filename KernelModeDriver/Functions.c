#include "Functions.h"

NTSTATUS KGetProcessId (PWCH ProcessName, PULONGLONG ProcessId) 
{
	*ProcessId = 0;

	NTSTATUS Status;
	PVOID Info = NULL;
	ULONG InfoSize;	
	ULONG MaxThread = 0;
	
	do {
		if (Info) { ExFreePool(Info); }

		InfoSize = 0;
		Status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &InfoSize);
		if (!InfoSize) { return Status; }
		
		Info = NULL;
		Info = ExAllocatePool(NonPagedPool, InfoSize);
		if (Info == NULL) { return STATUS_MEMORY_NOT_ALLOCATED; }

		Status = ZwQuerySystemInformation(SystemProcessInformation, Info, InfoSize, &InfoSize);
		
	} while (Status == STATUS_INFO_LENGTH_MISMATCH);

	if (!NT_SUCCESS(Status))
	{
		ExFreePool(Info);
		return Status;
	}

	PSYSTEM_PROCESS_INFORMATION pProcess = (PSYSTEM_PROCESS_INFORMATION)Info;
	if (!pProcess)
	{
		ExFreePool(Info);
		return STATUS_RESOURCE_DATA_NOT_FOUND;
	}
	
	while (TRUE) {
		if (&pProcess->ImageName != NULL && pProcess->ImageName.Length == wcslen(ProcessName) * sizeof(WCHAR)) {
			if (memcmp(pProcess->ImageName.Buffer, ProcessName, wcslen(ProcessName) * sizeof(WCHAR)) == 0) {
				if (MaxThread < pProcess->NumberOfThreads) 
				{
					*ProcessId = (ULONGLONG)pProcess->UniqueProcessId;
					MaxThread = pProcess->NumberOfThreads;
				}
			}
		}
		if (!pProcess->NextEntryOffset) { break; }
		pProcess = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcess + pProcess->NextEntryOffset); 
	}
	ExFreePool(Info);
	if (*ProcessId) { return STATUS_SUCCESS; }
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS KGetImageBase(ULONGLONG ProcessId, PULONGLONG ImageBase)
{
	NTSTATUS Status;
	PEPROCESS Process = NULL;
	Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);
	if (NT_SUCCESS(Status) && Process) {
		KAPC_STATE apc = { 0 };
		KeStackAttachProcess(Process, &apc);
		*ImageBase = (ULONGLONG)PsGetProcessSectionBaseAddress(Process);
		KeUnstackDetachProcess(&apc);
		ObfDereferenceObject(Process);
	}
	return Status;
}

NTSTATUS KGetModuleBase (ULONGLONG ProcessId, PWCH ModuleName, PULONGLONG ModuleBase, PULONG ModuleSize)
{
	*ModuleBase = 0;
	*ModuleSize = 0;
	NTSTATUS Status;
	PEPROCESS Process;

	Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);
	if (!NT_SUCCESS(Status)) { return Status; }

	KeAttachProcess((PKPROCESS)Process);

	PPEB peb = PsGetProcessPeb(Process);

	if (!peb || !peb->Ldr || !peb->Ldr->Initialized)
	{
		KeDetachProcess();
		ObDereferenceObject(Process);
		return STATUS_RESOURCE_DATA_NOT_FOUND;
	}

	for (PLIST_ENTRY list = peb->Ldr->InLoadOrderModuleList.Flink;
		list != &peb->Ldr->InLoadOrderModuleList;
		list = list->Flink) 
	{
		PLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		if (&Entry->BaseDllName != NULL && Entry->BaseDllName.Length == wcslen(ModuleName) * sizeof(WCHAR))
		{
			if (memcmp(Entry->BaseDllName.Buffer, ModuleName, wcslen(ModuleName) * sizeof(WCHAR)) == 0)
			{
				*ModuleBase = (ULONGLONG)Entry->DllBase;
				*ModuleSize = Entry->SizeOfImage;
				break;
			}
		}
	}

	KeDetachProcess();
	ObDereferenceObject(Process);
	return STATUS_SUCCESS;
}

NTSTATUS KQueryVirtualMemory(ULONGLONG ProcessId, ULONGLONG BaseAddress, PMEMORY_BASIC_INFORMATION MBI)
{
	NTSTATUS Status;
	PEPROCESS Process = NULL;
	HANDLE ProcessHandle = NULL;
	Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);
	if (NT_SUCCESS(Status) && Process) {
		Status = ObOpenObjectByPointer(Process, 0, NULL, 0, 0, KernelMode, &ProcessHandle);
		if (NT_SUCCESS(Status) && ProcessHandle) {
			Status = ZwQueryVirtualMemory(ProcessHandle, (PVOID)BaseAddress, MemoryBasicInformation, (PVOID)MBI, sizeof(MEMORY_BASIC_INFORMATION), NULL);
			ZwClose(ProcessHandle);
		}
		ObfDereferenceObject(Process);
	}
	return Status;
}

NTSTATUS KProtectVirtualMemory(ULONGLONG ProcessId, PULONGLONG BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect)
{
	NTSTATUS Status;
	PEPROCESS Process = NULL;
	Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);
	if (NT_SUCCESS(Status) && Process) {
		KAPC_STATE apc;
		KeStackAttachProcess(Process, &apc);
		Status = ZwProtectVirtualMemory(ZwCurrentProcess(), (PVOID*)BaseAddress, RegionSize, NewProtect, OldProtect);
		KeUnstackDetachProcess(&apc);
		ObfDereferenceObject(Process);
	}
	return Status;
}

NTSTATUS KReadWriteVirtualMemory(ULONGLONG ProcessId, ULONGLONG BaseAddress, ULONGLONG Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesReadWrite, COPYMODE CopyMode)
{
	if ((ULONG_PTR)BaseAddress + BufferSize < (ULONG_PTR)BaseAddress ||
		(ULONG_PTR)Buffer + BufferSize < (ULONG_PTR)Buffer ||
		(ULONG_PTR)BaseAddress + BufferSize >(ULONG_PTR)MmHighestUserAddress ||
		(ULONG_PTR)Buffer + BufferSize >(ULONG_PTR)MmHighestUserAddress)
	{
		return STATUS_ACCESS_VIOLATION;
	}

	NTSTATUS Status = STATUS_SUCCESS;
	*NumberOfBytesReadWrite = 0;
	if (BufferSize != 0) {
		PEPROCESS Process = NULL;
		Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);
		if (NT_SUCCESS(Status) && Process) {
			if (CopyMode == Read) { Status = MmCopyVirtualMemory(Process, (PVOID)BaseAddress, PsGetCurrentProcess(), (PVOID)Buffer, BufferSize, UserMode, NumberOfBytesReadWrite); }
			if (CopyMode == Write) { Status = MmCopyVirtualMemory(PsGetCurrentProcess(), (PVOID)Buffer, Process, (PVOID)BaseAddress, BufferSize, UserMode, NumberOfBytesReadWrite); }
			ObfDereferenceObject(Process);
		}
	}

	return Status;
}

NTSTATUS KAllocateVirtualMemory(ULONGLONG ProcessId, PULONGLONG BaseAddress, ULONGLONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect)
{
	NTSTATUS Status;
	PEPROCESS Process = NULL;
	Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);
	if (NT_SUCCESS(Status) && Process) {
		KAPC_STATE apc = { 0 };
		KeStackAttachProcess(Process, &apc);
		Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID*)BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
		KeUnstackDetachProcess(&apc);
		ObfDereferenceObject(Process);
	}
	return Status;
}

NTSTATUS KFreeVirtualMemory(ULONGLONG ProcessId, PULONGLONG BaseAddress, PSIZE_T RegionSize, ULONG FreeType)
{
	NTSTATUS Status;
	PEPROCESS Process = NULL;
	Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);
	if (NT_SUCCESS(Status) && Process) {
		KAPC_STATE apc = { 0 };
		KeStackAttachProcess(Process, &apc);
		Status = ZwFreeVirtualMemory(ZwCurrentProcess(), (PVOID*)BaseAddress, RegionSize, FreeType);
		KeUnstackDetachProcess(&apc);
		ObfDereferenceObject(Process);
	}
	return Status;
}

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
)
{
	NTSTATUS Status;
	PEPROCESS Process = NULL;
	HANDLE ProcessHandle = NULL;
	Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);
	if (NT_SUCCESS(Status) && Process) {
		Status = ObOpenObjectByPointer(Process, 0, NULL, 0, 0, KernelMode, &ProcessHandle);
		if (NT_SUCCESS(Status) && ProcessHandle) {
			Status = NtCreateThreadEx();
			ZwClose(ProcessHandle);
		}
		ObfDereferenceObject(Process);
	}
	return Status;
}
*/