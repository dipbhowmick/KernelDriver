#pragma once
#include <iostream>
#include <Windows.h>

#define LOG_DRIVER FALSE

#if LOG_DRIVER
#define LOG(x, ...) std::printf("[DrvLog] " x "\n",__VA_ARGS__)
#define ERR(x, ...) std::printf("[DrvErr] " x "\n",__VA_ARGS__)
#else
#define LOG(x, ...)
#define ERR(x, ...)
#endif

#define PROCESS_ID		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x111, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IMAGE_BASE		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x222, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) 
#define MODULE_BASE		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x333, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) 
#define VM_QUERY		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x444, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define VM_PROTECT		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x555, METHOD_BUFFERED, FILE_SPECIAL_ACCESS) 
#define VM_READ			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x666, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define VM_WRITE		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x777, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define VM_ALLOCATE		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x888, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define VM_FREE			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x999, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
//#define CREATE_THREAD		CTL_CODE(FILE_DEVICE_UNKNOWN, 0x000, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _PROCESS_ID_REQUEST {
	WCHAR ProcessName[256];
	ULONGLONG ProcessId;
} PROCESS_ID_REQUEST, * PPROCESS_ID_REQUEST;

typedef struct _IMAGE_BASE_REQUEST {
	ULONGLONG ProcessId;
	ULONGLONG ImageBase;
} IMAGE_BASE_REQUEST, * PIMAGE_BASE_REQUEST;

typedef struct _MODULE_BASE_REQUEST {
	ULONGLONG ProcessId;
	WCHAR ModuleName[256];
	ULONGLONG ModuleBase;
	ULONG ModuleSize;
} MODULE_BASE_REQUEST, * PMODULE_BASE_REQUEST;

typedef struct _VM_QUERY_REQUEST {
	ULONGLONG ProcessId;
	ULONGLONG BaseAddress;
	MEMORY_BASIC_INFORMATION MBI;
} VM_QUERY_REQUEST, * PVM_QUERY_REQUEST;

typedef struct _VM_PROTECT_REQUEST {
	ULONGLONG ProcessId;
	ULONGLONG BaseAddress;
	SIZE_T RegionSize;
	ULONG NewProtect;
	ULONG OldProtect;
} VM_PROTECT_REQUEST, * PVM_PROTECT_REQUEST;

typedef struct _VM_READ_WRITE_REQUEST {
	ULONGLONG ProcessId;
	ULONGLONG BaseAddress;
	ULONGLONG Buffer;
	SIZE_T BufferSize;
	SIZE_T NumberOfBytesReadWrite;
} VM_READ_WRITE_REQUEST, * PVM_READ_WRITE_REQUEST;

typedef struct _VM_ALLOCATE_REQUEST {
	ULONGLONG ProcessId;
	ULONGLONG BaseAddress;
	ULONGLONG ZeroBits;
	SIZE_T RegionSize;
	ULONG AllocationType;
	ULONG Protect;
} VM_ALLOCATE_REQUEST, * PVM_ALLOCATE_REQUEST;

typedef struct _VM_FREE_REQUEST {
	ULONGLONG ProcessId;
	ULONGLONG BaseAddress;
	SIZE_T RegionSize;
	ULONG FreeType;
} VM_FREE_REQUEST, * PVM_FREE_REQUEST;

class KDriver
{
public:
	HANDLE hDriver = INVALID_HANDLE_VALUE;

	KDriver()
	{
		hDriver = CreateFileA("\\\\.\\itzdip", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
		if (hDriver == INVALID_HANDLE_VALUE)
			ERR("Cannot Get Driver Handle. [CreateFileA ErrorCode: %u]\n", GetLastError());
		else
			LOG("Driver Connected!");
	}
	
	void GetPID(
		PCWCH ProcessName, 
		PULONGLONG ProcessId
	)
	{
		PROCESS_ID_REQUEST Request = { 0 };

		if (hDriver == INVALID_HANDLE_VALUE) {
			ERR("Invalid Driver Handle!");
			return;
		}

		memcpy(Request.ProcessName, ProcessName, wcslen(ProcessName) * sizeof(WCHAR));

		LOG("REQUESTED PID FOR [ProcessName: %ls]", Request.ProcessName);
		if (!DeviceIoControl(hDriver, PROCESS_ID, &Request, sizeof(Request), &Request, sizeof(Request), NULL, NULL)) {
			ERR("DeviceIoControl ErrorCode:  %u\n", GetLastError());
		}
		else 
		{
			LOG("RECIVED [PID: %u]", Request.ProcessId);
		}
		

		*ProcessId = Request.ProcessId;
	}

	void GetImageBase(
		ULONGLONG ProcessId,
		PULONGLONG ImageBase
	)
	{
		IMAGE_BASE_REQUEST Request = { 0 };

		if (hDriver == INVALID_HANDLE_VALUE) {
			ERR("Invalid Driver Handle!");
			return;
		}

		Request.ProcessId = ProcessId;

		LOG("REQUESTED IMAGE BASE FOR [PID: %u]", Request.ProcessId);
		if (!DeviceIoControl(hDriver, IMAGE_BASE, &Request, sizeof(Request), &Request, sizeof(Request), NULL, NULL)) {
			ERR("DeviceIoControl ErrorCode:  %u\n", GetLastError());
		}
		else
		{
			LOG("RECIVED [ImageBase: %u]", Request.ImageBase);
		}

		*ImageBase = Request.ImageBase;
	}

	void GetModuleBase(
		ULONGLONG ProcessId, 
		PCWCH ModuleName, 
		PULONGLONG ModuleBase, 
		PULONG ModuleSize = NULL
	)
	{
		MODULE_BASE_REQUEST Request = { 0 };

		if (hDriver == INVALID_HANDLE_VALUE) {
			ERR("Invalid Driver Handle!");
			return;
		}

		Request.ProcessId = ProcessId;
		memcpy(Request.ModuleName, ModuleName, wcslen(ModuleName) * sizeof(WCHAR));
		
		LOG("REQUESTED MODULE BASE FOR [PID: %u] AND [ModuleName: %ls]", Request.ProcessId, Request.ModuleName);
		if (!DeviceIoControl(hDriver, MODULE_BASE, &Request, sizeof(Request), &Request, sizeof(Request), NULL, NULL)) {
			ERR("DeviceIoControl ErrorCode:  %u\n", GetLastError());
		}
		else
		{
			LOG("RECIVED [ModuleBase: %u] AND [ModuleSize: %u]", Request.ModuleBase, Request.ModuleSize);
		}

		*ModuleBase = Request.ModuleBase;
		if (ModuleSize) { *ModuleSize = Request.ModuleSize; }
	}

	void QueryVirtualMemory(
		ULONGLONG ProcessId,
		ULONGLONG BaseAddress,
		PMEMORY_BASIC_INFORMATION MBI
	)
	{
		VM_QUERY_REQUEST Request = { 0 };

		if (hDriver == INVALID_HANDLE_VALUE) {
			ERR("Invalid Driver Handle!");
			return;
		}

		Request.ProcessId = ProcessId;
		Request.BaseAddress = BaseAddress;

		LOG("REQUESTED QUERY VIRTUAL MEMORY FOR [PID : %u] AND [BaseAddress: %u]", Request.ProcessId, Request.BaseAddress);
		if (!DeviceIoControl(hDriver, VM_QUERY, &Request, sizeof(Request), &Request, sizeof(Request), NULL, NULL)) {
			ERR("DeviceIoControl ErrorCode:  %u\n", GetLastError());
		}
		else
		{
			LOG("RECIVED [AllocationBase: %u] [AllocationProtect: %u] [BaseAddress: %u] [RegionSize: %u] [State: %u] [Protect: %u] [Type: %u]",
				Request.MBI.AllocationBase,
				Request.MBI.AllocationProtect,
				Request.MBI.BaseAddress,
				Request.MBI.RegionSize,
				Request.MBI.State,
				Request.MBI.Protect,
				Request.MBI.Type);
		}

		*MBI = Request.MBI;
	}

	void ProtectVirtualMemory(
		ULONGLONG ProcessId,
		PULONGLONG BaseAddress,
		PSIZE_T RegionSize,
		ULONG NewProtect,
		PULONG OldProtect
	)
	{
		VM_PROTECT_REQUEST Request = { 0 };

		if (hDriver == INVALID_HANDLE_VALUE) {
			ERR("Invalid Driver Handle!");
			return;
		}

		Request.ProcessId = ProcessId;
		Request.BaseAddress = *BaseAddress;
		Request.RegionSize = *RegionSize;
		Request.NewProtect = NewProtect;

		LOG("REQUESTED PROTECT VIRTUAL MEMORY FOR [PID: %u] [BaseAddress: %u] [RegionSize: %u] [NewProtect: %u]", Request.ProcessId, Request.BaseAddress, Request.RegionSize, Request.NewProtect);
		if (!DeviceIoControl(hDriver, VM_PROTECT, &Request, sizeof(Request), &Request, sizeof(Request), NULL, NULL)) {
			ERR("DeviceIoControl ErrorCode:  %u\n", GetLastError());
		}
		else
		{
			LOG("RECIVED [BaseAddress: %u] [RegionSize: %u] [OldProtect: %u]", Request.BaseAddress, Request.RegionSize, Request.OldProtect);
		}

		*BaseAddress = Request.BaseAddress;
		*RegionSize = Request.RegionSize;
		*OldProtect = Request.OldProtect;
	}

	void ReadVirtualMemory(
		ULONGLONG ProcessId,
		ULONGLONG BaseAddress,
		PVOID Buffer,
		SIZE_T BufferSize,
		PSIZE_T NumberOfBytesReadWrite
	)
	{
		VM_READ_WRITE_REQUEST Request = { 0 };

		if (hDriver == INVALID_HANDLE_VALUE) {
			ERR("Invalid Driver Handle!");
			return;
		}

		Request.ProcessId = ProcessId;
		Request.BaseAddress = BaseAddress;
		Request.Buffer = (ULONGLONG)Buffer;
		Request.BufferSize = BufferSize;

		LOG("REQUESTED READ VIRTUAL MEMORY FOR [PID: %u] [BaseAddress: %u] [BufferSize: %u]", Request.ProcessId, Request.BaseAddress, Request.BufferSize);
		if (!DeviceIoControl(hDriver, VM_READ, &Request, sizeof(Request), &Request, sizeof(Request), NULL, NULL)) {
			ERR("DeviceIoControl ErrorCode:  %u\n", GetLastError());
		}
		else
		{
			LOG("RECIVED [NumberOfBytesRead: %u]", Request.NumberOfBytesReadWrite);
		}

		*NumberOfBytesReadWrite = Request.NumberOfBytesReadWrite;
	}

	void WriteVirtualMemory(
		ULONGLONG ProcessId,
		ULONGLONG BaseAddress,
		PVOID Buffer,
		SIZE_T BufferSize,
		PSIZE_T NumberOfBytesReadWrite
	)
	{
		VM_READ_WRITE_REQUEST Request = { 0 };

		if (hDriver == INVALID_HANDLE_VALUE) {
			ERR("Invalid Driver Handle!");
			return;
		}

		Request.ProcessId = ProcessId;
		Request.BaseAddress = BaseAddress;
		Request.Buffer = (ULONGLONG)Buffer;
		Request.BufferSize = BufferSize;

		LOG("REQUESTED WRITE VIRTUAL MEMORY FOR [PID: %u] [BaseAddress: %u] [BufferSize: %u]", Request.ProcessId, Request.BaseAddress, Request.BufferSize);
		if (!DeviceIoControl(hDriver, VM_WRITE, &Request, sizeof(Request), &Request, sizeof(Request), NULL, NULL)) {
			ERR("DeviceIoControl ErrorCode:  %u\n", GetLastError());
		}
		else
		{
			LOG("RECIVED [NumberOfBytesWrite: %u]", Request.NumberOfBytesReadWrite);
		}

		*NumberOfBytesReadWrite = Request.NumberOfBytesReadWrite;
	}

	void AllocateVirtualMemoryEx(
		LONGLONG ProcessId,
		PULONGLONG BaseAddress,
		PSIZE_T RegionSize,
		ULONG AllocationType,
		ULONG Protect,
		ULONGLONG ZeroBits = 0
	) 
	{
		VM_ALLOCATE_REQUEST Request = { 0 };

		if (hDriver == INVALID_HANDLE_VALUE) {
			ERR("Invalid Driver Handle!");
			return;
		}

		Request.ProcessId = ProcessId;
		Request.BaseAddress = *BaseAddress;
		Request.ZeroBits = ZeroBits;
		Request.RegionSize = *RegionSize;
		Request.AllocationType = AllocationType;
		Request.Protect = Protect;

		LOG("REQUESTED ALLOCATE VIRTUAL MEMORY FOR [PID: %u] [BaseAddress: %u] [RegionSize: %u]", Request.ProcessId, Request.BaseAddress, Request.RegionSize);
		if (!DeviceIoControl(hDriver, VM_ALLOCATE, &Request, sizeof(Request), &Request, sizeof(Request), NULL, NULL)) {
			ERR("DeviceIoControl ErrorCode:  %u\n", GetLastError());
		}
		else
		{
			LOG("RECIVED [BaseAddress: %u] [RegionSize: %u]", Request.BaseAddress, Request.RegionSize);
		}

		*BaseAddress = Request.BaseAddress;
		*RegionSize = Request.RegionSize;
	}

	void FreeVirtualMemoryEx(
		LONGLONG ProcessId,
		PULONGLONG BaseAddress,
		PSIZE_T RegionSize,
		ULONG FreeType
	)
	{
		VM_FREE_REQUEST Request = { 0 };

		if (hDriver == INVALID_HANDLE_VALUE) {
			ERR("Invalid Driver Handle!");
			return;
		}

		Request.ProcessId = ProcessId;
		Request.BaseAddress = *BaseAddress;
		Request.RegionSize = *RegionSize;
		Request.FreeType = FreeType;

		LOG("REQUESTED FREE VIRTUAL MEMORY FOR [PID: %u] [BaseAddress: %u] [RegionSize: %u]", Request.ProcessId, Request.BaseAddress, Request.RegionSize);
		if (!DeviceIoControl(hDriver, VM_FREE, &Request, sizeof(Request), &Request, sizeof(Request), NULL, NULL)) {
			ERR("DeviceIoControl ErrorCode:  %u\n", GetLastError());
		}
		else
		{
			LOG("RECIVED [BaseAddress: %u] [RegionSize: %u]", Request.BaseAddress, Request.RegionSize);
		}

		*BaseAddress = Request.BaseAddress;
		*RegionSize = Request.RegionSize;
	}

};

//extern KDriver Driver;
//KDriver Driver = Driver();

