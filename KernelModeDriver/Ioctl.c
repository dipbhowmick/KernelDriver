#include "Ioctl.h"

NTSTATUS IoCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}
NTSTATUS IoClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}
NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	
	switch (IoGetCurrentIrpStackLocation(Irp)->Parameters.DeviceIoControl.IoControlCode)
	{
	case PROCESS_ID:
	{
		PPROCESS_ID_REQUEST Request = (PPROCESS_ID_REQUEST)Irp->AssociatedIrp.SystemBuffer;
		Irp->IoStatus.Status = KGetProcessId(
			Request->ProcessName, 
			&Request->ProcessId
		);
		Irp->IoStatus.Information = sizeof(PROCESS_ID_REQUEST);
		break;
	}

	
	case IMAGE_BASE:
	{
		PIMAGE_BASE_REQUEST Request = (PIMAGE_BASE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
		Irp->IoStatus.Status = KGetImageBase(
			Request->ProcessId,
			&Request->ImageBase
		);
		Irp->IoStatus.Information = sizeof(IMAGE_BASE_REQUEST);
		break;
	}
	
	case MODULE_BASE:
	{
		PMODULE_BASE_REQUEST Request = (PMODULE_BASE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
		Irp->IoStatus.Status = KGetModuleBase(
			Request->ProcessId,
			Request->ModuleName,
			&Request->ModuleBase,
			&Request->ModuleSize
		);
		Irp->IoStatus.Information = sizeof(MODULE_BASE_REQUEST);
		break;
	}
	
	case VM_QUERY:
	{
		PVM_QUERY_REQUEST Request = (PVM_QUERY_REQUEST)Irp->AssociatedIrp.SystemBuffer;
		Irp->IoStatus.Status = KQueryVirtualMemory(
			Request->ProcessId,
			Request->BaseAddress,
			&Request->MBI
		);
		Irp->IoStatus.Information = sizeof(VM_QUERY_REQUEST);
		break;
	}
		
	case VM_PROTECT:
	{
		PVM_PROTECT_REQUEST Request = (PVM_PROTECT_REQUEST)Irp->AssociatedIrp.SystemBuffer;
		Irp->IoStatus.Status = KProtectVirtualMemory(
			Request->ProcessId,
			&Request->BaseAddress,
			&Request->RegionSize, 
			Request->NewProtect,
			&Request->OldProtect
		);
		Irp->IoStatus.Information = sizeof(VM_PROTECT_REQUEST);
		break;
	}
	
	case VM_READ:
	{
		PVM_READ_WRITE_REQUEST Request = (PVM_READ_WRITE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
		Irp->IoStatus.Status = KReadWriteVirtualMemory(
			Request->ProcessId,
			Request->BaseAddress,
			Request->Buffer,
			Request->BufferSize,
			&Request->NumberOfBytesReadWrite,
			Read
		);
		Irp->IoStatus.Information = sizeof(VM_READ_WRITE_REQUEST);
		break;
	}

	case VM_WRITE:
	{
		PVM_READ_WRITE_REQUEST Request = (PVM_READ_WRITE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
		Irp->IoStatus.Status = KReadWriteVirtualMemory(
			Request->ProcessId,
			Request->BaseAddress,
			Request->Buffer,
			Request->BufferSize,
			&Request->NumberOfBytesReadWrite,
			Write
		);
		Irp->IoStatus.Information = sizeof(VM_READ_WRITE_REQUEST);
		break;
	}
	
	case VM_ALLOCATE:
	{
		PVM_ALLOCATE_REQUEST Request = (PVM_ALLOCATE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
		Irp->IoStatus.Status = KAllocateVirtualMemory(
			Request->ProcessId, 
			&Request->BaseAddress, 
			Request->ZeroBits, 
			&Request->RegionSize, 
			Request->AllocationType, 
			Request->Protect
		);
		Irp->IoStatus.Information = sizeof(VM_ALLOCATE_REQUEST);
		break;
	}
	
	case VM_FREE:
	{
		PVM_FREE_REQUEST Request = (PVM_FREE_REQUEST)Irp->AssociatedIrp.SystemBuffer;
		Irp->IoStatus.Status = KFreeVirtualMemory(
			Request->ProcessId,
			&Request->BaseAddress,
			&Request->RegionSize,
			Request->FreeType
		);
		Irp->IoStatus.Information = sizeof(VM_FREE_REQUEST);
		break;
	}

	//case CREATE_THREAD:
	//{
	//	break;
	//}

	default:
		Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		Irp->IoStatus.Information = 0;
		break;
	}

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}