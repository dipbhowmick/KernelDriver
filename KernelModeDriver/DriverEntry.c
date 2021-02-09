#include "pch.h"
//#include "Ioctl.h"

NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	UNREFERENCED_PARAMETER(pDriverObject);

	IoDeleteSymbolicLink(&dos);
	IoDeleteDevice(pDriverObject->DeviceObject);

	Print("Driver UnLoaded Successfully!");
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);

	RtlInitUnicodeString(&drv, DRIVER);
	RtlInitUnicodeString(&dev, DEVICE);
	RtlInitUnicodeString(&dos, DOSDEVICES);

	IoCreateDevice(pDriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	IoCreateSymbolicLink(&dos, &dev);

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = IoCreate;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = IoClose;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;

	pDriverObject->DriverUnload = UnloadDriver;

	pDriverObject->Flags |= DO_DIRECT_IO;
	pDriverObject->Flags &= ~DO_DEVICE_INITIALIZING;
	
	Print("Driver Loaded Successfully!");

	return STATUS_SUCCESS;
}