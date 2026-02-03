#include <ntifs.h>
#include <fltKernel.h>

#include "../include/Filter.h"
#include "../include/Protector.h"

PFLT_FILTER flt_handle = NULL;

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	NTSTATUS st = STATUS_UNSUCCESSFUL;

	st = FltRegisterFilter(DriverObject, &registration, &flt_handle);
	if (!NT_SUCCESS(st))
		goto Exit;

	st = MiniFilterPortInitialize(flt_handle);
	if (!NT_SUCCESS(st))
		goto Unregister;

	st = ProtectorPortInitialize(flt_handle);
	if (!NT_SUCCESS(st))
		goto MiniPort;

	st = ProtectorInitializeCallbacks();
	if (!NT_SUCCESS(st))
		goto ProtectorPort;

	st = FltStartFiltering(flt_handle);
	if (!NT_SUCCESS(st))
		goto ObCallbacks;


	return STATUS_SUCCESS;

ObCallbacks:
	ProtectorUninitializeCallbacks();
ProtectorPort:
	ProtectorPortFinalize();
MiniPort:
	MiniFilterPortFinalize();
Unregister:
	if (flt_handle)
	{
		FltUnregisterFilter(flt_handle);
		flt_handle = NULL;
	}
Exit:
	return st;
}

VOID DriverUnload(
	_In_ PDRIVER_OBJECT driver_object)
{
	UNREFERENCED_PARAMETER(driver_object);

	ProtectorUninitializeCallbacks();
	MiniFilterPortFinalize();
	ProtectorPortFinalize();

	if (flt_handle)
	{
		FltUnregisterFilter(flt_handle);
		flt_handle = NULL;
	}
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS MiniFilterUnloadRoutine(
	_In_ FLT_FILTER_UNLOAD_FLAGS flags)
{
	UNREFERENCED_PARAMETER(flags);

	ProtectorUninitializeCallbacks();
	MiniFilterPortFinalize();
	ProtectorPortFinalize();

	if (flt_handle)
	{
		FltUnregisterFilter(flt_handle);
		flt_handle = NULL;
	}

	return STATUS_SUCCESS;
}