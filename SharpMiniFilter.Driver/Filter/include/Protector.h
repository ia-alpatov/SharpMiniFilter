#pragma once
#include <ntifs.h>
#include "../include/ProtectorPort.h"


#define DANGEROUS_PROCESS_ACCESS (PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_SET_INFORMATION)
#define DANGEROUS_THREAD_ACCESS (THREAD_TERMINATE | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT | THREAD_SET_INFORMATION)


_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ProtectorInitializeCallbacks(void);
_IRQL_requires_(PASSIVE_LEVEL)
VOID ProtectorUninitializeCallbacks(void);
BOOLEAN ProtectorRulesContainsLocked(_In_ PLIST_ENTRY Head, _In_ PCUNICODE_STRING Name);
BOOLEAN ProtectorIsProcessCoveredByProtectList(_In_ PEPROCESS Process);
NTSTATUS ProtectorProtectPidNow(_In_ HANDLE Pid);
NTSTATUS ProtectorUnprotectPidNow(_In_ HANDLE Pid);
static BOOLEAN IsProcessProtected(PEPROCESS Process);
static  BOOLEAN
ProtectorIsCallerCreatorOfProcess(_In_ HANDLE CallerPid, _In_ PEPROCESS Eproc);


EXTERN_C PUCHAR PsGetProcessImageFileName(PEPROCESS Process);

typedef struct _PROCESS_PARENT_ENTRY
{
	LIST_ENTRY Link;
	HANDLE ChildPid;
	HANDLE ParentPid;
} PROCESS_PARENT_ENTRY, * PPROCESS_PARENT_ENTRY;

typedef struct _OBC_CALL_CONTEXT
{
	OB_OPERATION Operation;
	PVOID Object;
	POBJECT_TYPE ObjectType;
} OBC_CALL_CONTEXT, * POBC_CALL_CONTEXT;

typedef HANDLE(NTAPI* PFN_PsGetProcessInheritedFromUniqueProcessId)(_In_ PEPROCESS Process);
static PFN_PsGetProcessInheritedFromUniqueProcessId g_PsGetProcessInheritedFromUniqueProcessId = NULL;

#pragma comment(lib, "ntoskrnl.lib")

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
	PVOID       Object;
	ULONG_PTR   UniqueProcessId;
	ULONG_PTR   HandleValue;
	ULONG       GrantedAccess;
	USHORT      CreatorBackTraceIndex;
	USHORT      ObjectTypeIndex;
	ULONG       HandleAttributes;
	ULONG       Reserved;

} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];

} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

#ifndef SystemExtendedHandleInformation
#define SystemExtendedHandleInformation ((SYSTEM_INFORMATION_CLASS)64)
#endif

#ifndef _ZWQUERY_SYSTEM_INFORMATION_DECL
#define _ZWQUERY_SYSTEM_INFORMATION_DECL
NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_writes_bytes_to_opt_(SystemInformationLength, *ReturnLength) PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
);
#endif
