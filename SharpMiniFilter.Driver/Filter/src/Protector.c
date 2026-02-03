#include <ntifs.h>
#include "../include/Protector.h"
#include "../include/ProtectorPort.h"
#include "../include/Common.h"
#include "../include/Utils.h"


FAST_MUTEX protector_RulesLock;
LIST_ENTRY protector_ProtectNames;
LIST_ENTRY protector_RejectNames;
volatile LONG protector_RulesReady = 0;

extern POBJECT_TYPE* PsProcessType;
extern POBJECT_TYPE* PsThreadType;

static VOID
ProtectorRevokeExistingUserHandlesToThreadsOfProcess(_In_ PEPROCESS Target)
{
	NTSTATUS st;
	ULONG bufLen = 1u << 18;
	PVOID buf = NULL;
	HANDLE targetPid = PsGetProcessId(Target);

	for (;;) {
		buf = ExAllocatePoolZero(NonPagedPoolNx, bufLen, 'hTOB');
		if (!buf) return;
		st = ZwQuerySystemInformation(SystemExtendedHandleInformation, buf, bufLen, &bufLen);
		if (st == STATUS_INVALID_INFO_CLASS) { ExFreePoolWithTag(buf, 'hTOB'); return; }
		if (st == STATUS_INFO_LENGTH_MISMATCH) { ExFreePoolWithTag(buf, 'hTOB'); buf = NULL; bufLen <<= 1; if (bufLen > (1u << 24)) return; continue; }
		if (!NT_SUCCESS(st)) { ExFreePoolWithTag(buf, 'hTOB'); return; }
		break;
	}

	const ULONG safeThreadMask = SYNCHRONIZE | READ_CONTROL | THREAD_QUERY_LIMITED_INFORMATION;

	PSYSTEM_HANDLE_INFORMATION_EX hi = (PSYSTEM_HANDLE_INFORMATION_EX)buf;
	for (ULONG_PTR i = 0; i < hi->NumberOfHandles; ++i) {
		const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* h = &hi->Handles[i];

		if ((HANDLE)h->UniqueProcessId == targetPid) continue;

		if (!NT_SUCCESS(ObReferenceObjectByPointer((PVOID)h->Object, 0, *PsThreadType, KernelMode)))
			continue;

		PETHREAD th = (PETHREAD)h->Object;
		PEPROCESS ownerProc = IoThreadToProcess(th);
		ObDereferenceObject(th);

		if (ownerProc != Target) continue;
		if ((h->GrantedAccess & ~safeThreadMask) == 0) continue;

		if (ProtectorIsCriticalOwnerByPid((HANDLE)h->UniqueProcessId)) continue;

		CLIENT_ID cid = { 0 };
		cid.UniqueProcess = (HANDLE)h->UniqueProcessId;
		OBJECT_ATTRIBUTES oa; InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
		HANDLE owner = NULL;
		st = ZwOpenProcess(&owner, PROCESS_DUP_HANDLE, &oa, &cid);
		if (NT_SUCCESS(st)) {
			ZwDuplicateObject(owner, (HANDLE)h->HandleValue, NULL, NULL, 0, 0, DUPLICATE_CLOSE_SOURCE);
			ZwClose(owner);
		}
	}

	ExFreePoolWithTag(buf, 'hTOB');
}



static VOID
ProtectorRevokeExistingUserHandlesToProcess(_In_ PEPROCESS Target)
{
	NTSTATUS st;
	ULONG bufLen = 1 << 18;
	PVOID buf = NULL;

	HANDLE targetPid = PsGetProcessId(Target);

	for (;;) {
		buf = ExAllocatePoolZero(NonPagedPoolNx, bufLen, 'hTOB');
		if (!buf) return;
		st = ZwQuerySystemInformation(SystemExtendedHandleInformation, buf, bufLen, &bufLen);
		if (st == STATUS_INVALID_INFO_CLASS) {
			ExFreePoolWithTag(buf, 'hTOB'); buf = NULL;
			return;
		}
		if (st == STATUS_INFO_LENGTH_MISMATCH) {
			ExFreePoolWithTag(buf, 'hTOB');
			buf = NULL;
			bufLen <<= 1;
			if (bufLen > (1u << 24)) 
				return;
			continue;

		}
		if (!NT_SUCCESS(st)) {
			ExFreePoolWithTag(buf, 'hTOB');
			return;

		}
		break;

	}

	PSYSTEM_HANDLE_INFORMATION_EX hi = (PSYSTEM_HANDLE_INFORMATION_EX)buf;
	for (ULONG_PTR i = 0; i < hi->NumberOfHandles; ++i) {
		const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* h = &hi->Handles[i];

		if (h->Object != Target)
			continue;

		if ((HANDLE)h->UniqueProcessId == targetPid)
			continue;

		const ULONG safeMask = SYNCHRONIZE | READ_CONTROL | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;
		if ((h->GrantedAccess & ~safeMask) == 0)
			continue;

		if (ProtectorIsCriticalOwnerByPid((HANDLE)h->UniqueProcessId))
			continue;


		CLIENT_ID cid = { 0 };
		cid.UniqueProcess = (HANDLE)h->UniqueProcessId;
		cid.UniqueThread = 0;

		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

		HANDLE owner = NULL;
		st = ZwOpenProcess(&owner, PROCESS_DUP_HANDLE, &oa, &cid);
		if (NT_SUCCESS(st)) {
			HANDLE src = (HANDLE)h->HandleValue;
			ZwDuplicateObject(owner, src, NULL, NULL, 0, 0, DUPLICATE_CLOSE_SOURCE);
			ZwClose(owner);

		}

	}

	ExFreePoolWithTag(buf, 'hTOB');
}

static __forceinline BOOLEAN
ProtectorIsCallerCreatorOfProcess(_In_ HANDLE CallerPid, _In_ PEPROCESS Eproc)
{
	if (g_PsGetProcessInheritedFromUniqueProcessId)
	{
		HANDLE parent = g_PsGetProcessInheritedFromUniqueProcessId(Eproc);
		return (parent == CallerPid);
	}

	const HANDLE childPid = PsGetProcessId(Eproc);
	BOOLEAN hit = FALSE;
	ExAcquireFastMutex(&protector_ProcessParentLock);
	for (PLIST_ENTRY it = protector_ProcessParentList.Flink; it != &protector_ProcessParentList; it = it->Flink)
	{
		PPROCESS_PARENT_ENTRY entry = CONTAINING_RECORD(it, PROCESS_PARENT_ENTRY, Link);
		if (entry->ChildPid == childPid && entry->ParentPid == CallerPid)
		{
			hit = TRUE;
			break;
		}
	}
	ExReleaseFastMutex(&protector_ProcessParentLock);
	return hit;
}

static VOID ProtectorFreeCallContext(_Inout_ POB_POST_OPERATION_INFORMATION PostInfo)
{
	POBC_CALL_CONTEXT ctx = (POBC_CALL_CONTEXT)PostInfo->CallContext;
	if (!ctx)
		return;
	ExFreePoolWithTag(ctx, 'cCbO');
}

static BOOLEAN ProtectorIsCriticalOwnerByPid(_In_ HANDLE OwnerPid)
{
	PEPROCESS pe = NULL;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(OwnerPid, &pe)))
		return FALSE;

	const char* name = (const char*)PsGetProcessImageFileName(pe);
	BOOLEAN crit = FALSE;

	if (name) {
		crit |= ProtectorStrEqIgnoreCase16(name, "SYSTEM");
		crit |= ProtectorStrEqIgnoreCase16(name, "CSRSS.EXE");
		crit |= ProtectorStrEqIgnoreCase16(name, "WINLOGON.EXE");
		crit |= ProtectorStrEqIgnoreCase16(name, "WININIT.EXE");
		crit |= ProtectorStrEqIgnoreCase16(name, "SERVICES.EXE");
		crit |= ProtectorStrEqIgnoreCase16(name, "LSASS.EXE");
		crit |= ProtectorStrEqIgnoreCase16(name, "SMSS.EXE");

		crit |= ProtectorStrEqIgnoreCase16(name, "SPOOLSV.EXE");
		crit |= ProtectorStrEqIgnoreCase16(name, "SVCHOST.EXE");

		if (IsProcessProtected(pe))
			crit = TRUE;
	}

	ObDereferenceObject(pe);
	return crit;
}

static BOOLEAN ProtectorIsTrustedSystemCaller(void)
{
	const char* name = (const char*)PsGetProcessImageFileName(PsGetCurrentProcess());
	if (!name)
		return FALSE;

	if (ProtectorStrEqIgnoreCase16(name, "CSRSS.EXE"))
		return TRUE;
	if (ProtectorStrEqIgnoreCase16(name, "WINLOGON.EXE"))
		return TRUE;
	if (ProtectorStrEqIgnoreCase16(name, "WININIT.EXE"))
		return TRUE;
	if (ProtectorStrEqIgnoreCase16(name, "SERVICES.EXE"))
		return TRUE;
	if (ProtectorStrEqIgnoreCase16(name, "LSASS.EXE"))
		return TRUE;

	return FALSE;
}

static BOOLEAN IsProcessProtected(PEPROCESS Process)
{
	BOOLEAN found = FALSE;
	ExAcquireFastMutex(&protector_ProtectedProcessListLock);
	for (PLIST_ENTRY it = protector_ProtectedProcessList.Flink; it != &protector_ProtectedProcessList; it = it->Flink)
	{
		PPROTECTED_PROCESS_ENTRY entry = CONTAINING_RECORD(it, PROTECTED_PROCESS_ENTRY, Link);
		if (entry->Process == Process)
		{
			found = TRUE;
			break;
		}
	}
	ExReleaseFastMutex(&protector_ProtectedProcessListLock);
	return found;
}


static HANDLE GetProcessParentPid(_In_ PEPROCESS Process)
{
	HANDLE parentPid = NULL;

	if (g_PsGetProcessInheritedFromUniqueProcessId)
	{
		parentPid = g_PsGetProcessInheritedFromUniqueProcessId(Process);
	}
	else
	{
		HANDLE childPid = PsGetProcessId(Process);
		ExAcquireFastMutex(&protector_ProcessParentLock);
		for (PLIST_ENTRY it = protector_ProcessParentList.Flink;
			it != &protector_ProcessParentList;
			it = it->Flink)
		{
			PPROCESS_PARENT_ENTRY entry = CONTAINING_RECORD(it, PROCESS_PARENT_ENTRY, Link);
			if (entry->ChildPid == childPid)
			{
				parentPid = entry->ParentPid;
				break;
			}
		}
		ExReleaseFastMutex(&protector_ProcessParentLock);
	}

	return parentPid;
}

NTSTATUS ProtectorProtectPidNow(_In_ HANDLE Pid)
{
	PEPROCESS e = NULL;
	NTSTATUS st = PsLookupProcessByProcessId(Pid, &e);
	if (!NT_SUCCESS(st))
		return st;

	if (IsProcessProtected(e))
	{
		ObDereferenceObject(e);
		return STATUS_SUCCESS;
	}

	PPROTECTED_PROCESS_ENTRY p = ExAllocatePoolZero(NonPagedPoolNx, sizeof(*p), 'PPrO');
	if (!p)
	{
		ObDereferenceObject(e);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	p->Process = e;

	ExAcquireFastMutex(&protector_ProtectedProcessListLock);
	InsertTailList(&protector_ProtectedProcessList, &p->Link);
	ExReleaseFastMutex(&protector_ProtectedProcessListLock);

	ProtectorRevokeExistingUserHandlesToProcess(e);
	ProtectorRevokeExistingUserHandlesToThreadsOfProcess(e);


	return STATUS_SUCCESS;
}

NTSTATUS ProtectorUnprotectPidNow(_In_ HANDLE Pid)
{
	NTSTATUS st = STATUS_NOT_FOUND;

	(void)ProtectorRulesRemoveProtectPid(HandleToULong(Pid));

	ExAcquireFastMutex(&protector_ProtectedProcessListLock);
	for (PLIST_ENTRY it = protector_ProtectedProcessList.Flink; it != &protector_ProtectedProcessList;)
	{
		PPROTECTED_PROCESS_ENTRY e = CONTAINING_RECORD(it, PROTECTED_PROCESS_ENTRY, Link);
		PLIST_ENTRY next = it->Flink;
		if (PsGetProcessId(e->Process) == Pid)
		{
			RemoveEntryList(&e->Link);
			ExReleaseFastMutex(&protector_ProtectedProcessListLock);

			ObDereferenceObject(e->Process);
			ExFreePoolWithTag(e, 'PPrO');
			return STATUS_SUCCESS;
		}
		it = next;
	}
	ExReleaseFastMutex(&protector_ProtectedProcessListLock);
	return st;
}

static VOID ProtectorQueryPolicy(_In_ PEPROCESS Eproc, _Out_ PBOOLEAN OutProtect, _Out_ PBOOLEAN OutReject)
{
	const char* an = (const char*)PsGetProcessImageFileName(Eproc);
	ANSI_STRING a;
	UNICODE_STRING u = { 0 }, up = { 0 };

	RtlInitAnsiString(&a, an ? an : "");

	if (!NT_SUCCESS(RtlAnsiStringToUnicodeString(&u, &a, TRUE)))
		return;

	if (!NT_SUCCESS(RtlUpcaseUnicodeString(&up, &u, TRUE)))
	{
		RtlFreeUnicodeString(&u);
		return;
	}

	const BOOLEAN inProtectName = ProtectorIsNameListed(&up, TRUE);
	const BOOLEAN inRejectName = ProtectorIsNameListed(&up, FALSE);

	HANDLE pid = PsGetProcessId(Eproc);
	const BOOLEAN inProtectPid = ProtectorIsPIDListed(pid, TRUE);
	const BOOLEAN inRejectPid = ProtectorIsPIDListed(pid, FALSE);

	if (OutProtect)
		*OutProtect = (BOOLEAN)(*OutProtect || inProtectName || inProtectPid);
	if (OutReject)
		*OutReject = (BOOLEAN)(*OutReject || inRejectName || inRejectPid);

	RtlFreeUnicodeString(&up);
	RtlFreeUnicodeString(&u);
}

BOOLEAN ProtectorIsProcessCoveredByProtectList(_In_ PEPROCESS Eproc)
{
	BOOLEAN prot = FALSE, rej = FALSE;
	ProtectorQueryPolicy(Eproc, &prot, &rej);
	return (prot && !rej);
}

VOID ProtectorRevokeExistingUserHandlesToParents(_In_ PEPROCESS ChildProcess)
{
	HANDLE childPid = PsGetProcessId(ChildProcess);
	HANDLE parentPid = GetProcessParentPid(ChildProcess);

	if (!parentPid || parentPid == childPid)
		return;

	PEPROCESS parentProc = NULL;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(parentPid, &parentProc)))
		return;

	ProtectorRevokeExistingUserHandlesToProcess(parentProc);

	ObDereferenceObject(parentProc);
}

static OB_PREOP_CALLBACK_STATUS
ProtectorPreOperation(
	_In_ PVOID RegistrationContext,
	_Inout_ POB_PRE_OPERATION_INFORMATION PreInfo)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (!ProtectorPolicyIsActive())
		return OB_PREOP_SUCCESS;

	if (PreInfo->KernelHandle)
		return OB_PREOP_SUCCESS;

	ACCESS_MASK* Desired = NULL;
	ACCESS_MASK OriginalDesired = 0;
	BOOLEAN isProtect = FALSE, isReject = FALSE;

	if (PreInfo->ObjectType == *PsProcessType)
	{
		if (PsGetProcessId((PEPROCESS)PreInfo->Object) == PsGetCurrentProcessId())
			return OB_PREOP_SUCCESS;

		if (ProtectorIsTrustedSystemCaller())
			return OB_PREOP_SUCCESS;

		PEPROCESS eproc = (PEPROCESS)PreInfo->Object;

		isProtect = IsProcessProtected(eproc);

		ProtectorQueryPolicy(eproc, &isProtect, &isReject);

		if (!isProtect && !isReject)
			return OB_PREOP_SUCCESS;

		if (PreInfo->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			Desired = &PreInfo->Parameters->CreateHandleInformation.DesiredAccess;
			OriginalDesired = *Desired;

			GENERIC_MAPPING pm = {
				PROCESS_GENERIC_READ,
				PROCESS_GENERIC_WRITE,
				PROCESS_GENERIC_EXECUTE,
				PROCESS_ALL_ACCESS
			};
			RtlMapGenericMask(Desired, &pm);
		}
		else if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
		{
			Desired = &PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess;
			OriginalDesired = PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
		}
		else
		{
			return OB_PREOP_SUCCESS;
		}

		if (isReject)
		{
			*Desired = 0;
			if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			{
				PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess = 0;
			}

			POBC_CALL_CONTEXT ctx = (POBC_CALL_CONTEXT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*ctx), 'cCbO');
			if (ctx)
			{
				RtlZeroMemory(ctx, sizeof(*ctx));
				ctx->Operation = PreInfo->Operation;
				ctx->Object = PreInfo->Object;
				ctx->ObjectType = PreInfo->ObjectType;
				PreInfo->CallContext = ctx;
			}
			return OB_PREOP_SUCCESS;
		}

		if (isProtect)
		{
			GENERIC_MAPPING pm = {
				PROCESS_GENERIC_READ,
				PROCESS_GENERIC_WRITE,
				PROCESS_GENERIC_EXECUTE,
				PROCESS_ALL_ACCESS
			};
			RtlMapGenericMask(Desired, &pm);

			if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			{
				RtlMapGenericMask(&OriginalDesired, &pm);
			}


			const BOOLEAN selfAccess =
				(PsGetProcessId((PEPROCESS)PreInfo->Object) == PsGetCurrentProcessId());

			ACCESS_MASK allowedProc =
				SYNCHRONIZE |
				READ_CONTROL |
				PROCESS_QUERY_LIMITED_INFORMATION;

			if (selfAccess)
			{
				allowedProc |=
					PROCESS_QUERY_INFORMATION |
					PROCESS_VM_READ |
					PROCESS_SET_LIMITED_INFORMATION;
			}

			
			ACCESS_MASK deniedProc =
				PROCESS_TERMINATE |      
				PROCESS_VM_WRITE |         
				PROCESS_VM_OPERATION |     
				PROCESS_CREATE_THREAD |    
				PROCESS_SET_SESSIONID |   
				PROCESS_SUSPEND_RESUME |  
				PROCESS_SET_INFORMATION | 
				PROCESS_SET_QUOTA |     
				PROCESS_CREATE_PROCESS | 
				PROCESS_VM_READ | 
				PROCESS_QUERY_INFORMATION | 
				PROCESS_QUERY_LIMITED_INFORMATION | 
				PROCESS_DUP_HANDLE | 
				DELETE | 
				WRITE_DAC | 
				WRITE_OWNER;  

			*Desired &= allowedProc;
			*Desired &= ~deniedProc;

			ACCESS_MASK dangerousRemaining = *Desired & (
				PROCESS_TERMINATE |
				PROCESS_VM_WRITE |
				PROCESS_VM_OPERATION |
				PROCESS_SUSPEND_RESUME |
				PROCESS_SET_INFORMATION);

			if (dangerousRemaining != 0) {
				*Desired = 0;
				if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
					PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess = 0;
				}
			}

			if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			{
				PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess &= allowedProc;
				PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess &= ~deniedProc;
			}

			if ((*Desired & DANGEROUS_PROCESS_ACCESS) != 0)
			{
				*Desired = 0;
				if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
				{
					PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess = 0;
				}
			}
		}
	}
	else if (PreInfo->ObjectType == *PsThreadType)
	{
		if (PsGetThreadProcessId((PETHREAD)PreInfo->Object) == PsGetCurrentProcessId())
			return OB_PREOP_SUCCESS;

		if (ProtectorIsTrustedSystemCaller())
			return OB_PREOP_SUCCESS;

		HANDLE ownerPid = PsGetThreadProcessId((PETHREAD)PreInfo->Object);
		PEPROCESS owner = NULL;
		BOOLEAN creatorExempt = FALSE;
		BOOLEAN threadProtected = FALSE;
		BOOLEAN threadRejected = FALSE;

		if (NT_SUCCESS(PsLookupProcessByProcessId(ownerPid, &owner)))
		{
			threadProtected = IsProcessProtected(owner);

			if (!threadProtected)
			{
				ProtectorQueryPolicy(owner, &threadProtected, &threadRejected);
			}

			creatorExempt = ProtectorIsCallerCreatorOfProcess(PsGetCurrentProcessId(), owner);
			ObDereferenceObject(owner);
		}

		if (!threadProtected && !threadRejected)
			return OB_PREOP_SUCCESS;

		if (PreInfo->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			Desired = &PreInfo->Parameters->CreateHandleInformation.DesiredAccess;
			OriginalDesired = *Desired;
		}
		else if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
		{
			Desired = &PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess;
			OriginalDesired = PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
		}
		else
		{
			return OB_PREOP_SUCCESS;
		}

		if (threadRejected)
		{
			*Desired = 0;
			if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			{
				PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess = 0;
			}

			POBC_CALL_CONTEXT ctx = (POBC_CALL_CONTEXT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*ctx), 'cCbO');
			if (ctx)
			{
				RtlZeroMemory(ctx, sizeof(*ctx));
				ctx->Operation = PreInfo->Operation;
				ctx->Object = PreInfo->Object;
				ctx->ObjectType = PreInfo->ObjectType;
				PreInfo->CallContext = ctx;
			}
			return OB_PREOP_SUCCESS;
		}

		if (threadProtected)
		{
			GENERIC_MAPPING tm = {
				THREAD_GENERIC_READ,
				THREAD_GENERIC_WRITE,
				THREAD_GENERIC_EXECUTE,
				THREAD_ALL_ACCESS
			};
			RtlMapGenericMask(Desired, &tm);

			if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			{
				RtlMapGenericMask(&OriginalDesired, &tm);
			}

			const BOOLEAN selfThreadAccess = (ownerPid == PsGetCurrentProcessId());

			ACCESS_MASK allowedThread =
				SYNCHRONIZE |
				READ_CONTROL |
				THREAD_QUERY_LIMITED_INFORMATION;

			if (creatorExempt)
			{
				allowedThread |= THREAD_SUSPEND_RESUME | THREAD_SET_INFORMATION;
			}

			if (selfThreadAccess)
			{
				allowedThread |=
					THREAD_SUSPEND_RESUME |
					THREAD_SET_INFORMATION |
					THREAD_QUERY_INFORMATION |
					THREAD_GET_CONTEXT;
				
			}

			ACCESS_MASK deniedThread =
				THREAD_TERMINATE |         
				THREAD_SET_CONTEXT |        
				THREAD_SET_THREAD_TOKEN |   
				THREAD_DIRECT_IMPERSONATION | 
				THREAD_SUSPEND_RESUME |  
				THREAD_SET_INFORMATION | 
				THREAD_SET_LIMITED_INFORMATION | 
				THREAD_IMPERSONATE | 
				DELETE | 
				WRITE_DAC | 
				WRITE_OWNER;

			*Desired &= allowedThread;    
			*Desired &= ~deniedThread;   

			if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			{
				PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess &= allowedThread;
				PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess &= ~deniedThread;
			}

			if ((*Desired & DANGEROUS_THREAD_ACCESS) != 0)
			{
				*Desired = 0;
				if (PreInfo->Operation == OB_OPERATION_HANDLE_DUPLICATE)
				{
					PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess = 0;
				}
			}
		}
	}
	else
	{
		return OB_PREOP_SUCCESS;
	}

	if (Desired && (*Desired != OriginalDesired))
	{
		POBC_CALL_CONTEXT ctx = (POBC_CALL_CONTEXT)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*ctx), 'cCbO');
		if (ctx)
		{
			RtlZeroMemory(ctx, sizeof(*ctx));
			ctx->Operation = PreInfo->Operation;
			ctx->Object = PreInfo->Object;
			ctx->ObjectType = PreInfo->ObjectType;
			PreInfo->CallContext = ctx;
		}
	}

	return OB_PREOP_SUCCESS;
}

static VOID
ProtectorPostOperation(
	_In_ PVOID RegistrationContext,
	_In_ POB_POST_OPERATION_INFORMATION PostInfo)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	ProtectorFreeCallContext(PostInfo);
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ProtectorInitializeCallbacks(void)
{
	if (protector_RegHandle)
		return STATUS_SUCCESS;

	InitializeListHead(&protector_ProcessParentList);
	ExInitializeFastMutex(&protector_ProcessParentLock);

	{
		UNICODE_STRING fn;
		RtlInitUnicodeString(&fn, L"PsGetProcessInheritedFromUniqueProcessId");
		g_PsGetProcessInheritedFromUniqueProcessId =
			(PFN_PsGetProcessInheritedFromUniqueProcessId)MmGetSystemRoutineAddress(&fn);
	}

	OB_OPERATION_REGISTRATION ops[2] = { 0 };
	ops[0].ObjectType = PsProcessType;
	ops[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	ops[0].PreOperation = ProtectorPreOperation;
	ops[0].PostOperation = ProtectorPostOperation;

	ops[1].ObjectType = PsThreadType;
	ops[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	ops[1].PreOperation = ProtectorPreOperation;
	ops[1].PostOperation = ProtectorPostOperation;

	OB_CALLBACK_REGISTRATION reg = { 0 };
	reg.Version = OB_FLT_REGISTRATION_VERSION;
	reg.OperationRegistrationCount = (USHORT)RTL_NUMBER_OF(ops);
	reg.RegistrationContext = NULL;
	reg.OperationRegistration = ops;

	const ULONG kBaseAltitude = 321000;
	const USHORT kMaxAttempts = 32;

	NTSTATUS st = STATUS_UNSUCCESSFUL;

	for (USHORT i = 0; i < kMaxAttempts; ++i)
	{
		ULONG altVal = kBaseAltitude + i;

		WCHAR altBuf[16] = { 0 };
		UNICODE_STRING altStr;
		altStr.Buffer = altBuf;
		altStr.Length = 0;
		altStr.MaximumLength = sizeof(altBuf);

		st = RtlIntegerToUnicodeString(altVal, 10, &altStr);
		if (!NT_SUCCESS(st))
		{
			return st;
		}

		reg.Altitude = altStr;

		st = ObRegisterCallbacks(&reg, &protector_RegHandle);
		if (st == STATUS_FLT_INSTANCE_ALTITUDE_COLLISION || st == STATUS_OBJECT_NAME_COLLISION)
		{
			continue;
		}


		if (NT_SUCCESS(st) && !protector_ProcNotifyRegistered)
		{
			NTSTATUS pst = PsSetCreateProcessNotifyRoutineEx(ProtectorProcessNotifyEx, FALSE);
			if (NT_SUCCESS(pst))
				protector_ProcNotifyRegistered = TRUE;
		}

		return st;
	}
	return STATUS_FLT_INSTANCE_ALTITUDE_COLLISION;
}

static VOID ProtectorProcessNotifyEx(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);

	if (CreateInfo)
	{
		UNICODE_STRING base = { 0 };
		PCUNICODE_STRING full = CreateInfo->ImageFileName;
		if (!full || !full->Buffer || !full->Length)
			return;

		USHORT chars = full->Length / sizeof(WCHAR);
		USHORT i = chars;
		while (i > 0)
		{
			WCHAR c = full->Buffer[i - 1];
			if (c == L'\\' || c == L'/')
				break;
			--i;
		}
		base.Buffer = (PWCH)(full->Buffer + i);
		base.Length = (USHORT)((chars - i) * sizeof(WCHAR));
		base.MaximumLength = base.Length;

		UNICODE_STRING up = { 0 };
		NTSTATUS ust = RtlUpcaseUnicodeString(&up, &base, TRUE);
		if (!NT_SUCCESS(ust))
			return;

		const BOOLEAN inReject = ProtectorIsNameListed(&up, FALSE) || ProtectorIsPIDListed(ProcessId, FALSE);
		const BOOLEAN inProtectSelf = ProtectorIsNameListed(&up, TRUE) || ProtectorIsPIDListed(ProcessId, TRUE);

		if (inReject)
		{
			CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
		}

		BOOLEAN parentProtected = FALSE;
		PEPROCESS parentProc = NULL;
		if (NT_SUCCESS(PsLookupProcessByProcessId(CreateInfo->ParentProcessId, &parentProc)))
		{
			parentProtected = IsProcessProtected(parentProc) || ProtectorIsProcessCoveredByProtectList(parentProc);
			ObDereferenceObject(parentProc);
		}

		const BOOLEAN effectiveProtect = (inProtectSelf || parentProtected);

		RtlFreeUnicodeString(&up);

		if (effectiveProtect)
		{
			if (CreateInfo->CreationStatus == STATUS_SUCCESS)
			{
				PPROCESS_PARENT_ENTRY entry = ExAllocatePoolZero(NonPagedPoolNx, sizeof(*entry), 'PPrO');
				if (entry)
				{
					entry->ChildPid = ProcessId;
					entry->ParentPid = CreateInfo->ParentProcessId;
					ExAcquireFastMutex(&protector_ProcessParentLock);
					InsertTailList(&protector_ProcessParentList, &entry->Link);
					ExReleaseFastMutex(&protector_ProcessParentLock);
				}

				PPROTECTED_PROCESS_ENTRY p = ExAllocatePoolZero(NonPagedPoolNx, sizeof(*p), 'PPrO');
				if (p)
				{
					ObReferenceObject(Process);
					p->Process = Process;
					ExAcquireFastMutex(&protector_ProtectedProcessListLock);
					InsertTailList(&protector_ProtectedProcessList, &p->Link);
					ExReleaseFastMutex(&protector_ProtectedProcessListLock);

					ProtectorRevokeExistingUserHandlesToProcess(Process);
					ProtectorRevokeExistingUserHandlesToThreadsOfProcess(Process);


				}
			}
		}
		else
		{
			ExAcquireFastMutex(&protector_ProcessParentLock);
			PLIST_ENTRY it = protector_ProcessParentList.Flink;
			while (it != &protector_ProcessParentList)
			{
				PPROCESS_PARENT_ENTRY entry = CONTAINING_RECORD(it, PROCESS_PARENT_ENTRY, Link);
				PLIST_ENTRY next = it->Flink;
				if (entry->ChildPid == ProcessId)
				{
					RemoveEntryList(&entry->Link);
					ExFreePoolWithTag(entry, 'PPrO');
					break;
				}
				it = next;
			}
			ExReleaseFastMutex(&protector_ProcessParentLock);
		}
	}
	else
	{
		ExAcquireFastMutex(&protector_ProtectedProcessListLock);
		for (PLIST_ENTRY it = protector_ProtectedProcessList.Flink; it != &protector_ProtectedProcessList;)
		{
			PPROTECTED_PROCESS_ENTRY e = CONTAINING_RECORD(it, PROTECTED_PROCESS_ENTRY, Link);
			PLIST_ENTRY next = it->Flink;
			if (e->Process == Process)
			{
				RemoveEntryList(&e->Link);
				ExReleaseFastMutex(&protector_ProtectedProcessListLock);
				ObDereferenceObject(e->Process);
				ExFreePoolWithTag(e, 'PPrO');
				ExAcquireFastMutex(&protector_ProtectedProcessListLock);
				it = next;
				continue;
			}
			it = next;
		}
		ExReleaseFastMutex(&protector_ProtectedProcessListLock);

		ExAcquireFastMutex(&protector_ProcessParentLock);
		for (PLIST_ENTRY it = protector_ProcessParentList.Flink; it != &protector_ProcessParentList;)
		{
			PPROCESS_PARENT_ENTRY pe = CONTAINING_RECORD(it, PROCESS_PARENT_ENTRY, Link);
			PLIST_ENTRY next = it->Flink;
			if (pe->ChildPid == ProcessId)
			{
				RemoveEntryList(&pe->Link);
				ExFreePoolWithTag(pe, 'PPrO');
			}
			it = next;
		}
		ExReleaseFastMutex(&protector_ProcessParentLock);
	}
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID ProtectorUninitializeCallbacks(void)
{
	PVOID h = (PVOID)InterlockedExchangePointer(&protector_RegHandle, NULL);
	if (h)
		ObUnRegisterCallbacks(h);

	if (protector_ProcNotifyRegistered)
	{
		PsSetCreateProcessNotifyRoutineEx(ProtectorProcessNotifyEx, TRUE);
		protector_ProcNotifyRegistered = FALSE;
	}


	ExAcquireFastMutex(&protector_ProcessParentLock);
	while (!IsListEmpty(&protector_ProcessParentList))
	{
		PLIST_ENTRY e = RemoveHeadList(&protector_ProcessParentList);
		PPROCESS_PARENT_ENTRY entry = CONTAINING_RECORD(e, PROCESS_PARENT_ENTRY, Link);
		ExFreePoolWithTag(entry, 'PPrO');
	}
	ExReleaseFastMutex(&protector_ProcessParentLock);
}

static BOOLEAN ProtectorIsNameListed(
	_In_ PCUNICODE_STRING BaseNameUc,
	_In_ BOOLEAN ProtectList)
{
	if (!ProtectorRulesAreReady())
		return FALSE;

	BOOLEAN found = FALSE;
	ExAcquireFastMutex(&protector_RulesLock);
	PLIST_ENTRY head = ProtectList ? &protector_ProtectNames : &protector_RejectNames;

	for (PLIST_ENTRY it = head->Flink; it != head; it = it->Flink)
	{
		POB_NAME_RULE cur = CONTAINING_RECORD(it, OB_NAME_RULE, Link);
		UNICODE_STRING ruleName = cur->Name;

		UNICODE_STRING pidPrefix;
		RtlInitUnicodeString(&pidPrefix, L"PID:");
		if (RtlPrefixUnicodeString(&pidPrefix, &ruleName, TRUE))
			continue;

		BOOLEAN isWildcard = (ruleName.Length >= sizeof(WCHAR) && ruleName.Buffer[0] == L'*');

		if (isWildcard)
		{
			if (FsRtlIsNameInExpression(&ruleName, (PUNICODE_STRING)BaseNameUc, TRUE, NULL))
			{
				found = TRUE;
				break;
			}
		}
		else
		{
			if (BaseNameUc->Length >= ruleName.Length)
			{
				PUCHAR baseEnd = (PUCHAR)BaseNameUc->Buffer + (BaseNameUc->Length - ruleName.Length);
				if (RtlCompareMemory(baseEnd, ruleName.Buffer, ruleName.Length) == ruleName.Length)
				{
					found = TRUE;
					break;
				}
			}
		}
	}

	ExReleaseFastMutex(&protector_RulesLock);
	return found;
}

static BOOLEAN ProtectorIsPIDListed(_In_ HANDLE ProcessId, _In_ BOOLEAN ProtectList)
{
	if (!ProtectorRulesAreReady())
		return FALSE;

	const ULONG pid = HandleToULong(ProcessId);
	BOOLEAN found = FALSE;

	ExAcquireFastMutex(&protector_RulesLock);
	PLIST_ENTRY head = ProtectList ? &protector_ProtectNames : &protector_RejectNames;

	UNICODE_STRING prefix;
	RtlInitUnicodeString(&prefix, L"PID:");

	for (PLIST_ENTRY it = head->Flink; it != head; it = it->Flink)
	{
		POB_NAME_RULE cur = CONTAINING_RECORD(it, OB_NAME_RULE, Link);
		UNICODE_STRING name = cur->Name;

		if (!RtlPrefixUnicodeString(&prefix, &name, TRUE))
			continue;

		UNICODE_STRING tail;
		tail.Buffer = name.Buffer + (prefix.Length / sizeof(WCHAR));
		tail.Length = name.Length - prefix.Length;
		tail.MaximumLength = tail.Length;

		ULONG parsed = 0;
		if (NT_SUCCESS(RtlUnicodeStringToInteger(&tail, 0, &parsed)))
		{
			if (parsed == pid)
			{
				found = TRUE;
				break;
			}
		}
	}
	ExReleaseFastMutex(&protector_RulesLock);
	return found;
}

