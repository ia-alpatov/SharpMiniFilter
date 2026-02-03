#include <ntifs.h>
#include <fltKernel.h>
#include <ntstrsafe.h>

#include "../include/Auth.h"
#include "../include/ProtectorPort.h"
#include "../include/Protector.h"
#include "../include/Utils.h"
#include "../include/Common.h"

NTSTATUS ProtectorRulesRemoveProtectPid(_In_ ULONG Pid)
{
    WCHAR wbuf[32] = { 0 };
    UNICODE_STRING u = { 0 }, up = { 0 };
    NTSTATUS st = RtlStringCchPrintfW(wbuf, ARRAYSIZE(wbuf), L"PID:%lu", Pid);
    if (!NT_SUCCESS(st))
        return st;
    RtlInitUnicodeString(&u, wbuf);
    st = RtlUpcaseUnicodeString(&up, &u, TRUE);
    if (!NT_SUCCESS(st))
        return st;
    ExAcquireFastMutex(&protector_RulesLock);
    st = ObRulesRemoveLocked(&protector_ProtectNames, &up);
    ExReleaseFastMutex(&protector_RulesLock);
    RtlFreeUnicodeString(&up);
    return st;
}

static BOOLEAN ProtectorParsePidRule(_In_ PCUNICODE_STRING Name, _Out_ PULONG PidOut)
{
    UNICODE_STRING prefix;
    RtlInitUnicodeString(&prefix, L"PID:");
    if (!RtlPrefixUnicodeString(&prefix, Name, TRUE))
        return FALSE;

    UNICODE_STRING tail;
    tail.Buffer = Name->Buffer + (prefix.Length / sizeof(WCHAR));
    tail.Length = Name->Length - prefix.Length;
    tail.MaximumLength = tail.Length;

    ULONG tmp = 0;
    if (!NT_SUCCESS(RtlUnicodeStringToInteger(&tail, 0, &tmp)))
        return FALSE;

    *PidOut = tmp;
    return TRUE;
}

static VOID PidSetFree(_Inout_ PID_SET* S)
{
    if (!S)
        return;
    if (S->Items)
        ExFreePoolWithTag(S->Items, 'diPO');
    RtlZeroMemory(S, sizeof(*S));
}

static BOOLEAN PidSetContains(_In_ const PID_SET* S, _In_ ULONG Pid)
{
    for (ULONG i = 0; i < S->Count; ++i)
        if (S->Items[i] == Pid)
            return TRUE;
    return FALSE;
}

static VOID RulesSnapshotPidSetLocked(_In_ PLIST_ENTRY Head, _Out_ PID_SET* Out)
{
    RtlZeroMemory(Out, sizeof(*Out));

    ULONG cnt = 0;
    for (PLIST_ENTRY it = Head->Flink; it != Head; it = it->Flink)
    {
        POB_NAME_RULE r = CONTAINING_RECORD(it, OB_NAME_RULE, Link);
        ULONG pid;
        if (ProtectorParsePidRule(&r->Name, &pid))
            ++cnt;
    }
    if (!cnt)
        return;

    ULONG* arr = (ULONG*)ExAllocatePoolZero(NonPagedPoolNx, sizeof(ULONG) * cnt, 'diPO');
    if (!arr)
        return;

    ULONG i = 0;
    for (PLIST_ENTRY it = Head->Flink; it != Head; it = it->Flink)
    {
        POB_NAME_RULE r = CONTAINING_RECORD(it, OB_NAME_RULE, Link);
        ULONG pid;
        if (ProtectorParsePidRule(&r->Name, &pid))
            arr[i++] = pid;
    }

    Out->Count = i;
    Out->Items = arr;
}


VOID InitializeProtectedProcessList(VOID)
{
    ExInitializeFastMutex(&protector_ProtectedProcessListLock);
    InitializeListHead(&protector_ProtectedProcessList);
}


static VOID ProtectorRulesInit(VOID)
{
    ExInitializeFastMutex(&protector_RulesLock);
    InitializeListHead(&protector_ProtectNames);
    InitializeListHead(&protector_RejectNames);
    InterlockedExchange(&protector_RulesReady, 1);
}

static VOID ProtectorRulesClearListLocked(_Inout_ PLIST_ENTRY Head)
{
    while (!IsListEmpty(Head))
    {
        PLIST_ENTRY e = RemoveHeadList(Head);
        POB_NAME_RULE n = CONTAINING_RECORD(e, OB_NAME_RULE, Link);
        if (n->Name.Buffer)
            ExFreePoolWithTag(n->Name.Buffer, OB_RULE_TAG);
        ExFreePoolWithTag(n, OB_RULE_TAG);
    }
}

BOOLEAN ProtectorRulesContainsLocked(_In_ PLIST_ENTRY Head, _In_ PCUNICODE_STRING Name)
{
    for (PLIST_ENTRY it = Head->Flink; it != Head; it = it->Flink)
    {
        POB_NAME_RULE cur = CONTAINING_RECORD(it, OB_NAME_RULE, Link);
        if (RtlEqualUnicodeString(&cur->Name, Name, TRUE))
            return TRUE;
    }
    return FALSE;
}

static NTSTATUS ObRulesAddLocked(_Inout_ PLIST_ENTRY Head, _In_ PCUNICODE_STRING NameUc, _Out_opt_ PBOOLEAN Duplicate)
{
    if (Duplicate)
        *Duplicate = FALSE;
    if (ProtectorRulesContainsLocked(Head, NameUc))
    {
        if (Duplicate)
            *Duplicate = TRUE;
        return STATUS_SUCCESS;
    }

    POB_NAME_RULE entry = (POB_NAME_RULE)ExAllocatePoolZero(NonPagedPoolNx, sizeof(*entry), OB_RULE_TAG);
    if (!entry)
        return STATUS_INSUFFICIENT_RESOURCES;

    SIZE_T bytes = NameUc->Length + sizeof(WCHAR);
    entry->Name.Buffer = (PWCH)ExAllocatePoolZero(NonPagedPoolNx, bytes, OB_RULE_TAG);
    if (!entry->Name.Buffer)
    {
        ExFreePoolWithTag(entry, OB_RULE_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    entry->Name.Length = NameUc->Length;
    entry->Name.MaximumLength = (USHORT)bytes;
    RtlCopyMemory(entry->Name.Buffer, NameUc->Buffer, NameUc->Length);
    InsertTailList(Head, &entry->Link);
    return STATUS_SUCCESS;
}

static NTSTATUS ObRulesRemoveLocked(_Inout_ PLIST_ENTRY Head, _In_ PCUNICODE_STRING NameUc)
{
    for (PLIST_ENTRY it = Head->Flink; it != Head; it = it->Flink)
    {
        POB_NAME_RULE n = CONTAINING_RECORD(it, OB_NAME_RULE, Link);
        if (RtlEqualUnicodeString(&n->Name, NameUc, TRUE))
        {
            RemoveEntryList(&n->Link);
            if (n->Name.Buffer)
                ExFreePoolWithTag(n->Name.Buffer, OB_RULE_TAG);
            ExFreePoolWithTag(n, OB_RULE_TAG);
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

static NTSTATUS ObRulesReplaceList(
    _In_ BOOLEAN ProtectList,
    _In_reads_bytes_(Bytes) PCWCH NamesBlob,
    _In_ ULONG Bytes,
    _Out_ PULONG Processed,
    _Out_ PULONG Added,
    _Out_ PULONG Dups,
    _Out_ PULONG Invalid)
{
    *Processed = *Added = *Dups = *Invalid = 0;
    PLIST_ENTRY head = ProtectList ? &protector_ProtectNames : &protector_RejectNames;

    ExAcquireFastMutex(&protector_RulesLock);
    ProtectorRulesClearListLocked(head);

    ULONG off = 0;
    NTSTATUS finalStatus = STATUS_SUCCESS;

    while (off + sizeof(WCHAR) <= Bytes)
    {
        PCWCH p = NamesBlob + (off / sizeof(WCHAR));
        SIZE_T maxChars = (Bytes - off) / sizeof(WCHAR);
        SIZE_T len = 0;
        while (len < maxChars && p[len] != L'\0')
            len++;
        if (len == 0)
        {
            (*Invalid)++;
            off += sizeof(WCHAR);
            continue;
        }

        UNICODE_STRING u;
        u.Buffer = (PWCH)p;
        u.Length = (USHORT)(len * sizeof(WCHAR));
        u.MaximumLength = (USHORT)(u.Length + sizeof(WCHAR));

        UNICODE_STRING up = { 0 };
        up.Buffer = (PWCH)ExAllocatePoolZero(NonPagedPoolNx, u.Length + sizeof(WCHAR), OB_RULE_TAG);
        if (!up.Buffer)
        {
            finalStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        up.Length = u.Length;
        up.MaximumLength = (USHORT)(u.Length + sizeof(WCHAR));

        NTSTATUS ust = RtlUpcaseUnicodeString(&up, &u, FALSE);
        if (!NT_SUCCESS(ust))
        {
            ExFreePoolWithTag(up.Buffer, OB_RULE_TAG);
            (*Invalid)++;
            off += (ULONG)((len + 1) * sizeof(WCHAR));
            continue;
        }

        BOOLEAN dup = FALSE;
        NTSTATUS st = ObRulesAddLocked(head, &up, &dup);
        if (NT_SUCCESS(st))
        {
            (*Processed)++;
            if (dup)
                (*Dups)++;
            else
                (*Added)++;
        }
        else
        {
            (*Invalid)++;
        }

        ExFreePoolWithTag(up.Buffer, OB_RULE_TAG);
        off += (ULONG)((len + 1) * sizeof(WCHAR));
    }

    ExReleaseFastMutex(&protector_RulesLock);
    return finalStatus;
}

static NTSTATUS
ProtectorPortMessageRoutine(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength)
{
    if (ReturnOutputBufferLength)
        *ReturnOutputBufferLength = 0;

    POB_PORT_CTX ctx = (POB_PORT_CTX)PortCookie;
    if (!ctx)
        return STATUS_INVALID_PARAMETER;

    if (!ctx->Authed)
    {
        if (!InputBuffer || InputBufferLength < sizeof(PORT_AUTH_PACKET))
            return STATUS_ACCESS_DENIED;

        const PORT_AUTH_PACKET* p = (const PORT_AUTH_PACKET*)InputBuffer;

        if (p->Auth.Version != AUTH_VERSION || !IsTimestampWithinTolerance(p->Auth.Timestamp100ns))
            return STATUS_ACCESS_DENIED;

        UCHAR prefix[sizeof(ULONG) + sizeof(ULONGLONG) + 16] = { 0 };
        RtlCopyMemory(prefix, &p->Auth.Version, sizeof(ULONG));
        RtlCopyMemory(prefix + sizeof(ULONG), &p->Auth.Timestamp100ns, sizeof(ULONGLONG));
        RtlCopyMemory(prefix + sizeof(ULONG) + sizeof(ULONGLONG), p->Auth.Nonce, 16);

        NTSTATUS st = AuthVerifyHmac(
            gAuthKey,
            AUTH_HMAC_KEY_LEN,
            prefix,
            sizeof(prefix),
            NULL,
            0,
            p->Auth.Hmac);

        if (!NT_SUCCESS(st))
            return STATUS_ACCESS_DENIED;

        ctx->Authed = TRUE;
        InterlockedExchange8((volatile CHAR*)&protector_client_authed, 1);

        if (OutputBuffer && OutputBufferLength >= sizeof(USER_TO_FLT_REPLY))
        {
            USER_TO_FLT_REPLY* r = (USER_TO_FLT_REPLY*)OutputBuffer;
            NTSTATUS cst = RtlStringCchCopyW(r->msg, ARRAYSIZE(r->msg), L"OK");
            if (NT_SUCCESS(cst) && ReturnOutputBufferLength)
            {
                *ReturnOutputBufferLength = (ULONG)(sizeof(WCHAR) * 3);
            }
        }
        return STATUS_SUCCESS;
    }

    if (!InputBuffer || InputBufferLength < sizeof(ULONG))
        return STATUS_INVALID_PARAMETER;

    if (InputBufferLength >= sizeof(PORT_OBC_REQ_HDR))
    {
        const PORT_OBC_REQ_HDR* hdr = (const PORT_OBC_REQ_HDR*)InputBuffer;

        switch (hdr->Command)
        {
        case PORT_CMD_OBC_REPLACE_PROTECT:
        {
            if (InputBufferLength < sizeof(PORT_OBC_REQ_HDR) + sizeof(PORT_OBC_BULK_HEAD))
                return STATUS_INVALID_PARAMETER;

            const PORT_OBC_BULK_HEAD* b = (const PORT_OBC_BULK_HEAD*)((const UCHAR*)InputBuffer + sizeof(PORT_OBC_REQ_HDR));
            const ULONG namesBytes = InputBufferLength - (sizeof(PORT_OBC_REQ_HDR) + sizeof(PORT_OBC_BULK_HEAD));
            const PCWCH names = (const PCWCH)((const UCHAR*)b + sizeof(*b));

            PID_SET before = { 0 }, after = { 0 };
            ExAcquireFastMutex(&protector_RulesLock);
            RulesSnapshotPidSetLocked(&protector_ProtectNames, &before);
            ExReleaseFastMutex(&protector_RulesLock);

            ULONG processed = 0, added = 0, dups = 0, invalid = 0;
            NTSTATUS st = ObRulesReplaceList(TRUE, names, namesBytes, &processed, &added, &dups, &invalid);

            ExAcquireFastMutex(&protector_RulesLock);
            RulesSnapshotPidSetLocked(&protector_ProtectNames, &after);
            ExReleaseFastMutex(&protector_RulesLock);

            for (ULONG i = 0; i < after.Count; ++i)
            {
                if (!PidSetContains(&before, after.Items[i]))
                {
                    (void)ProtectorProtectPidNow(ULongToHandle(after.Items[i]));
                }
            }


            for (ULONG i = 0; i < before.Count; ++i)
            {
                if (!PidSetContains(&after, before.Items[i]))
                {
                    (void)ProtectorUnprotectPidNow(ULongToHandle(before.Items[i]));
                }
            }



            PidSetFree(&before);
            PidSetFree(&after);

            for (;;)
            {
                HANDLE buf[64];
                ULONG j = 0;

                ExAcquireFastMutex(&protector_ProtectedProcessListLock);
                for (PLIST_ENTRY it = protector_ProtectedProcessList.Flink;
                    it != &protector_ProtectedProcessList && j < ARRAYSIZE(buf);
                    it = it->Flink)
                {
                    PPROTECTED_PROCESS_ENTRY e = CONTAINING_RECORD(it, PROTECTED_PROCESS_ENTRY, Link);
                    if (!ProtectorIsProcessCoveredByProtectList(e->Process))
                        buf[j++] = PsGetProcessId(e->Process);
                }
                ExReleaseFastMutex(&protector_ProtectedProcessListLock);

                if (j == 0)
                    break;

                for (ULONG k = 0; k < j; ++k)
                    (void)ProtectorUnprotectPidNow(buf[k]);
            }


            PORT_OBC_BULK_RSP rsp = { st, processed, added, dups, invalid };
            if (OutputBuffer && OutputBufferLength >= sizeof(rsp)) {
                RtlCopyMemory(OutputBuffer, &rsp, sizeof(rsp));
                if (ReturnOutputBufferLength)
                    *ReturnOutputBufferLength = sizeof(rsp);
            }

            return st;
        }

        case PORT_CMD_OBC_REPLACE_REJECT:
        {
            if (InputBufferLength < sizeof(PORT_OBC_REQ_HDR) + sizeof(PORT_OBC_BULK_HEAD))
                return STATUS_INVALID_PARAMETER;

            const PORT_OBC_BULK_HEAD* b = (const PORT_OBC_BULK_HEAD*)((const UCHAR*)InputBuffer + sizeof(PORT_OBC_REQ_HDR));
            const ULONG namesBytes = InputBufferLength - (sizeof(PORT_OBC_REQ_HDR) + sizeof(PORT_OBC_BULK_HEAD));
            const PCWCH names = (const PCWCH)((const UCHAR*)b + sizeof(*b));

            ULONG processed = 0, added = 0, dups = 0, invalid = 0;
            NTSTATUS st = ObRulesReplaceList(FALSE, names, namesBytes, &processed, &added, &dups, &invalid);

            PID_SET rejectNow = { 0 };
            ExAcquireFastMutex(&protector_RulesLock);
            RulesSnapshotPidSetLocked(&protector_RejectNames, &rejectNow);
            ExReleaseFastMutex(&protector_RulesLock);

            for (ULONG i = 0; i < rejectNow.Count; ++i)
            {
                (void)ProtectorUnprotectPidNow(ULongToHandle(rejectNow.Items[i]));
            }
            PidSetFree(&rejectNow);

            PORT_OBC_BULK_RSP rsp = { st, processed, added, dups, invalid };
            if (OutputBuffer && OutputBufferLength >= sizeof(rsp))
            {
                RtlCopyMemory(OutputBuffer, &rsp, sizeof(rsp));
                if (ReturnOutputBufferLength)
                    *ReturnOutputBufferLength = sizeof(rsp);
            }
            return st;
        }

        default:
            break;
        }
    }

    return STATUS_NOT_SUPPORTED;
}

static NTSTATUS ProtectorPortConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_ PVOID ServerCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ClientPort);
    UNREFERENCED_PARAMETER(ServerCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    if (InterlockedCompareExchangePointer((PVOID*)&protector_client_port, ClientPort, NULL) != NULL)
        return STATUS_CONNECTION_REFUSED;

    POB_PORT_CTX ctx = (POB_PORT_CTX)ExAllocatePoolZero(NonPagedPoolNx, sizeof(*ctx), 'pcBO');
    if (!ctx)
        return STATUS_INSUFFICIENT_RESOURCES;

    ctx->Authed = FALSE;
    ctx->ClientPid = HandleToULong(PsGetCurrentProcessId());
    *ConnectionPortCookie = ctx;
    return STATUS_SUCCESS;
}

static VOID ProtectorPortDisconnectNotify(_In_opt_ PVOID ConnectionCookie)
{
    POB_PORT_CTX ctx = (POB_PORT_CTX)ConnectionCookie;
    InterlockedExchangePointer((PVOID*)&protector_client_port, NULL);
    InterlockedExchange8((volatile CHAR*)&protector_client_authed, 0);
    if (ctx)
        ExFreePoolWithTag(ctx, 'pcBO');
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID ProtectorPortFinalize(VOID)
{
    if (protector_server_port)
    {
        FltCloseCommunicationPort(protector_server_port);
        protector_server_port = NULL;
    }

    InterlockedExchangePointer((PVOID*)&protector_client_port, NULL);
    InterlockedExchange8((volatile CHAR*)&protector_client_authed, 0);

    ExAcquireFastMutex(&protector_RulesLock);
    ProtectorRulesClearListLocked(&protector_ProtectNames);
    ProtectorRulesClearListLocked(&protector_RejectNames);
    ExReleaseFastMutex(&protector_RulesLock);

    InterlockedExchange(&protector_RulesReady, 0);
}

BOOLEAN ProtectorPortIsReady(void)
{
    return (InterlockedCompareExchangePointer((PVOID*)&protector_client_port, NULL, NULL) != NULL) &&
        (protector_client_authed != 0);
}

BOOLEAN ProtectorRulesAreReady(void)
{
    return (InterlockedCompareExchange(&protector_RulesReady, 0, 0) != 0);
}


BOOLEAN ProtectorPolicyIsActive(void)
{
    if ((InterlockedCompareExchangePointer((PVOID*)&protector_client_port, NULL, NULL) != NULL) &&
        (protector_client_authed != 0))
    {
        return TRUE;
    }

    ExAcquireFastMutex(&protector_ProtectedProcessListLock);
    const BOOLEAN anyProt = !IsListEmpty(&protector_ProtectedProcessList);
    ExReleaseFastMutex(&protector_ProtectedProcessListLock);
    if (anyProt)
        return TRUE;

    if (!ProtectorRulesAreReady())
        return FALSE;

    BOOLEAN any = FALSE;
    ExAcquireFastMutex(&protector_RulesLock);
    any = !IsListEmpty(&protector_ProtectNames) || !IsListEmpty(&protector_RejectNames);
    ExReleaseFastMutex(&protector_RulesLock);
    return any;
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ProtectorPortSendMessage(
    _In_reads_bytes_opt_(sendLen) PVOID sendBuf,
    _In_ ULONG sendLen,
    _Out_writes_bytes_opt_(recvLen) PVOID recvBuf,
    _In_ ULONG recvLen,
    _Out_opt_ PULONG written)
{
    if (!ProtectorPortIsReady())
        return STATUS_DEVICE_NOT_READY;

    LARGE_INTEGER to;
    to.QuadPart = -(LONGLONG)4 * 10 * 1000 * 1000;

    ULONG reply = recvLen;
    NTSTATUS st = FltSendMessage(flt_handle, &protector_client_port, sendBuf, sendLen, recvBuf, &reply, &to);
    if (written)
        *written = reply;
    return st;
}


_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS ProtectorPortInitialize(_In_ PFLT_FILTER Filter)
{
    InitializeProtectedProcessList();
    ProtectorRulesInit();

    UNICODE_STRING name;
    OBJECT_ATTRIBUTES oa;
    PSECURITY_DESCRIPTOR sd = NULL;

    RtlInitUnicodeString(&name, PROTECTOR_PORT_NAME);

    NTSTATUS st = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(st))
        return st;

    InitializeObjectAttributes(&oa, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

    st = FltCreateCommunicationPort(
        Filter,
        &protector_server_port,
        &oa,
        NULL,
        ProtectorPortConnectNotify,
        ProtectorPortDisconnectNotify,
        ProtectorPortMessageRoutine,
        1);

    FltFreeSecurityDescriptor(sd);
    return st;
}