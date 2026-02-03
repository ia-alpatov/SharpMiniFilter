#include <ntifs.h>
#include <fltKernel.h>
#include <ntstrsafe.h>

#include "../include/Filter.h"
#include "../include/Common.h"
#include "../include/Auth.h"
#include "../include/Utils.h"
#include "../include/Error.h"

static PFLT_PORT filter_server_port = NULL;
static PFLT_PORT filter_client_port = NULL;

static BOOLEAN filter_client_authed = FALSE;

ULONG filter_client_pid = 0;

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS MiniFilterPortInitialize(_In_ PFLT_FILTER Filter)
{
	UNICODE_STRING name;
	OBJECT_ATTRIBUTES oa;
	PSECURITY_DESCRIPTOR sd = NULL;

	RtlInitUnicodeString(&name, MINIFILTER_PORT_NAME);

	NTSTATUS st = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
	if (!NT_SUCCESS(st))
		return st;

	InitializeObjectAttributes(&oa, &name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

	st = FltCreateCommunicationPort(
		Filter,
		&filter_server_port,
		&oa,
		NULL,
		MiniFilterPortNotifyRoutine,
		MiniFilterPortDisconnectRoutine,
		MiniFilterPortMessageRoutine,
		1);

	FltFreeSecurityDescriptor(sd);
	return st;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID MiniFilterPortFinalize(VOID)
{
	if (filter_server_port)
	{
		FltCloseCommunicationPort(filter_server_port);
		filter_server_port = NULL;
	}
	InterlockedExchangePointer((PVOID*)&filter_client_port, NULL);
	filter_client_authed = FALSE;
	filter_client_pid = 0;
}


_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MiniFilterPortNotifyRoutine(
	_In_ PFLT_PORT ClientPort,
	_In_ PVOID ServerCookie,
	_In_ PVOID ConnectionContext,
	_In_ ULONG ConnectionContextLength,
	_Out_ PVOID* ConnectionPortCookie)
{
	UNREFERENCED_PARAMETER(ServerCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(ConnectionContextLength);

	if (InterlockedCompareExchangePointer((PVOID*)&filter_client_port, ClientPort, NULL) != NULL)
		return STATUS_CONNECTION_REFUSED;

	PMF_PORT_CTX ctx = (PMF_PORT_CTX)ExAllocatePoolZero(NonPagedPoolNx, sizeof(*ctx), 'pcMF');
	if (!ctx)
	{
		InterlockedExchangePointer((PVOID*)&filter_client_port, NULL);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	ctx->Authed = FALSE;
	ctx->ClientPid = HandleToULong(PsGetCurrentProcessId());
	filter_client_pid = ctx->ClientPid;
	InterlockedExchange8((volatile CHAR*)&filter_client_authed, 0);

	*ConnectionPortCookie = ctx;
	return STATUS_SUCCESS;
}

_IRQL_requires_(PASSIVE_LEVEL)
VOID MiniFilterPortDisconnectRoutine(_In_opt_ PVOID ConnectionCookie)
{
	PMF_PORT_CTX ctx = (PMF_PORT_CTX)ConnectionCookie;

	InterlockedExchangePointer((PVOID*)&filter_client_port, NULL);
	InterlockedExchange8((volatile CHAR*)&filter_client_authed, 0);
	filter_client_pid = 0;

	if (ctx)
	{
		ExFreePoolWithTag(ctx, 'pcMF');
	}
}

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MiniFilterPortMessageRoutine(
	_In_opt_ PVOID PortCookie,
	_In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
	_In_ ULONG InputBufferLength,
	_Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
	_In_ ULONG OutputBufferLength,
	_Out_ PULONG ReturnOutputBufferLength)
{
	if (ReturnOutputBufferLength)
		*ReturnOutputBufferLength = 0;

	PMF_PORT_CTX ctx = (PMF_PORT_CTX)PortCookie;
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
		InterlockedExchange8((volatile CHAR*)&filter_client_authed, 1);

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

	UNREFERENCED_PARAMETER(InputBuffer);
	UNREFERENCED_PARAMETER(InputBufferLength);
	UNREFERENCED_PARAMETER(OutputBuffer);
	UNREFERENCED_PARAMETER(OutputBufferLength);
	return STATUS_NOT_SUPPORTED;
}


_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MiniFilterPortSendMessage(
	_In_reads_bytes_(sendLen) PVOID sendBuf,
	_In_ ULONG sendLen,
	_Out_writes_bytes_to_(recvLen, *written) PVOID recvBuf,
	_In_ ULONG recvLen,
	_Out_opt_ PULONG written)
{
	if (InterlockedCompareExchangePointer((PVOID*)&filter_client_port, NULL, NULL) == NULL)
		return STATUS_DEVICE_NOT_READY;

	if (!filter_client_authed)
		return STATUS_DEVICE_NOT_READY;

	LARGE_INTEGER to;
	to.QuadPart = -(LONGLONG)4 * 10 * 1000 * 1000;

	ULONG reply = recvLen;
	NTSTATUS st = FltSendMessage(flt_handle, &filter_client_port, sendBuf, sendLen, recvBuf, &reply, &to);
	if (written)
		*written = reply;
	return st;
}

FLT_OPERATION_REGISTRATION operations[] = {
	{IRP_MJ_CREATE,
	 0,
	 MiniFilterCreatePreRoutine,
	 MiniFilterCreatePostRoutine,
	 NULL},
	{IRP_MJ_OPERATION_END} };


FLT_REGISTRATION registration = {
	sizeof(FLT_REGISTRATION),	// size
	FLT_REGISTRATION_VERSION,	// version
	0,							// flags
	NULL,						// context registration
	operations,					// operation registration
	MiniFilterUnloadRoutine,	// filter unload callback
	NULL,						// instance setup callback
	NULL,						// instance query teardown callback
	NULL,						// instance teardown start callback
	NULL,						// instance teardown complete callback
	NULL,						// generate file name callback
	NULL,						// normalize name component callback
	NULL,						// normalize context cleanup callback
	NULL,						// transaction notification callback
	NULL,						// normalize name component ex callback
	NULL						// section notification callback
};

FLT_PREOP_CALLBACK_STATUS
MiniFilterCreatePreRoutine(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Out_ PVOID* CompletionContext)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
MiniFilterCreatePostRoutine(
	_Inout_ PFLT_CALLBACK_DATA callback_data,
	_In_ PCFLT_RELATED_OBJECTS flt_object,
	_In_opt_ PVOID completion_context,
	_In_ FLT_POST_OPERATION_FLAGS flags)
{
	UNREFERENCED_PARAMETER(flt_object);
	UNREFERENCED_PARAMETER(completion_context);
	UNREFERENCED_PARAMETER(flags);

	if (HandleToULong(PsGetCurrentProcessId()) == filter_client_pid)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (KeGetCurrentIrql() > APC_LEVEL)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	PFLT_FILE_NAME_INFORMATION name_info = NULL;
	NTSTATUS status;

	status = FltGetFileNameInformation(
		callback_data,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
		&name_info);
	if (!NT_SUCCESS(status))
	{
		goto EXIT_OF_CREATE_POST_OPERATION;
	}

	status = FltParseFileNameInformation(name_info);
	IF_ERROR(FltParseFileNameInformation, EXIT_OF_CREATE_POST_OPERATION);

	FLT_TO_USER sent;
	RtlZeroMemory(&sent, sizeof(sent));
	FLT_TO_USER_REPLY reply;
	RtlZeroMemory(&reply, sizeof(reply));
	ULONG returned_bytes = 0;

	size_t nameChars = name_info->Name.Length / sizeof(WCHAR);
	if (!NT_SUCCESS(RtlStringCchCopyNW(sent.path, RTL_NUMBER_OF(sent.path),
		name_info->Name.Buffer, nameChars)))
	{
		goto EXIT_OF_CREATE_POST_OPERATION;
	}
	sent.pId = PtrToUint(PsGetCurrentProcessId());

	status = MiniFilterPortSendMessage(&sent, sizeof(sent), &reply, sizeof(reply), &returned_bytes);

	if (NT_SUCCESS(status) && returned_bytes >= sizeof(FLT_TO_USER_REPLY) && reply.block)
	{
		callback_data->IoStatus.Status = STATUS_ACCESS_DENIED;
	}
	else if (status == STATUS_TIMEOUT)
	{
		DbgPrint("[Filter] CreatePost: client reply timed out, allowing access\n");
	}
	else if (status == STATUS_DEVICE_NOT_READY)
	{
		DbgPrint("[Filter] CreatePost: device not ready, allowing access\n");
	}
	else if (!NT_SUCCESS(status))
	{
		DbgPrint("[Filter] CreatePost: MinifltPortSendMessage failed 0x%X, allowing access\n", status);
	}

EXIT_OF_CREATE_POST_OPERATION:

	if (name_info)
	{
		FltReleaseFileNameInformation(name_info);
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}
