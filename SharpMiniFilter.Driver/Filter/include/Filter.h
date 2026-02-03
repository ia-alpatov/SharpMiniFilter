#pragma once
#include <fltKernel.h>

extern PFLT_FILTER flt_handle;
extern FLT_OPERATION_REGISTRATION operations[];
extern FLT_REGISTRATION registration;

extern ULONG filter_client_pid;

FLT_PREOP_CALLBACK_STATUS
MiniFilterCreatePreRoutine(
    _Inout_ PFLT_CALLBACK_DATA callback_data,
    _In_ PCFLT_RELATED_OBJECTS flt_object,
    _Out_ PVOID* completion_context);

FLT_POSTOP_CALLBACK_STATUS
MiniFilterCreatePostRoutine(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
MiniFilterUnloadRoutine(
    _In_ FLT_FILTER_UNLOAD_FLAGS flags);


_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS MiniFilterPortInitialize(_In_ PFLT_FILTER flt_handle);
VOID MiniFilterPortFinalize(VOID);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS MiniFilterPortNotifyRoutine(_In_ PFLT_PORT client_port, _In_ PVOID server_cookie,
    _In_ PVOID connection_context, _In_ ULONG connection_context_size,
    _Out_ PVOID* connection_port_cookie);
VOID MiniFilterPortDisconnectRoutine(_In_ PVOID connection_cookie);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS MiniFilterPortMessageRoutine(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength);

_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS MiniFilterPortSendMessage(_In_ PVOID send_data, _In_ ULONG send_data_size,
    _Out_opt_ PVOID recv_buffer, _In_ ULONG recv_buffer_size,
    _Out_ PULONG written_bytes_to_recv_buffer);
