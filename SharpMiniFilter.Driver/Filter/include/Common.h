#pragma once

#define MINIFILTER_PORT_NAME L"\\SharpMiniFilterPort_e5b13067-b42f-4f60-af6a-722f368c47fc"
#define PROTECTOR_PORT_NAME L"\\SharpProtectorPort_a5b44047-b42f-4f40-af6a-722f368c47fc"
#define BUFFER_SIZE 4096

#define AUTH_HMAC_SIZE 32
#define AUTH_VERSION 1
#define NONCE_SIZE 16

#define PORT_CMD_OBC_REPLACE_PROTECT 0x2001u
#define PORT_CMD_OBC_REPLACE_REJECT 0x2002u

typedef struct _MF_PORT_CTX
{
    BOOLEAN Authed;
    ULONG ClientPid;
} MF_PORT_CTX, *PMF_PORT_CTX;

#pragma pack(push, 1)

typedef struct _PORT_OBC_REQ_HDR
{
    ULONG Command;
    ULONG Reserved;
} PORT_OBC_REQ_HDR, *PPORT_OBC_REQ_HDR;

typedef struct _PORT_OBC_BULK_HEAD
{
    ULONG Count;
} PORT_OBC_BULK_HEAD, *PPORT_OBC_BULK_HEAD;

typedef struct _PORT_OBC_BULK_RSP
{
    NTSTATUS Status;
    ULONG Processed;
    ULONG Added;
    ULONG Duplicates;
    ULONG Invalid;
} PORT_OBC_BULK_RSP, *PPORT_OBC_BULK_RSP;

typedef struct _AUTH_HEADER
{
    ULONG Version;
    ULONGLONG Timestamp100ns;
    UCHAR Nonce[NONCE_SIZE];
    UCHAR Hmac[AUTH_HMAC_SIZE];
} AUTH_HEADER, *PAUTH_HEADER;

typedef struct _FLT_TO_USER
{
    wchar_t path[BUFFER_SIZE / sizeof(wchar_t)];
    unsigned int pId;
} FLT_TO_USER, *PFLT_TO_USER;

typedef struct _FLT_TO_USER_REPLY
{
    unsigned __int32 block;
} FLT_TO_USER_REPLY, *PFLT_TO_USER_REPLY;

typedef struct _USER_TO_FLT
{
    wchar_t msg[BUFFER_SIZE / sizeof(wchar_t)];
} USER_TO_FLT, *PUSER_TO_FLT;

typedef struct _USER_TO_FLT_REPLY
{
    wchar_t msg[BUFFER_SIZE / sizeof(wchar_t)];
} USER_TO_FLT_REPLY, *PUSER_TO_FLT_REPLY;

typedef struct _PORT_AUTH_PACKET
{
    AUTH_HEADER Auth;
} PORT_AUTH_PACKET, *PPORT_AUTH_PACKET;

#pragma pack(pop)


typedef struct _PID_SET
{
    ULONG Count;
    ULONG* Items;
} PID_SET;