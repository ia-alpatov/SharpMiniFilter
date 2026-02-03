#include <ntifs.h>
#include <bcrypt.h>
#pragma comment(lib, "ksecdd.lib")

NTSTATUS AuthVerifyHmac(
    const UCHAR *Key, ULONG KeyLen,
    const UCHAR *HeaderPrefix, ULONG HeaderLen,
    const UCHAR *Body, ULONG BodyLen,
    const UCHAR *ReceivedHmac)
{
    NTSTATUS st;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PUCHAR hashObj = NULL;
    ULONG hashObjLen = 0, resLen = 0;
    UCHAR calc[32] = {0};

    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(st))
        goto Exit;

    st = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjLen, sizeof(hashObjLen), &resLen, 0);
    if (!NT_SUCCESS(st))
        goto Exit;

    hashObj = ExAllocatePool2(POOL_FLAG_NON_PAGED, hashObjLen, 'mHaU');
    if (!hashObj)
    {
        st = STATUS_NO_MEMORY;
        goto Exit;
    }

    st = BCryptCreateHash(hAlg, &hHash, hashObj, hashObjLen, (PUCHAR)Key, KeyLen, 0);
    if (!NT_SUCCESS(st))
        goto Exit;

    if (HeaderLen)
        st = BCryptHashData(hHash, (PUCHAR)HeaderPrefix, HeaderLen, 0);
    if (!NT_SUCCESS(st))
        goto Exit;

    if (BodyLen && Body)
        st = BCryptHashData(hHash, (PUCHAR)Body, BodyLen, 0);
    if (!NT_SUCCESS(st))
        goto Exit;

    st = BCryptFinishHash(hHash, calc, sizeof(calc), 0);
    if (!NT_SUCCESS(st))
        goto Exit;

    st = (RtlCompareMemory(calc, ReceivedHmac, 32) == 32)
             ? STATUS_SUCCESS
             : STATUS_ACCESS_DENIED;

Exit:
    if (hHash)
        BCryptDestroyHash(hHash);
    if (hashObj)
        ExFreePoolWithTag(hashObj, 'mHaU');
    if (hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);
    return st;
}