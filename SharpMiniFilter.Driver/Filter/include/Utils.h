#pragma once
#include <fltKernel.h>

static __forceinline BOOLEAN IsTimestampWithinTolerance(ULONGLONG ts100ns)
{
    LARGE_INTEGER now;
    KeQuerySystemTime(&now);
    const LONGLONG skew = 5LL * 60 * 10 * 1000 * 1000;
    LONGLONG d = (LONGLONG)ts100ns - now.QuadPart;
    if (d < 0)
        d = -d;
    return d <= skew;
}

static __forceinline BOOLEAN ProtectorStrEqIgnoreCase16(const char* a, const char* b)
{
	for (int i = 0; i < 16; ++i)
	{
		char ca = a[i], cb = b[i];
		if (ca == 0 && cb == 0)
			return TRUE;
		if (ca == 0 || cb == 0)
			return FALSE;
		if (ca >= 'a' && ca <= 'z')
			ca -= ('a' - 'A');
		if (cb >= 'a' && cb <= 'z')
			cb -= ('a' - 'A');
		if (ca != cb)
			return FALSE;
	}
	return TRUE;
}
