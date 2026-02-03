#pragma once

#define IF_ERROR(func_name, to)                                                                \
	if (!NT_SUCCESS(status))                                                                   \
	{                                                                                          \
		DbgPrint("[Filter] " __FUNCTION__ " - " #func_name " failed (status: 0x%x)", status); \
		goto to;                                                                               \
	}