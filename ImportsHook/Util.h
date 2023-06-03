#pragma once
#include "sysntifs.h"

#define Log(...) DbgPrintEx(0, 0, __VA_ARGS__)
#define RELATIVE_ADDR(addr, size) ((PVOID)((PBYTE)(addr) + *(PINT)((PBYTE)(addr) + ((size) - (INT)sizeof(INT))) + (size)))

PVOID GetModuleBaseAddress(PCHAR name, PULONG out_size);