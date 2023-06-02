#pragma once
#include "sysntifs.h"

#define Log(...) DbgPrintEx(0, 0, __VA_ARGS__)

PVOID GetModuleBaseAddress(PCHAR name, PULONG out_size);
