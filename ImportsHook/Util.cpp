#include "Util.h"

PVOID GetModuleBaseAddress(PCHAR name, PULONG out_size) {
	PVOID addr = 0;
	ULONG size = 0;
	NTSTATUS status = 0;

retry:

	status = ZwQuerySystemInformation(SystemModuleInformation, (PVOID)0, (ULONG)0, &size);
	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		Log("! ZwQuerySystemInformation for size failed: %p !\n", status);
		return addr;
	}

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePool2((POOL_FLAG_NON_PAGED | POOL_FLAG_UNINITIALIZED), size, POOL_TAG);
	if (!modules) {
		Log("! failed to allocate %d bytes for modules !\n", size);
		return addr;
	}

	if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemModuleInformation, modules, size, 0))) {
		ExFreePoolWithTag(modules, (ULONG)POOL_TAG);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			goto retry;
		}
		else {
			return addr;
		}
	}

	for (ULONG i = 0; i < modules->NumberOfModules; ++i) {
		RTL_PROCESS_MODULE_INFORMATION m = modules->Modules[i];
		if (strstr((char*)m.FullPathName, name)) {
			addr = m.ImageBase;
			if (out_size) {
				*out_size = m.ImageSize;
			}
			break;
		}
	}

	ExFreePoolWithTag(modules, POOL_TAG);
	return addr;
}