#include "TextHook.h"
#include "Util.h"

struct Driver {
	ULONG_PTR ImageBase;
	ULONG ImageSize;
};

Driver target_driver;

inline void* __CRTDECL operator new(size_t, void* _P) noexcept
{
	return (_P);
}

TextHook* io_hook = nullptr;

bool breakpoint = false;
void Callback() {
	ULONG_PTR returnAddress = (ULONG_PTR)_ReturnAddress();
	if (returnAddress >= target_driver.ImageBase && returnAddress < (target_driver.ImageBase + target_driver.ImageSize)) {
		Log("driver called IofCompleteRequest from %p\n", returnAddress - target_driver.ImageBase);
	}
}

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath
) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	// find the vgc driver:
	target_driver.ImageBase = (ULONG_PTR)GetModuleBaseAddress("ntoskrnl.exe", &target_driver.ImageSize);
	if (!target_driver.ImageBase) {
		Log("Could not find the driver.\n");
		return STATUS_UNSUCCESSFUL;
	}

	io_hook = (TextHook*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(TextHook), 'kooH');

	if (!io_hook) {
		Log("Could not allocate memory for the hook.\n");
		return STATUS_UNSUCCESSFUL;
	}

	// call the constructor
	new (io_hook) TextHook(RTL_CONSTANT_STRING(L"IofCompleteRequest"), (PVOID)Callback);

	return STATUS_SUCCESS;
}