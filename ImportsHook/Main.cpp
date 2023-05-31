#include "TextHook.h"

inline void* __CRTDECL operator new(size_t, void* _P) noexcept
{
	return (_P);
}

TextHook* io_hook = nullptr;


void Callback() {
	Log("IofCompleteRequest: %p\n", _ReturnAddress());
}

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath
) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	io_hook = (TextHook*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(TextHook), 'kooH');

	if (!io_hook) {
		Log("Could not allocate memory for the hook.\n");
		return STATUS_UNSUCCESSFUL;
	}

	// call the constructor
	new (io_hook) TextHook(RTL_CONSTANT_STRING(L"IofCompleteRequest"), (PVOID)Callback);

	return STATUS_SUCCESS;
}