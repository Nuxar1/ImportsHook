#include "TextHook.h"



NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath
) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	TextHook getPhysAddrHook(RTL_CONSTANT_STRING(L"IofCompleteRequest"), (PVOID)static_cast<void(*)()>([]() { Log("IofCompleteRequest called from %p\n", _ReturnAddress()); }));

	Log(0, 0, "ImportsHook loaded\n");


	// Sleep for 1 seconds.
	LARGE_INTEGER sleep_duration = { 0 };
	sleep_duration.QuadPart = -10000000;
	KeDelayExecutionThread(KernelMode, FALSE, &sleep_duration);

	return STATUS_SUCCESS;
}