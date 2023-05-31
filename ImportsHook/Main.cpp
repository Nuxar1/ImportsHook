#include "TextHook.h"



NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath
) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	TextHook getPhysAddrHook(RTL_CONSTANT_STRING(L"MmGetPhysicalAddress"), (PVOID)static_cast<void(*)()>([]() { DbgPrintEx(0, 0, "MmGetPhysicalAddress called"); }));


	return STATUS_SUCCESS;
}