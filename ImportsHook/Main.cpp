#include "TextHook.h"
#include "Util.h"

#define CREATE_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define REMOVE_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define ENABLE_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define DISABLE_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define REMOVE_ALL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define SET_TARGET CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_NEITHER, FILE_SPECIAL_ACCESS)

struct Driver {
	ULONG_PTR ImageBase;
	ULONG ImageSize;
};
Driver target_driver;

constexpr int max_hooks = 0x100;
TextHook* io_hooks[max_hooks];
int hook_count = 0;

void HookCallback(TextHook* object) {
	ULONG_PTR return_address = (ULONG_PTR)_ReturnAddress();
	if (return_address >= target_driver.ImageBase && return_address < target_driver.ImageBase + target_driver.ImageSize) {
		Log("Callback called: %sZ\n", object->m_szFunctionName);
		return;
	}
}

NTSTATUS IoControl(ULONG ControlCode, const wchar_t* InputBuffer) {
	switch (ControlCode)
	{
	case CREATE_HOOK:
	{
		if (hook_count >= max_hooks) {
			Log("Too many hooks.\n");
			return 0;
		}

		UNICODE_STRING target;
		RtlInitUnicodeString(&target, InputBuffer);
		// check if the hook already exists
		for (size_t i = 0; i < hook_count; i++)
		{
			if (RtlCompareUnicodeString(&target, &io_hooks[i]->m_szFunctionName, FALSE) == 0) {
				Log("Hook already exists.\n");
				return STATUS_UNSUCCESSFUL;
			}
		}

		TextHook* allocation = (TextHook*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(TextHook), 'kooH');
		if (!allocation) {
			Log("Could not allocate memory for the hook.\n");
			return STATUS_UNSUCCESSFUL;
		}

		// call the constructor
		io_hooks[hook_count++] = new (allocation) TextHook(target, (PVOID)HookCallback);
		break;
	}
	case REMOVE_HOOK:
	{
		for (size_t i = 0; i < hook_count; i++)
		{
			UNICODE_STRING target;
			RtlInitUnicodeString(&target, InputBuffer);
			if (RtlCompareUnicodeString(&target, &io_hooks[i]->m_szFunctionName, FALSE) == 0) {
				io_hooks[i]->~TextHook();
				ExFreePoolWithTag(io_hooks[i], 'kooH');
				io_hooks[i] = nullptr;
				break;
			}
		}

		// remove the null pointer
		for (size_t i = 0; i < hook_count; i++)
		{
			if (!io_hooks[i]) {
				for (size_t j = i; j < hook_count - 1; j++)
				{
					io_hooks[j] = io_hooks[j + 1];
				}
				io_hooks[hook_count - 1] = nullptr;
				hook_count--;
				break;
			}
		}
		break;
	}
	case ENABLE_HOOK:
	{
		UNICODE_STRING target;
		RtlInitUnicodeString(&target, InputBuffer);
		for (size_t i = 0; i < hook_count; i++)
		{
			if (RtlCompareUnicodeString(&target, &io_hooks[i]->m_szFunctionName, FALSE) == 0) {
				io_hooks[i]->Enable();
				break;
			}
		}
		break;
	}
	case DISABLE_HOOK:
	{
		UNICODE_STRING target;
		RtlInitUnicodeString(&target, InputBuffer);
		for (size_t i = 0; i < hook_count; i++)
		{
			if (RtlCompareUnicodeString(&target, &io_hooks[i]->m_szFunctionName, FALSE) == 0) {
				io_hooks[i]->Disable();
				break;
			}
		}
		break;
	}
	case REMOVE_ALL:
	{
		for (size_t i = 0; i < hook_count; i++)
		{
			io_hooks[i]->~TextHook();
			ExFreePoolWithTag(io_hooks[i], 'kooH');
			io_hooks[i] = nullptr;
		}
		hook_count = 0;
		break;
	}
	case SET_TARGET:
	{
		ANSI_STRING target{ 0 };
		UNICODE_STRING unicode_target{ 0 };
		RtlInitUnicodeString(&unicode_target, InputBuffer);
		NTSTATUS status = RtlUnicodeStringToAnsiString(&target, &unicode_target, TRUE);
		if (!NT_SUCCESS(status)) {
			Log("Could not convert the string.\n");
			return STATUS_UNSUCCESSFUL;
		}

		// find the target driver
		target_driver.ImageBase = (ULONG_PTR)GetModuleBaseAddress(target.Buffer, &target_driver.ImageSize);
		if (!target_driver.ImageBase) {
			Log("Could not find the driver.\n");
			return STATUS_UNSUCCESSFUL;
		}

		RtlFreeAnsiString(&target);
		break;
	}
	}
	return STATUS_SUCCESS;
}

NTSTATUS Dispatch(PDEVICE_OBJECT DeviceObject, _IRP* Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	NTSTATUS io_status = IoControl(stack->Parameters.DeviceIoControl.IoControlCode, (const wchar_t*)stack->Parameters.DeviceIoControl.Type3InputBuffer);

	Irp->IoStatus.Status = io_status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

void DriverUnload(PDRIVER_OBJECT driver_object) {
	UNICODE_STRING symlink_name = RTL_CONSTANT_STRING(L"\\??\\IOHook");
	IoDeleteSymbolicLink(&symlink_name);
	IoDeleteDevice(driver_object->DeviceObject);

	IoControl(REMOVE_ALL, L"");

	Log("Driver unloaded.\n");
}

NTSTATUS DriverInitialize(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
	UNREFERENCED_PARAMETER(registry_path);

	// create a device object
	UNICODE_STRING device_name = RTL_CONSTANT_STRING(L"\\Device\\IOHook");
	PDEVICE_OBJECT device_object;
	if (!NT_SUCCESS(IoCreateDevice(driver_object, 0, &device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_object))) {
		Log("Could not create the device object.\n");
		return STATUS_UNSUCCESSFUL;
	}

	// create a symbolic link
	UNICODE_STRING symlink_name = RTL_CONSTANT_STRING(L"\\DosDevices\\IOHook");
	if (!NT_SUCCESS(IoCreateSymbolicLink(&symlink_name, &device_name))) {
		Log("Could not create the symbolic link.\n");
		IoDeleteDevice(device_object);
		return STATUS_UNSUCCESSFUL;
	}

	driver_object->DriverUnload = DriverUnload;

	const auto do_nothing = [](PDEVICE_OBJECT, PIRP irp) {
		irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	};
	driver_object->MajorFunction[IRP_MJ_CREATE] = do_nothing;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = do_nothing;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = Dispatch;

	Log("Driver initialized.\n");
	Log("Driver object: 0x%p, deviceobject: 0x%p\n", driver_object, driver_object->DeviceObject);

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT  DriverObject,
	_In_ PUNICODE_STRING RegistryPath
) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	target_driver.ImageBase = 0;
	target_driver.ImageSize = 0;

	//DriverInitialize(DriverObject, RegistryPath);
	// Create a driver object
	UNICODE_STRING driver_name = RTL_CONSTANT_STRING(L"\\Driver\\IOHook");
	if (!NT_SUCCESS(IoCreateDriver(&driver_name, &DriverInitialize))) {
		Log("Could not create the driver object.\n");
		return STATUS_UNSUCCESSFUL;
	}

	Log("Driver loaded.\n");

	return STATUS_SUCCESS;
}