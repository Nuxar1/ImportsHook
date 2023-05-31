#include "TextHook.h"
#include <intrin.h>
#include <windef.h>

ZydisDecoder* TextHook::m_Decoder = nullptr;

TextHook::TextHook(UNICODE_STRING szFunctionName, PVOID pTarget, PVOID pDetour) : m_pTarget(pTarget), m_pDetour(pDetour), m_OriginalSize(0), m_pOriginal(nullptr), m_bEnabled(false), m_pCallDetour(nullptr), m_pJmpToCallDetour(nullptr), m_szFunctionName(szFunctionName)
{
	if (!m_Decoder) {
		m_Decoder = (ZydisDecoder*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ZydisDecoder), 'roDZ');
		if (!m_Decoder) {
			Log("TextHook: Could not allocate memory for the decoder.\n");
			return;
		}
		ZydisDecoderInit(m_Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
	}

	// Decode the first instructions of the function we want to hook until we have enough bytes to create a jump to the detour function.
	ZydisDecodedInstruction Instruction;
	ULONG Offset = 0;
	while (ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(m_Decoder, (ZydisDecoderContext*)ZYAN_NULL, (PVOID)((ULONG64)pTarget + Offset), jumpSize + 0x10, &Instruction))) {
		Offset += Instruction.length;
		if (Offset >= jumpSize + 1) // jumpsize + 1 byte for pop rax
			break;
	}
	if (Offset < jumpSize + 1) {
		Log("TextHook: Could not find enough bytes to create a jump to the detour function.\n");
		return;
	}

	// Copy the original data of the function we want to hook.
	m_OriginalSize = Offset;
	m_pOriginal = ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, Offset, 'girO');
	if (!m_pOriginal)
		return;

	RtlCopyMemory(m_pOriginal, pTarget, Offset);

	// Create a detour function that calls the detour function.
	m_pCallDetour = CreateCallDetour(m_pDetour, m_pTarget, m_OriginalSize);
	if (!m_pCallDetour)
		return;

	// Create a jump to the detour function.
	m_pJmpToCallDetour = CreateJmpToAddress(m_pCallDetour, m_OriginalSize);
	if (!m_pJmpToCallDetour)
		return;
	((PBYTE)m_pJmpToCallDetour)[m_OriginalSize - 1] = 0x58; // pop rax (restored from epilogue. Check CreateCallDetour()!)

	// Write the jump to the detour function.
	if (!WriteReadOnly(pTarget, m_pJmpToCallDetour, m_OriginalSize)) {
		Log("TextHook: Could not write the jump to the detour function.\n");
		return;
	}

	m_bEnabled = true;

	Log("TextHook: Hooked %wZ at 0x%p.\n", m_szFunctionName, pTarget);
}

TextHook::TextHook(UNICODE_STRING szFunctionName, PVOID pDetour) : TextHook(szFunctionName, MmGetSystemRoutineAddress(&szFunctionName), pDetour) {}

TextHook::~TextHook()
{
	Disable();

	if (m_pCallDetour)
		ExFreePool(m_pCallDetour);

	if (m_pJmpToCallDetour)
		ExFreePool(m_pJmpToCallDetour);

	if (m_pOriginal)
		ExFreePool(m_pOriginal);

	Log("TextHook: Unhooked %wZ.\n", m_szFunctionName);
}

void TextHook::Enable()
{
	if (m_bEnabled)
		return;
	if(!m_pTarget || !m_pJmpToCallDetour || !m_OriginalSize)
		return;
	if (!WriteReadOnly(m_pTarget, m_pJmpToCallDetour, m_OriginalSize)) {
		Log("TextHook: Could not write the jump to the detour function.\n");
		return;
	}
	m_bEnabled = true;
}

void TextHook::Disable()
{
	if (!m_bEnabled)
		return;
	if (!m_pTarget || !m_pOriginal || !m_OriginalSize)
		return;
	if (!WriteReadOnly(m_pTarget, m_pOriginal, m_OriginalSize)) {
		Log("TextHook: Could not write the original data.\n");
		return;
	}
	m_bEnabled = false;
}

bool TextHook::WriteReadOnly(PVOID pAddress, PVOID pSource, ULONG Size)
{
	PMDL Mdl = IoAllocateMdl((PVOID)pAddress, Size, FALSE, FALSE, NULL);
	if (!Mdl)
		return nullptr;

	MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);

	_disable();
	KeEnterGuardedRegion();
	RtlCopyMemory((PVOID)Mapping, pSource, Size);
	KeLeaveGuardedRegion();
	_enable();

	MmUnmapLockedPages(Mapping, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);

	return true;
}

PVOID TextHook::CreateJmpToAddress(PVOID pTarget, ULONG Size)
{
	if (Size < jumpSize)
		return nullptr;

	PBYTE pJmpToAddress = (PBYTE)ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, 'pmtJ');
	if (!pJmpToAddress)
		return nullptr;
	RtlFillMemory(pJmpToAddress, Size, 0x90); // nop

	// mov rax, pTarget
	// jmp rax
	// ...
	// pop rax

	pJmpToAddress[0] = 0x48;
	pJmpToAddress[1] = 0xB8;
	*(PVOID*)(&pJmpToAddress[2]) = pTarget;
	pJmpToAddress[10] = 0xFF;
	pJmpToAddress[11] = 0xE0;

	return pJmpToAddress;
}

PVOID TextHook::CreateCallDetour(PVOID pDetour, PVOID pOriginal, ULONG originalSize)
{
	if (!pDetour || !pOriginal || !originalSize)
		return nullptr;

	// push rcx
	// push rdx
	// push r8
	// push r9
	// sub rsp, 0x20
	// mov rax, pTarget
	// call rax
	// add rsp, 0x20
	// pop r9
	// pop r8
	// pop rdx
	// pop rcx
	// 
	// epilogue
	// push rax
	// JmpToAddress

	BYTE assembly[] = {
		0x51, // push rcx
		0x52, // push rdx
		0x41, 0x50, // push r8
		0x41, 0x51, // push r9
		0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
		0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, // mov rax, pTarget
		0xFF, 0xD0, // call rax
		0x48, 0x83, 0xC4, 0x20, // add rsp, 0x20
		0x41, 0x59, // pop r9
		0x41, 0x58, // pop r8
		0x5A, // pop rdx
		0x59 // pop rcx
	};

	// 1 byte for push rax.
	ULONG callDetourSize = sizeof(assembly) + originalSize + 1 + jumpSize;
	PBYTE pCallDetour = (PBYTE)ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, callDetourSize, 'llaC');
	if (!pCallDetour)
		return nullptr;

	RtlCopyMemory(pCallDetour, assembly, sizeof(assembly));
	*(PVOID*)(&pCallDetour[12]) = pDetour;

	RtlCopyMemory(&pCallDetour[sizeof(assembly)], pOriginal, originalSize);

	PVOID pJmpToAddress = CreateJmpToAddress((PVOID)((ULONG64)pOriginal + originalSize - 1));
	if (!pJmpToAddress) {
		ExFreePool(pCallDetour);
		return nullptr;
	}

	pCallDetour[sizeof(assembly) + originalSize] = 0x50; // push rax

	RtlCopyMemory(&pCallDetour[sizeof(assembly) + originalSize + 1], pJmpToAddress, jumpSize);
	ExFreePool(pJmpToAddress);

	return pCallDetour;
}
