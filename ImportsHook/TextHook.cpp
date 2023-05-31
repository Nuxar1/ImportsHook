#include "TextHook.h"
#include <windef.h>

ZydisDecoder* TextHook::m_Decoder = nullptr;

TextHook::TextHook(UNICODE_STRING szFunctionName, PVOID pTarget, PVOID pDetour) : m_pTarget(pTarget), m_pDetour(pDetour), m_OriginalSize(0), m_pOriginal(nullptr), m_bEnabled(false), m_pCallDetour(nullptr), m_pJmpToCallDetour(nullptr), m_szFunctionName(szFunctionName)
{
	if (!m_Decoder) {
		m_Decoder = (ZydisDecoder*)ExAllocatePool2(NonPagedPool, sizeof(ZydisDecoder), 'roDZ');
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
		DbgPrint("TextHook: Could not find enough bytes to create a jump to the detour function.");
		return;
	}

	PVOID endOfHook = (PVOID)((ULONG64)pTarget + Offset);

	// Copy the original data of the function we want to hook.
	m_OriginalSize = Offset;
	m_pOriginal = ExAllocatePool2(NonPagedPool, Offset, 'girO');
	if (!m_pOriginal)
		return;

	RtlCopyMemory(m_pOriginal, pTarget, Offset);

	// Create a detour function that calls the detour function.
	m_pCallDetour = CreateCallDetour(m_pDetour, endOfHook, m_pOriginal, m_OriginalSize);
	if (!m_pCallDetour)
		return;

	// Create a jump to the detour function.
	m_pJmpToCallDetour = CreateJmpToAddress(m_pCallDetour, m_OriginalSize);
	if (!m_pJmpToCallDetour)
		return;
	((PBYTE)m_pJmpToCallDetour)[m_OriginalSize - 1] = 0x58; // pop rax (restored from epilogue. Check CreateCallDetour()!)

	// Write the jump to the detour function.
	if (!WriteReadOnly(pTarget, m_pJmpToCallDetour, m_OriginalSize)) {
		DbgPrint("TextHook: Could not write the jump to the detour function.");
		return;
	}

	m_bEnabled = true;

	DbgPrint("TextHook: Hooked %wZ at 0x%p.", m_szFunctionName, pTarget);
}

TextHook::TextHook(UNICODE_STRING szFunctionName, PVOID pDetour) : TextHook(szFunctionName, MmGetSystemRoutineAddress(&szFunctionName), pDetour) {}

TextHook::~TextHook()
{
	m_bEnabled = false;

	if (m_pOriginal) {
		// Restore the original data of the function we want to hook.
		WriteReadOnly(m_pTarget, m_pOriginal, m_OriginalSize);
		ExFreePool(m_pOriginal);
	}

	if (m_pJmpToCallDetour)
		ExFreePool(m_pJmpToCallDetour);

	if (m_pCallDetour)
		ExFreePool(m_pCallDetour);
}

void TextHook::Enable()
{
	if (m_bEnabled)
		return;
	if (!WriteReadOnly(m_pTarget, m_pJmpToCallDetour, m_OriginalSize)) {
		DbgPrint("TextHook: Could not write the jump to the detour function.");
		return;
	}
	m_bEnabled = true;
}

void TextHook::Disable()
{
	if (!m_bEnabled)
		return;
	if (!WriteReadOnly(m_pTarget, m_pOriginal, m_OriginalSize)) {
		DbgPrint("TextHook: Could not write the original data.");
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

	RtlCopyMemory((PVOID)Mapping, pSource, Size);

	MmUnmapLockedPages(Mapping, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);

	return true;
}

PVOID TextHook::CreateJmpToAddress(PVOID pTarget, ULONG Size)
{
	if (Size < jumpSize)
		return nullptr;

	PBYTE pJmpToAddress = (PBYTE)ExAllocatePool2(NonPagedPool, Size, 'pmtJ');
	if (!pJmpToAddress)
		return nullptr;

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

PVOID TextHook::CreateCallDetour(PVOID pDetour, PVOID pOriginal, PVOID epilogue, ULONG epilogueSize)
{
	if (!pDetour || !pOriginal || !epilogue || !epilogueSize)
		return nullptr;
	// 32 bytes for the call detour.
	// 1 byte for push rax.
	ULONG callDetourSize = 32 + epilogueSize + 1 + jumpSize;
	PBYTE pCallDetour = (PBYTE)ExAllocatePool2(NonPagedPool, callDetourSize, 'llaC');
	if (!pCallDetour)
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

	// JmpToAddress jumps to the original function BUT! -1 to pop rax.
	pCallDetour[0] = 0x51; // push rcx
	pCallDetour[1] = 0x52; // push rdx
	pCallDetour[2] = 0x41; pCallDetour[3] = 0x50; // push r8 
	pCallDetour[4] = 0x41; pCallDetour[5] = 0x51; // push r9
	pCallDetour[7] = 0x48; pCallDetour[8] = 0x83; pCallDetour[9] = 0xEC; pCallDetour[10] = 0x20; // sub rsp, 0x20
	pCallDetour[11] = 0x48; pCallDetour[12] = 0xB8; *(PVOID*)(&pCallDetour[13]) = pDetour; // mov rax, pDetour
	pCallDetour[21] = 0xFF; pCallDetour[22] = 0xD0; // call rax
	pCallDetour[23] = 0x48; pCallDetour[24] = 0x83; pCallDetour[25] = 0xC4; pCallDetour[26] = 0x20; // add rsp, 0x20
	pCallDetour[27] = 0x41; pCallDetour[28] = 0x59; // pop r9
	pCallDetour[29] = 0x41; pCallDetour[30] = 0x58; // pop r8
	pCallDetour[31] = 0x5A; // pop rdx
	pCallDetour[32] = 0x59; // pop rcx

	RtlCopyMemory(&pCallDetour[33], epilogue, epilogueSize);

	PVOID pJmpToAddress = CreateJmpToAddress((PVOID)((ULONG64)pOriginal + epilogueSize), jumpSize);
	if (!pJmpToAddress) {
		ExFreePool(pCallDetour);
		return nullptr;
	}
	RtlCopyMemory(&pCallDetour[33 + epilogueSize], pJmpToAddress, jumpSize);
	ExFreePool(pJmpToAddress);

	return pCallDetour;
}
