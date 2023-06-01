#include "TextHook.h"

ZydisDecoder* TextHook::m_Decoder = nullptr;

TextHook::TextHook(UNICODE_STRING szFunctionName, PVOID pTarget, PVOID pDetour) : m_pTarget(pTarget), m_pDetour(pDetour), m_OriginalSize(0), m_pOriginal(nullptr), m_bEnabled(false), m_pCallDetour(nullptr), m_pJmpToCallDetour(nullptr), m_szFunctionName(szFunctionName)
{
	if (!m_pTarget || !m_pDetour) {
		Log("TextHook: Invalid parameters (%wZ). pTarget: 0x%p, pDetour: 0x%p.\n", szFunctionName, pTarget, pDetour);
	}

	if (!m_Decoder) {
		m_Decoder = (ZydisDecoder*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ZydisDecoder), 'roDZ');
		if (!m_Decoder) {
			Log("TextHook: Could not allocate memory for the decoder.\n");
			return;
		}
		ZydisDecoderInit(m_Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
	}

	// Decode the first instructions of the function we want to hook until we have enough bytes to create a jump to the detour function.
	//Instruction Instructions[jumpSize];
	Instruction* Instructions = (Instruction*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(Instruction) * jumpSize, 'tsnI');
	if (!Instructions) {
		Log("TextHook: Could not allocate memory for the instructions.\n");
		return;
	}
	ULONG instructionCount = 0;
	ULONG Offset = 0;
	while (Instructions[instructionCount].Decode(m_Decoder, (PVOID)((ULONG64)pTarget + Offset), jumpSize + ZYDIS_MAX_INSTRUCTION_LENGTH - Offset)) {
		Offset += Instructions[instructionCount].m_Instruction.length;
		instructionCount++;
		if (Offset >= jumpSize)
			break;
	}
	if (Offset < jumpSize) {
		Log("TextHook: Could not find enough bytes to create a jump to the detour function.\n");
		return;
	}

	// Copy the original data of the function we want to hook.
	m_OriginalSize = Offset;
	m_pOriginal = ExAllocatePool2(POOL_FLAG_NON_PAGED, m_OriginalSize, 'girO');
	if (!m_pOriginal)
		return;

	RtlCopyMemory(m_pOriginal, pTarget, m_OriginalSize);

	// Create a detour function that calls the detour function.
	m_pCallDetour = CreateCallDetour(m_pDetour, m_pTarget, m_OriginalSize, Instructions, instructionCount);
	if (!m_pCallDetour)
		return;

	// Create a jump to the detour function.
	m_pJmpToCallDetour = CreateJmpToAddress(m_pCallDetour);
	if (!m_pJmpToCallDetour)
		return;

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
	if (!m_pTarget || !m_pJmpToCallDetour || !m_OriginalSize)
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

PVOID TextHook::CreateJmpToAddress(PVOID pTarget)
{
	PBYTE pJmpToAddress = (PBYTE)ExAllocatePool2(POOL_FLAG_NON_PAGED, jumpSize, 'pmtJ');
	if (!pJmpToAddress)
		return nullptr;

	// jmp [rip + 0]

	BYTE jmp[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 }; // jmp [rip + 0]

	RtlCopyMemory(pJmpToAddress, jmp, sizeof(jmp));
	*(PVOID*)(pJmpToAddress + sizeof(jmp)) = pTarget;

	return pJmpToAddress;
}

ULONG TextHook::CopyInstruction(PVOID pDestination, Instruction* pInstruction, ULONG count)
{
	// relative addresses need fixup.
	ULONG Offset = 0;
	ULONG_PTR address = (ULONG_PTR)pDestination;
	for (size_t i = 0; i < count; i++)
	{
		const ZydisDecodedInstruction& instruction = pInstruction[i].m_Instruction;
		const ZydisDecodedOperand* operands = pInstruction[i].m_Operands;


		if (instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE) {

			switch (instruction.meta.category)
			{
			case ZYDIS_CATEGORY_CALL:
			{
				__debugbreak();
				// "call [rip + 0x0]" would work but the return address would be at the the data we call and not after that.
				// thats why we use: 
				// push 0xABC (the lower bits)
				// push 0xDEF (the higher bits)
				// jmp target (absolute address, encoded as jmp [rip + 0x0])
				ULONG_PTR target = (ULONG_PTR)pInstruction[i].m_pAddress + instruction.length + operands[0].imm.value.s;
				BYTE push_rax[] = { 0x50 }; // push rax to decrement the stack pointer
				BYTE mov_rsp_higher[] = { 0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00 }; // mov [rsp + 0x4], 0x0
				BYTE mov_rsp_lower[] = { 0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00 }; // mov [rsp], 0x0
				BYTE jmp_far[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
				ULONG_PTR returnAddress = address + Offset + sizeof(mov_rsp_higher) + sizeof(mov_rsp_higher) + sizeof(jmp_far);
				UINT32 lower = (UINT32)returnAddress;
				UINT32 higher = (UINT32)(returnAddress >> 32);
				*(UINT32*)(&mov_rsp_lower[3]) = lower;
				*(UINT32*)(&mov_rsp_higher[4]) = higher;
				*(ULONG_PTR*)(&jmp_far[6]) = target;

				RtlCopyMemory((PVOID)(address + Offset), push_rax, sizeof(push_rax));
				Offset += sizeof(push_rax);

				RtlCopyMemory((PVOID)(address + Offset), mov_rsp_lower, sizeof(mov_rsp_lower));
				Offset += sizeof(mov_rsp_lower);

				RtlCopyMemory((PVOID)(address + Offset), mov_rsp_higher, sizeof(mov_rsp_higher));
				Offset += sizeof(mov_rsp_higher);

				RtlCopyMemory((PVOID)(address + Offset), jmp_far, sizeof(jmp_far));
				Offset += sizeof(jmp_far);
				break;
			}
			case ZYDIS_CATEGORY_COND_BR:
			{
				__debugbreak();
				// only jmp can jump to 64 bit absolute addresses
				//	jcc DO_JUMP 
				//	jmp NO_JUMP
				// DO_JUMP:
				//	jmp target (actually encoded as jmp [rip + 0x0])
				// NO_JUMP:
				ULONG_PTR target = (ULONG_PTR)pInstruction[i].m_pAddress + instruction.length + operands[0].imm.value.s;

				BYTE jmp_far[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
				*(ULONG_PTR*)(&jmp_far[6]) = target;

				BYTE jmp_no_jump[] = { 0xEB, sizeof(jmp_far) };


				ZydisEncoderRequest jcc_do_jump;
				RtlFillMemory(&jcc_do_jump, sizeof(jcc_do_jump), 0);
				jcc_do_jump.machine_mode = instruction.machine_mode;
				jcc_do_jump.mnemonic = instruction.mnemonic;
				jcc_do_jump.operand_count = 1;
				jcc_do_jump.operands[0].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
				jcc_do_jump.operands[0].imm.s = sizeof(jmp_no_jump);
				ZyanUSize encoded_length = ZYDIS_MAX_INSTRUCTION_LENGTH;
				ZydisEncoderEncodeInstruction(&jcc_do_jump, (PVOID)(address + Offset), &encoded_length); // jcc DO_JUMP
				Offset += (ULONG)encoded_length;

				RtlCopyMemory((PVOID)(address + Offset), jmp_no_jump, sizeof(jmp_no_jump)); // jmp NO_JUMP
				Offset += sizeof(jmp_no_jump);

				RtlCopyMemory((PVOID)(address + Offset), jmp_far, sizeof(jmp_far)); // jmp target
				Offset += sizeof(jmp_far);
				break;
			}
			case ZYDIS_CATEGORY_UNCOND_BR:
			{
				__debugbreak();
				// jmp [rip + 0x0] can jump to 64 bit absolute addresses
				ULONG_PTR target = (ULONG_PTR)pInstruction[i].m_pAddress + instruction.length + operands[0].imm.value.s;
				BYTE jmp_far[] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
				*(ULONG_PTR*)(&jmp_far[6]) = target;

				RtlCopyMemory((PVOID)(address + Offset), jmp_far, sizeof(jmp_far));
				Offset += sizeof(jmp_far);

				break;
			}
			default:
			{
				__debugbreak();
				ZydisEncoderRequest req;
				ZydisEncoderDecodedInstructionToEncoderRequest(&instruction, pInstruction[i].m_Operands, instruction.operand_count_visible, &req);
				for (size_t j = 0; j < req.operand_count; j++) {
					ZydisEncoderOperand& operand = req.operands[j];

					if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY && operand.mem.base == ZYDIS_REGISTER_RIP) {
						ULONG_PTR memoryTarget = (ULONG_PTR)pInstruction[i].m_pAddress + instruction.length + operand.mem.displacement;

						operand.mem.base = ZYDIS_REGISTER_NONE;
						operand.mem.displacement = memoryTarget;

						Log("TextHook: Fixup relative address at %p from 0x%x to %p\n", address, pInstruction[i].m_Operands[j].mem.disp.value, memoryTarget);
					}
				}

				ZyanU8 encoded_instruction[ZYDIS_MAX_INSTRUCTION_LENGTH] = { 0 };
				ZyanUSize encoded_length = sizeof(encoded_instruction);
				if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, encoded_instruction, &encoded_length)))
				{
					Log("TextHook: Failed to encode instruction.\n");
					return 0;
				}
				RtlCopyMemory((PVOID)(address + Offset), encoded_instruction, encoded_length);
				Offset += (ULONG)encoded_length;
				break;
			}
			}

		}
		else {
			RtlCopyMemory((PVOID)(address + Offset), pInstruction[i].m_RawData, instruction.length);
			Offset += instruction.length;	
		}
	}
	return Offset;
}

PVOID TextHook::CreateCallDetour(PVOID pDetour, PVOID pOriginal, ULONG originalSize, Instruction* pEpilogue, ULONG count)
{
	if (!pDetour || !pOriginal || !originalSize)
		return nullptr;

	// Todo: SwapContext and RestoreContext instead of just registers for parameters
	// 
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
	// epilogue <--- CopyInstruction
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

	// double of original size since relative addresses need fixup and we don't know the size yet.
	ULONG callDetourSize = sizeof(assembly) + originalSize * 3 + jumpSize;
	PBYTE pCallDetour = (PBYTE)ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE, callDetourSize, 'llaC');
	if (!pCallDetour)
		return nullptr;

	RtlCopyMemory(pCallDetour, assembly, sizeof(assembly));
	*(PVOID*)(&pCallDetour[12]) = pDetour;

	ULONG newInstructionsSize = CopyInstruction(pCallDetour + sizeof(assembly), pEpilogue, count);

	PVOID pJmpToAddress = CreateJmpToAddress((PVOID)((ULONG64)pOriginal + originalSize));
	if (!pJmpToAddress) {
		ExFreePool(pCallDetour);
		return nullptr;
	}

	RtlCopyMemory(&pCallDetour[sizeof(assembly) + newInstructionsSize], pJmpToAddress, jumpSize);
	ExFreePool(pJmpToAddress);

	return pCallDetour;
}
