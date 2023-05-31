#pragma once
#include <ntifs.h>
#include <intrin.h>
#include <windef.h>
#include <Zydis/Zydis.h>

#define Log(...) DbgPrintEx(0, 0, __VA_ARGS__)

class Instruction
{
public:
	bool m_bValid;

	ZydisDecodedInstruction m_Instruction;
	ZydisDecodedOperand m_Operands[ZYDIS_MAX_OPERAND_COUNT];

	PVOID m_pAddress;
	BYTE m_RawData[ZYDIS_MAX_INSTRUCTION_LENGTH];

	Instruction() : m_bValid(false), m_Instruction(), m_Operands(), m_RawData() {}
	bool Decode(const ZydisDecoder* decoder, PVOID pAddress, ULONG Size)
	{
		m_pAddress = pAddress;
		m_bValid = ZYAN_SUCCESS(ZydisDecoderDecodeFull(decoder, pAddress, Size, &m_Instruction, m_Operands));
		RtlCopyMemory(m_RawData, pAddress, m_Instruction.length);
		return m_bValid;
	}
};

class TextHook
{
	static ZydisDecoder* m_Decoder;

	PVOID m_pTarget;
	PVOID m_pDetour;

	ULONG m_OriginalSize;
	PVOID m_pOriginal; // Original data of the function we want to hook.

	PVOID m_pCallDetour;
	PVOID m_pJmpToCallDetour;

	UNICODE_STRING m_szFunctionName;

	bool m_bEnabled;
public:
	TextHook(UNICODE_STRING szFunctionName, PVOID pTarget, PVOID pDetour);
	TextHook(UNICODE_STRING szFunctionName, PVOID pDetour);
	~TextHook();
	TextHook(const TextHook&) = delete;
	void Enable();
	void Disable();
private:
	static bool WriteReadOnly(PVOID pAddress, PVOID pSource, ULONG Size);

	static constexpr ULONG jumpSize = 12;

	// Creates a jump to the address specified by pTarget.
	// Has to be freed with ExFreePool.
	// Not executable. Copy to executable memory.
	static PVOID CreateJmpToAddress(PVOID pTarget, ULONG Size = jumpSize);

	// returns the new size
	static ULONG CopyInstruction(PVOID pDestination, Instruction* pInstruction, ULONG count);

	// Creates a call to the address specified by pTarget. Preserves parameter registers.
	// The original data (which is overwritten by the jmp) specified with pOriginal is executed after the call.
	// After that it jumps back to the original function (pOriginal+orignalSize-1).
	// The -1 is because rax needs to be poped after the jmp. (See CreateCallDetour)
	// Has to be freed with ExFreePool.
	static PVOID CreateCallDetour(PVOID pDetour, PVOID pOriginal, ULONG originalSize, Instruction* pEpilogue, ULONG count);
};