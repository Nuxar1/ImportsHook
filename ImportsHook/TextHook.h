#pragma once
#include <ntifs.h>
#include <Zydis/Zydis.h>

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
	static PVOID CreateJmpToAddress(PVOID pTarget, ULONG Size);
	static PVOID CreateCallDetour(PVOID pDetour, PVOID pOriginal, PVOID epilogue, ULONG epilogueSize);
};