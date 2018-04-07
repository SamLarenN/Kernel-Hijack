#ifndef SPEEDFAN_HOOK_H
#define SPEEDFAN_HOOK_H
#pragma once

#include <iostream>
#include <Windows.h>



struct HOOKPARAMS
{
	PVOID MmGetSystemRoutineAddress;
	PVOID Context;
};

class SpeedfanHook
{
public:
	BOOLEAN OnSetup();
	SpeedfanHook();
	~SpeedfanHook();

	VOID SetHookParams(PVOID Context) { m_Params.Context = Context; }
	VOID ExecuteHook(PVOID Hook);

private:
	BOOLEAN HookIOCTLFunction();

private:
	uint64_t m_ModuleBase = 0, m_NtBase = 0, m_MmGetSystemRoutineAddressRVA = 0;
	HOOKPARAMS m_Params;
};

#endif // !SPEEDFAN_HOOK_H

extern SpeedfanHook* g_pHook;

void __stdcall HookFunc(HOOKPARAMS* ParamStruct);