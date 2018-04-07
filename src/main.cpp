#include <iostream>
#include <Windows.h>
#include <Subauth.h>
#include <Psapi.h>
#include "Utilities\Utils.h"
#include "Memory\Proc.h"
#include "Speedfan\SpeedfanHook.h"




int main()
{
	// Grab the first "svchost.exe" we find (reliable process to find)
	if (!g_pProc->OnSetup("svchost.exe"))
		return 0;

	// Set up hook
	if (!g_pHook->OnSetup())
		return 0;

	// Set hook parameter
	g_pHook->SetHookParams((PVOID)0x4141414141414141);

	// Execute hook
	g_pHook->ExecuteHook(HookFunc);


	
	std::cin.get();
	return 0;
}