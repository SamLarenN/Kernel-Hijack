#ifndef UTILS_H
#define UTILS_H
#pragma once
#include <Windows.h>
#include <string>





class Utils
{
public:
	Utils();
	~Utils();

public:
	BOOLEAN EnablePrivilege(const char* lpPrivilegeName);
	BOOLEAN RegisterService(std::string ServicePath, std::string *ServiceRegKey);
	NTSTATUS LoadDriver(std::string ServiceRegKey);
	NTSTATUS UnloadDriver(std::string ServiceRegKey);
	int isAscii(int c);
	int isPrintable(uint32_t uint32);
	char* ToLower(char* szText);

	PVOID GetSystemRoutine(PVOID MmGetSystemRoutineAddress, const wchar_t* RoutineName);

private:
	BOOLEAN InitNativeFuncs();


	BOOLEAN m_bIsNativeInitialized = false;
};

#endif // !UTILS_H

extern Utils* g_pUtils;