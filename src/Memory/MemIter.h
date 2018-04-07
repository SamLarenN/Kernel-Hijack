#ifndef MEMITER_H
#define MEMITER_H
#pragma once

#include <Windows.h>
#include <functional>
#include "Utilities\Superfetch.h"
#include "Memory\MemIterNative.h"


class MemIter
{
public:
	BOOLEAN OnSetup(std::function<BOOLEAN(PVOID, PVOID, ULONG, PVOID)> Callback, std::function<BOOLEAN(uint64_t, DWORD, LPVOID)> ReadPhysicalAddress);
	~MemIter();

	BOOLEAN IterateMemory(const char* Pooltag, PVOID Context);

private:
	BOOLEAN isInRam(uint64_t address, uint32_t len);

private:
	std::function<BOOLEAN(PVOID, PVOID, ULONG, PVOID)> Callback;
	std::function<BOOLEAN(uint64_t, DWORD, LPVOID)> ReadPhysicalAddress;
	SFMemoryInfo m_MemInfo[32];
	int m_InfoCount = 0;
};

#endif // !MEMITER_H

extern MemIter* g_pMemIter;