#ifndef SUPERFETCH_H
#define SUPERFETCH_H
#pragma once

#include <Windows.h>
#include <memory>
#include <Psapi.h>
#include "Utilities\SuperfetchNative.h"

struct SFMemoryInfo
{
	uint64_t Start;
	uint64_t End;
	int PageCount;
	uint64_t Size;
};

class Superfetch
{
public:
	Superfetch();
	~Superfetch();



	template<typename SYS_TYPE>
	std::unique_ptr<SYS_TYPE>
		QueryInfo(
			__in SYSTEM_INFORMATION_CLASS sysClass
		)
	{
		size_t size = sizeof(RTL_PROCESS_MODULES) + SPAGE_SIZE;
		NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
		void* info = malloc(size);
		if (!info)
			return std::unique_ptr<SYS_TYPE>(nullptr);

		for (; STATUS_INFO_LENGTH_MISMATCH == status; size *= 2)
		{
			status = NtQuerySystemInformation(
				(SYSTEM_INFORMATION_CLASS)sysClass,
				info,
				size,
				nullptr);

			info = realloc(info, size * 2);
			if (!info)
				break;
		}

		std::unique_ptr<SYS_TYPE> r_info = std::unique_ptr<SYS_TYPE>(static_cast<SYS_TYPE*>(info));
		return r_info;
	}


	inline void SFBuildInfo(IN PSUPERFETCH_INFORMATION SuperfetchInfo, IN PVOID Buffer, IN ULONG Length, IN SUPERFETCH_INFORMATION_CLASS InfoClass) {
		SuperfetchInfo->Version = SUPERFETCH_VERSION;
		SuperfetchInfo->Magic = SUPERFETCH_MAGIC;
		SuperfetchInfo->Data = Buffer;
		SuperfetchInfo->Length = Length;
		SuperfetchInfo->InfoClass = InfoClass;
	}


	bool SFSetup()
	{
		BOOLEAN old;
		auto status = RtlAdjustPrivilege(SE_PROF_SINGLE_PROCESS_PRIVILEGE, TRUE, FALSE, &old);
		status |= RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &old);
		if (!NT_SUCCESS(status))
			return false;

		SYSTEM_BASIC_INFORMATION basicInfo;

		status = NtQuerySystemInformation(SystemBasicInformation,
			&basicInfo, sizeof(SYSTEM_BASIC_INFORMATION), nullptr);
		if (!NT_SUCCESS(status))
			return false;


		return true;
	}


	bool SFGetMemoryInfo(SFMemoryInfo* pInfo, int& rCount)
	{
		PPF_MEMORY_RANGE_INFO MemoryRanges;
		SUPERFETCH_INFORMATION SuperfetchInfo;
		ULONG ResultLength = 0;
		PF_MEMORY_RANGE_INFO MemoryRangeInfo;
		MemoryRangeInfo.Version = 1;
		SFBuildInfo(&SuperfetchInfo, &MemoryRangeInfo, sizeof(MemoryRangeInfo), SuperfetchMemoryRangesQuery);

		if (
			NtQuerySystemInformation(SystemSuperfetchInformation, &SuperfetchInfo, sizeof(SuperfetchInfo), &ResultLength)
			== STATUS_BUFFER_TOO_SMALL)
		{
			MemoryRanges = static_cast<PPF_MEMORY_RANGE_INFO>(HeapAlloc(GetProcessHeap(), 0, ResultLength));
			MemoryRanges->Version = 1;
			SFBuildInfo(&SuperfetchInfo, MemoryRanges, ResultLength, SuperfetchMemoryRangesQuery);
			if (!NT_SUCCESS(NtQuerySystemInformation(SystemSuperfetchInformation, &SuperfetchInfo, sizeof(SuperfetchInfo), &ResultLength)))
				return false;
		}
		else {
			MemoryRanges = &MemoryRangeInfo;
		}

		rCount = 0;
		PPHYSICAL_MEMORY_RUN Node;
		for (ULONG i = 0; i < MemoryRanges->RangeCount; i++) {
			Node = reinterpret_cast<PPHYSICAL_MEMORY_RUN>(&MemoryRanges->Ranges[i]);
			pInfo[i].Start = Node->BasePage << PAGE_SHIFT;
			pInfo[i].End = (Node->BasePage + Node->PageCount) << PAGE_SHIFT;
			pInfo[i].PageCount = Node->PageCount;
			pInfo[i].Size = ((Node->PageCount << PAGE_SHIFT) >> 10) * 1024; // kb to byte
			rCount++;
		}
		return true;
	}


	uint64_t SFGetModuleBase(const char* module)
	{
		auto module_info = QueryInfo<RTL_PROCESS_MODULES>(SystemModuleInformation);

		for (size_t i = 0; i < module_info->NumberOfModules; i++)
			if (!_strnicmp(module, module_info.get()->Modules[i].FullPathName + module_info->Modules[i].OffsetToFileName, strlen(module) + 1))
				return reinterpret_cast<size_t>(module_info->Modules[i].ImageBase);

		return 0;
	}


	uint64_t SFGetNativeProcedureRVA(const char* lpProcedure)
	{
		uint64_t MmGetSystemRoutineAddress = 0;
		char szSystemPath[MAX_PATH] = { 0 };
		MODULEINFO modInfo;

		GetSystemDirectoryA(szSystemPath, MAX_PATH);
		strcat_s(szSystemPath, "\\ntoskrnl.exe");

		HMODULE MappedImage = LoadLibraryExA(szSystemPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
		if (!MappedImage)
			return 0;

		if (!GetModuleInformation(GetCurrentProcess(), MappedImage, &modInfo, sizeof(modInfo)))
		{
			FreeModule(MappedImage);
			return 0;
		}

		
		MmGetSystemRoutineAddress = (uint64_t)GetProcAddress(MappedImage, lpProcedure);
		MmGetSystemRoutineAddress -= (uint64_t)modInfo.lpBaseOfDll;

		FreeModule(MappedImage);
		return MmGetSystemRoutineAddress;
	}
};

#endif // !SUPERFETCH_H

extern Superfetch* g_pFetch;