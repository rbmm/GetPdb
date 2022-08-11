#include "StdAfx.h"

_NT_BEGIN

#include "common.h"
#include "../tkn/tkn.h"
#include "qpm.h"

OBJECT_ATTRIBUTES zoa = { sizeof(zoa) };

NTSTATUS DoIoControl(ULONG code);

ULONG WINAPI EnumAllDlls(PVOID pEnumData)
{
	enum { Size = 0x100000 };//1Mb

	HWND hwnd = reinterpret_cast<EnumData*>(pEnumData)->hwnd;
	ULONG_PTR dwProcessId = reinterpret_cast<EnumData*>(pEnumData)->dwProcessId;
	delete reinterpret_cast<EnumData*>(pEnumData);

	NAMES Table;
	if (Table.Create(Size))
	{
		PSYSTEM_PROCESS_INFORMATION pspi = Table.BuildListOfProcesses(dwProcessId);

		if (pspi)
		{
			static LARGE_INTEGER SectionSize = { MaxThreads << secshift };

			HANDLE hSection;

			if (0 <= NtCreateSection(&hSection, SECTION_ALL_ACCESS, 0, &SectionSize, PAGE_READWRITE, SEC_COMMIT, 0))
			{
				PVOID BaseAddress = 0;
				SIZE_T ViewSize = 0;

				if (0 <= ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0, 0, 0, &ViewSize, ViewUnmap, 0, PAGE_READWRITE))
				{
					DoIoControl(IOCTL_SetProtectedProcess);

					Table.QueryLoop(pspi, hSection, BaseAddress);

					DoIoControl(IOCTL_DelProtectedProcess);

					ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
				}

				NtClose(hSection);
			}
		}
	}

	if (ULONG N = RtlNumberGenericTableElementsAvl(&Table))
	{
		ULONG ofs = N << 2;
		if (PCHAR buf = new CHAR[Table.GetNamesLen() + ofs])
		{
			PULONG pu = (PULONG)buf;
			PSTR psz = RtlOffsetToPointer(pu, ofs);

			PVOID Key = 0;

			while(PCSTR ptr = (PCSTR)RtlEnumerateGenericTableWithoutSplayingAvl(&Table, &Key))
			{
				*pu++ = ofs;
				ULONG len = (ULONG)strlen(ptr + 1) + 2;
				ofs += len;
				memcpy(psz, ptr, len);
				psz += len;
			}

			struct L {
				static int __cdecl compare(void* base, const void* p, const void* q)
				{
					UCHAR a = reinterpret_cast<CNT_MODULE_INFORMATION*>(RtlOffsetToPointer(base, *(ULONG*)p))->LoadCount;
					UCHAR b = reinterpret_cast<CNT_MODULE_INFORMATION*>(RtlOffsetToPointer(base, *(ULONG*)q))->LoadCount;

					if (a < b) return -1;
					if (a > b) return +1;
					return 0;
				}
			};

			qsort_s(buf, N, sizeof(ULONG), L::compare, buf);

			if (SendMessage(hwnd, e_List, N, (LPARAM)buf) != e_List)
			{
				delete [] buf;
			}

			return 0;
		}
	}

	SendMessage(hwnd, e_List, 0, 0);

	ExitThread(0);
}

_NT_END