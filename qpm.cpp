#include "stdafx.h"

#include "..\NtVer\nt_ver.h"
_NT_BEGIN

#include "../tkn/tkn.h"
#include "qpm.h"

extern HANDLE g_hDrv;

NTSTATUS DoIoControl(ULONG code)
{
	IO_STATUS_BLOCK iosb;
	return g_hDrv ? NtDeviceIoControlFile(g_hDrv, 0, 0, 0, &iosb, code, 0, 0, 0, 0) : STATUS_INVALID_HANDLE;
}

NTSTATUS MyOpenProcess(PHANDLE ProcessHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID Cid)
{
	if (g_hDrv)
	{
		IO_STATUS_BLOCK iosb;
		NTSTATUS status = NtDeviceIoControlFile(g_hDrv, 0, 0, 0, &iosb, IOCTL_OpenProcess, &Cid->UniqueProcess, sizeof(HANDLE), 0, 0);
		*ProcessHandle = (HANDLE)iosb.Information;
		return status;
	}
	return NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, Cid);
}

#ifdef _WIN64

#include "../wow/wow.h"

BEGIN_DLL_FUNCS(ntdll, 0)
	FUNC(LdrQueryProcessModuleInformation),
	FUNC(RtlExitUserThread),
END_DLL_FUNCS();

void InitWow64()
{
	DLL_LIST_0::Process(&ntdll);
}

#endif

BOOLEAN IsExportSuppressionEnabled(HANDLE hProcess);
NTSTATUS SetExportValid(HANDLE hProcess, LPCVOID pv1, LPCVOID pv2);

struct THREAD_INFO  
{
	union {
		HANDLE hProcess;
		struct  
		{
			ULONG_PTR IsWow64Process : 1;
			ULONG_PTR ExportSuppressed : 1;
		};
	};

	union {
		HANDLE hThread;
		struct  
		{
			ULONG_PTR IsWow64Thread : 1;
		};
	};

	PVOID RemoteViewBase;
	PSYSTEM_PROCESS_INFORMATION pspi;

	void Cleanup()
	{
		ZwUnmapViewOfSection(hProcess, RemoteViewBase), RemoteViewBase = 0;
		NtClose(hProcess), hProcess = 0;
	}
};

ULONG FormatWaitArray(_In_ THREAD_INFO* pta, ULONG n, _Out_ PHANDLE lpHandles, _Out_ PULONG Indexes)
{
	ULONG nCount = 0, i = 0;
	do 
	{
		if (HANDLE hThread = pta++->hThread)
		{
			*Indexes++ = i, *lpHandles++ = hThread, nCount++;
		}
	} while (i++, --n);

	return nCount;
}

void NAMES::AddName(PSTR Name)
{
	ULONG len = (ULONG)strlen(Name) + 2;
	*--Name = 0;

	BOOLEAN bNew;
	if (Name = (PSTR)RtlInsertElementGenericTableAvl(this, Name, len, &bNew))
	{
		++*Name;
		if (bNew)
		{
			_cbNames += len;
		}
	}
}

BOOL NAMES::Create(ULONG size)
{
	if (PVOID pv = VirtualAlloc(0, size, MEM_COMMIT, PAGE_READWRITE))
	{
		Init(pv);
		_cbFree = size;

		return TRUE;
	}

	return FALSE;
}

PSYSTEM_PROCESS_INFORMATION NAMES::BuildListOfProcesses(ULONG_PTR dwProcessId)
{
	union {
		PVOID buf;
		PSYSTEM_PROCESS_INFORMATION pspi;
	};

	buf = RtlOffsetToPointer(TableContext, _cbUsed);

	ULONG cb;

	if (dwProcessId)
	{
		if (_cbFree < sizeof(SYSTEM_PROCESS_INFORMATION))
		{
			return 0;
		}
		cb = sizeof(SYSTEM_PROCESS_INFORMATION);
		pspi->NextEntryOffset = 0;
		pspi->UniqueProcessId = (HANDLE)dwProcessId;
		pspi->InheritedFromUniqueProcessId = dwProcessId == 4 ? 0 : INVALID_HANDLE_VALUE;
	}
	else if (0 > NtQuerySystemInformation(SystemProcessInformation, buf, _cbFree, &cb))
	{
		return 0;
	}

	cb = (cb + __alignof(PVOID) - 1) & ~(__alignof(PVOID) - 1);

	_cbFree -= cb, _cbUsed += cb;

	return pspi;
}

PVOID NTAPI NAMES::alloc (_In_ PRTL_AVL_TABLE Table, _In_ CLONG ByteSize)
{
	ULONG cbFree = static_cast<NAMES*>(Table)->_cbFree;

	if ((ULONG)(ByteSize = (ByteSize + __alignof(PVOID) - 1) & ~(__alignof(PVOID) - 1)) < cbFree)
	{
		PVOID pv = (PBYTE)Table->TableContext + static_cast<NAMES*>(Table)->_cbUsed;

		static_cast<NAMES*>(Table)->_cbFree -= ByteSize;
		static_cast<NAMES*>(Table)->_cbUsed += ByteSize;

		return pv;
	}

	return 0;
}

RTL_GENERIC_COMPARE_RESULTS NTAPI NAMES::compare (_In_ PRTL_AVL_TABLE , _In_ PVOID FirstStruct, _In_ PVOID SecondStruct)
{
	int i = strcmp((PCSTR)FirstStruct + 1, (PCSTR)SecondStruct + 1);
	if (0 > i) return GenericLessThan;
	if (0 < i) return GenericGreaterThan;
	return GenericEqual;
}

VOID NAMES::AddNames(_In_ PRTL_PROCESS_MODULES mods, _In_opt_ PRTL_PROCESS_MODULES32 mods32)
{
	union {
		PRTL_PROCESS_MODULE_INFORMATION Modules;
		PRTL_PROCESS_MODULE_INFORMATION32 Modules32;
	};

	ULONG NumberOfModules;

	if (NumberOfModules = mods->NumberOfModules)
	{
		Modules = mods->Modules;

		do 
		{
			AddName(Modules++->FullPathName);

		} while (--NumberOfModules);
	}

	if (mods32)
	{
		if (NumberOfModules = mods32->NumberOfModules)
		{
			Modules32 = mods32->Modules;

			do 
			{
				AddName(Modules32++->FullPathName);

			} while (--NumberOfModules);
		}
	}
}

extern OBJECT_ATTRIBUTES zoa;

ULONG Process( PRTL_PROCESS_MODULES mods, ULONG Size)
{
	if (ULONG NumberOfModules = mods->NumberOfModules)
	{
		if (Size == __builtin_offsetof(RTL_PROCESS_MODULES, Modules) + NumberOfModules * sizeof(RTL_PROCESS_MODULE_INFORMATION))
		{
			PRTL_PROCESS_MODULE_INFORMATION Modules = mods->Modules;
			do 
			{
				_strlwr(Modules->FullPathName);
			} while (Modules++, --NumberOfModules);

			return Size;
		}
		else
		{
			mods->NumberOfModules = 0;
		}
	}

	return sizeof(PVOID);
}

ULONG Process( PRTL_PROCESS_MODULES32 mods, ULONG Size)
{
	if (ULONG NumberOfModules = mods->NumberOfModules)
	{
		if (Size == __builtin_offsetof(RTL_PROCESS_MODULES32, Modules) + NumberOfModules * sizeof(RTL_PROCESS_MODULE_INFORMATION32))
		{
			CHAR SysDir[64];
			ULONG cch = GetSystemDirectoryA(SysDir, _countof(SysDir));
			static const CHAR system32[] = "\\system32\\";
			static const CHAR wow64[] = "wow64";
			_strlwr(SysDir);

			PRTL_PROCESS_MODULE_INFORMATION32 Modules = mods->Modules;
			do 
			{
				PSTR FullPathName = _strlwr(Modules->FullPathName);
				if (_countof(system32) < cch)
				{
					if (!memcmp(FullPathName, SysDir, cch) &&
						!memcmp(FullPathName += cch - _countof(system32) + 2, system32, _countof(system32) - 1))
					{
						memcpy(FullPathName + _countof("\\sys") - 1, wow64, _countof(wow64) - 1);
					}
				}
			} while (Modules++, --NumberOfModules);

			return Size;
		}
		else
		{
			mods->NumberOfModules = 0;
		}
	}

	return sizeof(PVOID);
}

NTSTATUS StartQuery(
					_In_ HANDLE hProcess,
					_In_ PVOID RemoteBaseAddress,
					_In_ ULONG Size,
					_In_ BOOLEAN ExportSuppression,
#ifdef _WIN64
					_In_ BOOL wow,
#endif
					_Out_ THREAD_INFO* pta 
					)
{
	PVOID pvLdrQueryProcessModuleInformation;
	PVOID pvRtlExitUserThread;
	NTSTATUS (NTAPI *QueueApcThread)(HANDLE hThread, PKNORMAL_ROUTINE , PVOID , PVOID , PVOID );

#ifdef _WIN64
	if (wow)
	{
		pvLdrQueryProcessModuleInformation = ntdll.funcs[0].pv;
		pvRtlExitUserThread = ntdll.funcs[1].pv;
		QueueApcThread = RtlQueueApcWow64Thread;
	}
	else
#endif
	{
		pvLdrQueryProcessModuleInformation = LdrQueryProcessModuleInformation;
		pvRtlExitUserThread = RtlExitUserThread;
		QueueApcThread = ZwQueueApcThread;
	}

	NTSTATUS status;

	if (ExportSuppression)
	{
		if (0 > (status = SetExportValid(hProcess, pvLdrQueryProcessModuleInformation, pvRtlExitUserThread)))
		{
			return status;
		}
	}

	HANDLE hThread;
	if (0 <= (status = RtlCreateUserThread(hProcess, 0, TRUE, 0, 0, 0, pvRtlExitUserThread, 0, &hThread, 0)))
	{
		if (0 <= (status = QueueApcThread(hThread, 
			(PKNORMAL_ROUTINE)pvLdrQueryProcessModuleInformation, 
			RemoteBaseAddress, 
			(PVOID)(ULONG_PTR)Size, 
			(PBYTE)RemoteBaseAddress + Size)))
		{
			NtSetInformationThread(hThread, ThreadHideFromDebugger, 0, 0);

			if (0 <= (status = ZwResumeThread(hThread, 0)))
			{
				pta->hThread = hThread;
#ifdef _WIN64
				pta->IsWow64Thread = wow;
#endif
				pta->RemoteViewBase = RemoteBaseAddress;

				return STATUS_SUCCESS;
			}
		}

		ZwTerminateThread(hThread, 0);
		NtClose(hThread);
	}

	return status;
}

void NAMES::QueryLoop(
					  _In_ PSYSTEM_PROCESS_INFORMATION pspi, 
					  _In_ HANDLE hSection, 
					  _In_ PVOID BaseAddress
					  )
{
	THREAD_INFO ta[MaxThreads] {}, *pta;
	HANDLE hThreads[MaxThreads];
	ULONG Indexes[MaxThreads]; // hThreads -> ta
	CLIENT_ID cid = { };

	LONG Mask = ~0;/* 1 - THREAD_INFO is free */
	ULONG Index;

	ULONG NextEntryOffset = 0;

#ifdef _WIN64
	BOOL bWowInit = (ntdll.funcs[0].pv && ntdll.funcs[1].pv);
#endif

	struct QueryBuf 
	{
		ULONG NumberOfModules;
		UCHAR buf[secsize - 2 * sizeof(ULONG)];
		ULONG ReturnedSize;
	};

	union {
		void* LocalBaseAddress;
		ULONG_PTR up;
		QueryBuf* pQb;
		RTL_PROCESS_MODULES* mods;
		RTL_PROCESS_MODULES32* mods32;
	};

	ULONG ReturnedSize;

	do 
	{
		if (_BitScanForward(&Index, Mask))
		{
			(ULONG_PTR&)pspi += NextEntryOffset;

			if (!(cid.UniqueProcess = pspi->UniqueProcessId))
			{
				continue;
			}

			LARGE_INTEGER SectionOffset = { Index << secshift };
			LocalBaseAddress = RtlOffsetToPointer(BaseAddress, SectionOffset.LowPart);

			NTSTATUS status;
			HANDLE hProcess;

			if (pspi->InheritedFromUniqueProcessId)
			{
				if (0 <= (status = MyOpenProcess(&hProcess, 
					PROCESS_VM_OPERATION|PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_SET_INFORMATION, &zoa, &cid)))
				{
					PROCESS_EXTENDED_BASIC_INFORMATION pebi = {sizeof(pebi)};
					if (0 <= (status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pebi, sizeof(pebi), 0)))
					{
						if (pebi.IsProcessDeleting)
						{
							status = STATUS_PROCESS_IS_TERMINATING;
						}
						else if (pebi.IsFrozen && pebi.IsStronglyNamed)
						{
							status = STATUS_INVALID_DEVICE_STATE;
						}
						else
						{
							BOOLEAN ExportSuppression = IsExportSuppressionEnabled(hProcess);

							pta = ta + Index;
							pta->pspi = pspi;

							pta->hProcess = hProcess;
#ifdef _WIN64
							pta->IsWow64Process = bWowInit && pebi.IsWow64Process;
#endif
							pta->ExportSuppressed = ExportSuppression;

							pQb->NumberOfModules = 0;
							pQb->ReturnedSize = 0;

							PVOID RemoteBaseAddress = 0;
							SIZE_T ViewSize = secsize;

							if (0 <= (status = ZwMapViewOfSection(hSection, hProcess, &RemoteBaseAddress, 0, 
								secsize, &SectionOffset, &ViewSize, ViewUnmap, 0, PAGE_READWRITE)))
							{
								if (0 <= (status = StartQuery(hProcess, RemoteBaseAddress, 
									secsize - sizeof(ULONG), 
									ExportSuppression, 
#ifdef _WIN64
									FALSE, 
#endif
									pta)))
								{
									_bittestandreset(&Mask, Index);
									continue;
								}

								ZwUnmapViewOfSection(hProcess, RemoteBaseAddress);
							}

							pta->hProcess = 0, pta->pspi = 0;
						}
					}

					NtClose(hProcess);
				}
			}
			else
			{
				if (0 <= (status = NtQuerySystemInformation(SystemModuleInformation, LocalBaseAddress, secsize, &ReturnedSize)))
				{
					if (ReturnedSize = Process(mods, ReturnedSize))
					{
						AddNames(mods, 0);
					}
				}
			}
		}
		else
		{
			do 
			{
__0:
				LARGE_INTEGER Timeout = { (ULONG)-10000000, -1 };
				Index = ZwWaitForMultipleObjects(FormatWaitArray(ta, _countof(ta), hThreads, Indexes), hThreads, WaitAny, TRUE, &Timeout);

				if (Index > MaxThreads)
				{
					goto __1;
				}

				pta = &ta[Index = Indexes[Index]];
				PVOID buf = LocalBaseAddress = RtlOffsetToPointer(BaseAddress, Index << secshift);

				NtClose(pta->hThread);

				ReturnedSize = pQb->ReturnedSize;

				up += (ULONG_PTR)pta->RemoteViewBase & 0xFFFF;
				ReturnedSize = pta->IsWow64Thread ? Process(mods32, ReturnedSize) : Process(mods, ReturnedSize);
				pta->hThread = 0;

#ifdef _WIN64
				if (pta->IsWow64Process)
				{
					pta->IsWow64Process = 0;

					if (ReturnedSize <= 0x10000 - sizeof(ULONG))
					{
						if (0 <= StartQuery(pta->hProcess, (PBYTE&)pta->RemoteViewBase += ReturnedSize, 
							secsize - ReturnedSize - sizeof(ULONG), pta->ExportSuppressed, TRUE, pta))
						{
							goto __0;
						}
					}
				}
#endif

				pta->Cleanup();
				_bittestandset(&Mask, Index);

				if (ReturnedSize)
				{
					if (buf == LocalBaseAddress)
					{
						AddNames(mods, 0);
					}
					else
					{
						AddNames((PRTL_PROCESS_MODULES)buf, mods32);
					}

				}

			} while (!_BitScanForward(&Index, Mask));
		}

	} while (NextEntryOffset = pspi->NextEntryOffset);

	while (Mask != ~0)
	{
		goto __0;
	}

__1:

	Index = MaxThreads;
	pta = ta;
	do 
	{
		if (HANDLE hThread = pta->hThread)
		{
			ZwTerminateThread(hThread, 0);
			NtClose(hThread);
			pta->Cleanup();
		}

	} while (pta++, --Index);
}

_NT_END