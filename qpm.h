#pragma once

enum { secshift = 17, secsize = (1 << secshift), MaxThreads = 32 };

class NAMES : public RTL_AVL_TABLE 
{
	ULONG _cbFree = 0, _cbUsed = 0, _cbNames = 0;

	void Init(PVOID pv)
	{
		RtlInitializeGenericTableAvl(this, compare, alloc, free, pv);
	}

	void AddName(PSTR Name);

public:

	NAMES()
	{
		TableContext = 0;
	}

	BOOL Create(ULONG size);

	PSYSTEM_PROCESS_INFORMATION BuildListOfProcesses(ULONG_PTR dwProcessId);

	VOID AddNames(_In_ PRTL_PROCESS_MODULES mods, _In_opt_ PRTL_PROCESS_MODULES32 mods32);

	void QueryLoop(_In_ PSYSTEM_PROCESS_INFORMATION pspi, _In_ HANDLE hSection, _In_ PVOID BaseAddress);

	ULONG GetNamesLen()
	{
		return _cbNames;
	}

	PVOID malloca(_In_ ULONG ByteSize)
	{
		return ByteSize > _cbFree ? new CHAR[ByteSize] : RtlOffsetToPointer(TableContext, _cbUsed);
	}

	void freea(_In_ PVOID pv)
	{
		if (pv != RtlOffsetToPointer(TableContext, _cbUsed))
		{
			delete [] pv;
		}
	}

	static PVOID NTAPI alloc (_In_ PRTL_AVL_TABLE Table, _In_ CLONG ByteSize);

	static VOID NTAPI free (_In_ PRTL_AVL_TABLE ,_In_ PVOID )
	{
		__debugbreak();
	}

	static RTL_GENERIC_COMPARE_RESULTS NTAPI compare (_In_ PRTL_AVL_TABLE , _In_ PVOID FirstStruct, _In_ PVOID SecondStruct);

	~NAMES()
	{
		if (PVOID buf = TableContext)
		{
			VirtualFree(buf, 0, MEM_RELEASE);
		}
	}
};

#ifdef _WIN64
void InitWow64();
#endif
