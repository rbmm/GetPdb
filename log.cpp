#include "stdafx.h"

_NT_BEGIN

#include "log.h"

Log::operator PWSTR()
{
	if (ULONG Ptr = _Ptr)
	{
		PWSTR psz = 0;
		ULONG cch = 0;
		while (cch = MultiByteToWideChar(CP_UTF8, 0, (PSTR)_BaseAddress, Ptr, psz, cch))
		{
			if (psz)
			{
				psz[cch] = 0;
				return psz;
			}

			if (!(psz = (PWSTR)LocalAlloc(LMEM_FIXED, (1+cch)*sizeof(WCHAR))))
			{
				break;
			}
		}

		if (psz)
		{
			LocalFree(psz);
		}
	}

	return 0;
}

ULONG Log::Init(SIZE_T RegionSize)
{
	if (PVOID BaseAddress = LocalAlloc(0, RegionSize))
	{
		_RegionSize = (ULONG)RegionSize, _Ptr = 0, _BaseAddress = BaseAddress;
		*(CHAR*)BaseAddress = 0;
		return NOERROR;
	}
	return GetLastError();
}

Log::~Log()
{
	if (_BaseAddress)
	{
		LocalFree(_BaseAddress);
	}
}

bool Log::operator ()(PCSTR format, ...)
{
	va_list args;
	va_start(args, format);

	int len = _vsnprintf_s(_buf(), _cch(), _TRUNCATE, format, args);

	va_end(args);

	if (0 < len)
	{
		_Ptr += len;
		return true;
	}

	return false;
}

bool Log::operator << (PCSTR str)
{
	if (strcpy_s(_buf(), _cch(), str))
	{
		return false;
	}
	_Ptr += (ULONG)strlen(str);
	return true;
}

bool Log::write(PCSTR buf, ULONG cb)
{
	if (memcpy_s(_buf(), _cch(), buf, cb))
	{
		return false;
	}
	_Ptr += cb;
	return true;
}

Log& Log::operator[](HRESULT dwError)
{
	LPCVOID lpSource = 0;
	ULONG dwFlags = FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS;

	if ((dwError & FACILITY_NT_BIT) || (0 > dwError && HRESULT_FACILITY(dwError) == FACILITY_NULL))
	{
		dwError &= ~FACILITY_NT_BIT;
__nt:
		dwFlags = FORMAT_MESSAGE_FROM_HMODULE|FORMAT_MESSAGE_IGNORE_INSERTS;

		static HMODULE ghnt;
		if (!ghnt && !(ghnt = GetModuleHandle(L"ntdll"))) return *this;
		lpSource = ghnt;
	}

	if (dwFlags = FormatMessageA(dwFlags, lpSource, dwError, 0, _buf(), _cch(), 0))
	{
		_Ptr += dwFlags;
	}
	else if (dwFlags & FORMAT_MESSAGE_FROM_SYSTEM)
	{
		goto __nt;
	}
	return *this;
}

_NT_END