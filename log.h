#pragma once

class Log
{
	PVOID _BaseAddress;
	ULONG _RegionSize, _Ptr;

	PSTR _buf()
	{
		return (PSTR)((ULONG_PTR)_BaseAddress + _Ptr);
	}

	ULONG _cch()
	{
		return (_RegionSize - _Ptr);
	}

public:
	ULONG Init(SIZE_T RegionSize);

	~Log();

	Log(Log&&) = delete;
	Log(Log&) = delete;
	Log(): _BaseAddress(0) { }

	operator PWSTR();

	operator PCSTR()
	{
		return (PCSTR)_BaseAddress;
	}

	bool write(PCSTR buf, ULONG cb);
	bool operator ()(PCSTR format, ...);
	bool operator << (PCSTR str);

	Log& operator[](HRESULT dwError);
};
