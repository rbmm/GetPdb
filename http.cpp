#include "StdAfx.h"

_NT_BEGIN

#include "../winz/str.h"
#include "../asio/ssl.h"
#include "../asio/CiclicBuffer.h"
#include "dllVector.h"

BOOL IsValidPDBExist(POBJECT_ATTRIBUTES poa, PGUID Signature, ULONG Age);

BOOL
CrackUrlA(
		  _In_ PSTR lpszUrl,
		  _Out_ INTERNET_SCHEME* pnScheme,
		  _Out_ PSTR* lppszHostName,
		  _Out_ INTERNET_PORT* pnPort,
		  _Out_ PSTR* lppszUrlPath
		  )
{
	if (lpszUrl[0] != 'h' || lpszUrl[1] != 't' || lpszUrl[2] != 't' || lpszUrl[3] != 'p')
	{
		return FALSE;
	}

	*pnPort = INTERNET_DEFAULT_HTTP_PORT;
	*pnScheme = INTERNET_SCHEME_HTTP;

	if (lpszUrl[4] == 's')
	{
		*pnScheme = INTERNET_SCHEME_HTTPS;
		*pnPort = INTERNET_DEFAULT_HTTPS_PORT;
		lpszUrl++;
	}

	if (lpszUrl[4] != ':' || lpszUrl[5] != '/' || lpszUrl[6] != '/')
	{
		return FALSE;
	}
	
	PSTR lpszHostName = lpszUrl += 7;

	if (!(lpszUrl = strchr(lpszHostName, '/')))
	{
		return FALSE;
	}

	*lpszUrl++ = 0;
	*lppszHostName = lpszHostName;
	*lppszUrlPath = lpszUrl;

	if (lpszUrl = strchr(lpszUrl, '#'))
	{
		*lpszUrl = 0;
	}

	if (lpszUrl = strchr(lpszHostName, ':'))
	{
		*lpszUrl = 0;
		ULONG nPort = strtoul(lpszUrl + 1, &lpszUrl, 10);
		if (*lpszUrl || nPort > MAXUSHORT)
		{
			return FALSE;
		}

		*pnPort = (INTERNET_PORT)nPort;
	}

	return TRUE;
}

extern const volatile UCHAR guz = 0;

#define SaveTick(t) t = GetTickCount()
#define TickNow(t) GetTickCount() - t

//#define __DBG__

#ifdef __DBG__
#undef DbgPrint

void
__cdecl
DbgPrint_Empty (
		  PCSTR /*Format*/,
		  ...
		  )
{
}

//#define DbgPrint DbgPrint_Empty

void PrintStr(PSTR psz, ULONG cch)
{
	ULONG len;
	do 
	{
		DbgPrint("%.*s", len = min(0x100, cch), psz);
	} while (psz += len, cch -= len);
}
#else
#define PrintStr /##/
#endif

#define dbgp /##/
#define dbgp_0 /##/
#define dbgp_1 /##/

PSTR ParseHTTPStatusLine(PSTR buf, ULONG cb, PULONG pStatusCode, PULONG pdwMajorVersion = 0, PULONG pdwMinorVersion = 0)
{
	PSTR end;

	if (
		cb < 6 ||
		(*buf++|0x20) != 'h' ||
		(*buf++|0x20) != 't' ||
		(*buf++|0x20) != 't' ||
		(*buf++|0x20) != 'p' ||
		*buf++ != '/' ||
		!(end = strnchr(cb - 5, buf, '\n')) || end[-2] != '\r'
		)
	{
		return 0;
	}

	ULONG n = strtoul(buf, &buf, 10);

	if (*buf != '.')
	{
		return 0;
	}

	if (pdwMajorVersion)
	{
		*pdwMajorVersion = n;
	}

	n = strtoul(buf + 1, &buf, 10);

	if (*buf != ' ')
	{
		return 0;
	}

	if (pdwMinorVersion)
	{
		*pdwMinorVersion = n;
	}

	n = strtoul(buf + 1, &buf, 10);

	if (*buf == ' ' || buf == end - 2)
	{
		*pStatusCode = n;
		return end;
	}

	return 0;
}

PSTR ParseHTTPHeaders(PSTR buf, PSTR end, PULONG pLineCount)
{
	ULONG LineCount = 0;

	while (PSTR sz = _strnchr(buf, end, '\n'))
	{
		if (sz == buf + 1 || sz[-2] != '\r')
		{
			return 0;
		}

		if (sz == buf + 2)
		{
			*pLineCount = LineCount;
			return sz;
		}

		do 
		{
			char c = *buf;

			if (c == ':')
			{
				*buf = 0;
				break;
			}

			*buf++ = c | 0x20;

			if (buf == sz)
			{
				return 0;
			}

		} while (buf < sz);

		buf = sz, LineCount++;
	}

	return 0;
}

void GetHTTPHeaders(PSTR buf, ULONG hash[], PSTR values[], ULONG n)
{
	do 
	{
		ULONG cb = (ULONG)strlen(buf);
		*hash++ = RtlComputeCrc32(0, buf, cb);
		*values++ = buf += cb + 1;
		(buf = strnchr(MAXSIZE_T, buf, '\n'))[-2] = 0;
	} while (--n);
}

//ULONG gTlsIndex;

class CFileDownload;

class __declspec(novtable) CyclicBuferExW : public ZRingBuffer
{
public:
	virtual void OnWriteError() = 0;
	virtual void AddRef() = 0;
	virtual void Release() = 0;
};

namespace SI {
	ULONG dwAllocationGranularity, dwPageSize;

	struct __{

		__(){
			SYSTEM_INFO si;
			GetSystemInfo(&si);

			if ((si.dwAllocationGranularity & (si.dwAllocationGranularity - 1)) ||
				(si.dwPageSize & (si.dwPageSize - 1)))
			{
				__debugbreak();
			}

			dwAllocationGranularity = si.dwAllocationGranularity - 1;
			dwPageSize = si.dwPageSize;
		}
	} _;
};

NTSTATUS InitBytesPerSector(HANDLE hFile, PULONG pBytesPerSector)
{
	IO_STATUS_BLOCK iosb;

	union {
		FILE_FS_SECTOR_SIZE_INFORMATION ffssi;
		FILE_FS_SIZE_INFORMATION ffsi;
	};

	NTSTATUS status = NtQueryVolumeInformationFile(hFile, &iosb, &ffssi, sizeof(ffssi), FileFsSectorSizeInformation);

	ULONG BytesPerSector;

	if (0 <= status)
	{
		BytesPerSector = ffssi.PhysicalBytesPerSectorForPerformance;
	}
	else
	{
		status = NtQueryVolumeInformationFile(hFile, &iosb, &ffsi, sizeof(ffsi), FileFsSizeInformation);

		if (0 > status)
		{
			return status;
		}

		BytesPerSector = ffsi.BytesPerSector;
	}

	if ( ((BytesPerSector - 1) & BytesPerSector) || BytesPerSector > 0x10000)
	{
		return STATUS_UNSUCCESSFUL;
	}

	if (BytesPerSector < SI::dwPageSize)
	{
		BytesPerSector = SI::dwPageSize;
	}

	*pBytesPerSector = BytesPerSector;

	return STATUS_SUCCESS;
}

class CFileWriter : public IO_OBJECT
{
	enum { opWrite, opCmp };
	LARGE_INTEGER _ByteOffset{}, _EndOfFile{};
	BOOL _bUnknownSize = FALSE;
	CyclicBuferExW* _pDD;

	~CFileWriter()
	{
		dbgp("%s<%p> %I64x\n", __FUNCTION__, this, _ByteOffset.QuadPart);
		_pDD->Release();
	}

public:

	BOOL IsCreated()
	{
		return getHandleNoLock() != 0;
	}

	CFileWriter(CyclicBuferExW* pDD) : _pDD(pDD)
	{
		dbgp("%s<%p>\n", __FUNCTION__, this);
		pDD->AddRef();
	}

	void Cleanup()
	{
		dbgp("%08x[%x]:%s<%p> %I64x/%I64x\n", GetCurrentThreadId(), _pDD->getIOcount(), __FUNCTION__, this, _ByteOffset.QuadPart, _EndOfFile.QuadPart);

		if (HANDLE hFile = getHandleNoLock())
		{
			IO_STATUS_BLOCK iosb;
			if (_ByteOffset.QuadPart < _EndOfFile.QuadPart)
			{
				if (!_bUnknownSize || 0 > NtSetInformationFile(hFile, &iosb, &_ByteOffset, sizeof(_ByteOffset), FileEndOfFileInformation))
				{
					static FILE_DISPOSITION_INFORMATION fdi = { TRUE };
					NtSetInformationFile(hFile, &iosb, &fdi, sizeof(fdi), FileDispositionInformation);
				}
			}

			Close();
		}
	}

	// return are EndRead will be called
	bool Write(PFILE_SEGMENT_ELEMENT aSegmentArray, ULONG Length)
	{
		dbgp("%08x[%x]:%s<%p>(%08x->%I64x)\n", GetCurrentThreadId(), _pDD->getIOcount(), __FUNCTION__, this, Length, _ByteOffset.QuadPart);

		if (_ByteOffset.QuadPart < _EndOfFile.QuadPart)
		{
			if (NT_IRP* irp = new NT_IRP(this, opWrite, 0, 0))
			{
				NTSTATUS status = STATUS_INVALID_HANDLE;

				HANDLE hFile;
				if (LockHandle(hFile))
				{
					status = NtWriteFileGather(hFile, 0, 0, irp, irp, aSegmentArray, Length, &_ByteOffset, 0);
					UnlockHandle();
				}

				irp->CheckNtStatus(status);

				return true;
			}
		}

		_pDD->OnWriteError();

		return false;
	}

	NTSTATUS Create(POBJECT_ATTRIBUTES poa, PLARGE_INTEGER EndOfFile, BOOL bUnknownSize)
	{
		if (getHandleNoLock()) __debugbreak();

		//dbgp("%s<%p>(%wZ, %I64x)\n", __FUNCTION__, this, poa->ObjectName, EndOfFile->QuadPart);

		_bUnknownSize = bUnknownSize;
		HANDLE hFile;
		IO_STATUS_BLOCK iosb;

		NTSTATUS status = NtCreateFile(&hFile, DELETE|FILE_WRITE_DATA|FILE_READ_DATA, poa, &iosb,
			EndOfFile, 0, FILE_SHARE_VALID_FLAGS, FILE_OVERWRITE_IF, 
			FILE_NON_DIRECTORY_FILE|FILE_NO_INTERMEDIATE_BUFFERING, 0, 0);

		if (0 > status)
		{
			return status;
		}

		Assign(hFile);

		_ByteOffset.QuadPart = 0;
		_EndOfFile.QuadPart = EndOfFile->QuadPart;

		if (0 <= (status = NT_IRP::RtlBindIoCompletion(hFile)))
		{
			static USHORT cmp = COMPRESSION_FORMAT_NONE;

			if (NT_IRP* irp = new NT_IRP(this, opCmp, 0))
			{
				status = NtFsControlFile(hFile, 0, 0, irp, irp, FSCTL_SET_COMPRESSION, &cmp, sizeof(cmp), 0, 0);

				dbgp_0("%x>SET_COMPRESSION>%x %x %p\n", GetCurrentThreadId(), status, irp->Status, irp->Information);

				irp->CheckNtStatus(status);
			}
		}

		return status;
	}

	void OnWrite(ULONG_PTR dwNumberOfBytesTransfered)
	{
		if (!_pDD->getIOcount()) __debugbreak();//$$$

		_ByteOffset.QuadPart += dwNumberOfBytesTransfered;

		if (_EndOfFile.QuadPart <= _ByteOffset.QuadPart)//<
		{
			dbgp("[%08x][%x]:%s<%p>(%08x)\n", GetCurrentThreadId(), _pDD->getIOcount(), __FUNCTION__, this, dwNumberOfBytesTransfered);

			if (_EndOfFile.QuadPart < _ByteOffset.QuadPart)
			{
				IO_STATUS_BLOCK iosb;
				NtSetInformationFile(getHandleNoLock(), &iosb, &_EndOfFile, sizeof(_EndOfFile), FileEndOfFileInformation);
			}
		}

		dbgp("\n[%08x][%x]:%s<%p>+++++++++ (%08x->%I64x) +++++++++\n", GetCurrentThreadId(), _pDD->getIOcount(), __FUNCTION__, this, dwNumberOfBytesTransfered, _ByteOffset.QuadPart);

		if (!_pDD->getIOcount())__debugbreak();//$$$
	}
private:
	void IOCompletionRoutine(CDataPacket* /*packet*/, ULONG Code, NTSTATUS status, ULONG_PTR dwNumberOfBytesTransfered, PVOID /*Pointer*/)
	{
		switch(Code)
		{
		case opCmp:
			if (0 <= status && !_bUnknownSize)
			{
				HANDLE hFile;
				if (LockHandle(hFile))
				{
					IO_STATUS_BLOCK iosb;
					NtSetInformationFile(hFile, &iosb, &_EndOfFile, sizeof(_EndOfFile), FileEndOfFileInformation);
					NtSetInformationFile(hFile, &iosb, &_EndOfFile, sizeof(_EndOfFile), FileValidDataLengthInformation);
					UnlockHandle();
				}
			}
			break;
		case opWrite:
			if (0 > status || !dwNumberOfBytesTransfered)
			{
				dwNumberOfBytesTransfered = 0;
				status = false;
			}
			else
			{
				OnWrite(dwNumberOfBytesTransfered);
				status = true;
			}
			_pDD->EndRead((ULONG)dwNumberOfBytesTransfered);
			if (status)
			{
				break;
			}
		default:
			//__debugbreak();
			_pDD->OnWriteError();
		}
	}
};

//////////////////////////////////////////////////////////////////////////
//

class CFileDownloadS : public CSSLEndpoint, public CyclicBuferExW
{
	enum { e_http_head_max_size = 0x4000 };
	LARGE_INTEGER _cbBytesNeed;
	PWSTR _FileName = 0;
	PSTR _http_head_buffer = 0;//e_http_head_max_size
	ZDllVector* _task;
	HANDLE _hRoot = 0;
	HWND _hwnd;
	Log* _log = 0;
	CFileWriter* _pFileWriter = 0;
	WSABUF _Buffers[2];
	ULONG _dwBufferCount;
	ULONG _dwHeadSize;
	ULONG _dwNumberOfBytesRead;
	ULONG _BytesPerSector = 0, _MinWriteSize = 0;
	ULONG _id, _dwExtraSize, _dwGetDataSize, _ip = 0;
	ULONG _t = GetTickCount();//$$$
	NTSTATUS _status = STATUS_UNSUCCESSFUL;
	LONG _dwFlags = 0;
	enum {
		_bHandshakeDone, _bSSL, _bNotRead, _bRedirected, _bReCreate, _bIoStart, _bWriteActive, _bConnected, _bUnknownLength, _bOk
	};
	INTERNET_PORT _nPort = 0x5000; //_byteswap_ushort(INTERNET_DEFAULT_HTTP_PORT);

private:
	
	virtual void OnEncryptDecryptError(SECURITY_STATUS s)
	{
		Log& log = *_log;
		if (&log)
		{
			log("!! EncryptDecryptError %x\r\n", s);
			log[s];
		}
	}

	virtual void LogError(ULONG opCode, ULONG dwError)
	{
		_status = RtlGetLastNtStatus();
		Log& log = *_log;
		if (&log)
		{
			NTSTATUS status = RtlGetLastNtStatus();
			if (RtlNtStatusToDosErrorNoTeb(status) == dwError)
			{
				dwError = HRESULT_FROM_NT(status);
			}
			log("!! error (%.4s %x %S)\r\n", &opCode, dwError & ~FACILITY_NT_BIT, _FileName);
			log[dwError];
		}

		dbgp_1("[%u]:%s<%p>(%.4s %x(%u))\n", TickNow(_t), __FUNCTION__, this, &opCode, RtlGetLastNtStatus(), dwError);
	}

	virtual ULONG GetMinReadBufferSize()
	{ 
		return _BytesPerSector; 
	}

	virtual ULONG GetMinWriteBufferSize()
	{ 
		return _MinWriteSize; 
	}

	virtual void OnIoStop()
	{
		dbgp("[%u]:%s<%p> <- %p\n", TickNow(_t), __FUNCTION__, this, _ReturnAddress());
		_pFileWriter->Cleanup();
		//PostMessageW(_hwnd, e_text, _id, (LPARAM)L"IoStop");
		Next();
	}

	virtual void OnWriteError() 
	{
		PostMessageW(_hwnd, e_text, _id, (LPARAM)L"WriteError");
		Disconnect();
	}

	virtual bool BeginRead(WSABUF* lpBuffers, ULONG dwBufferCount)
	{
		dbgp("[%08x][%x]:%s<%p>(%x)\n", GetCurrentThreadId(), getIOcount(), __FUNCTION__, this, dwBufferCount);

		if (!dwBufferCount)
		{
			return false;
		}

		WSABUF* p = lpBuffers;
		int len;
		ULONG n = dwBufferCount, elementCount = 1, Length = 0;
		do 
		{
			--n;
			if (len = p++->len)
			{
				if (n && (len & (SI::dwPageSize - 1))) 
				{
					__debugbreak();
					return false;
				}
				elementCount += (len +  SI::dwPageSize - 1) / SI::dwPageSize ;
			}
		} while (n);

		union {
			PVOID buf;
			PFILE_SEGMENT_ELEMENT aSegmentArray;
		};

		buf = alloca(elementCount * sizeof(FILE_SEGMENT_ELEMENT));
		PFILE_SEGMENT_ELEMENT pse = aSegmentArray;

		do 
		{
			PCHAR Buffer = lpBuffers->buf;
			if (len = lpBuffers++->len)
			{
				Length += len;
				do 
				{
					pse++->Buffer = PtrToPtr64(Buffer);
				} while (Buffer += SI::dwPageSize, 0 < (len -= SI::dwPageSize));
			}
		} while (--dwBufferCount);

		pse->Buffer = 0;

		dbgp("[%08x][%x]:%s<%p> WriteFrom<%p>(%x)\n", GetCurrentThreadId(), getIOcount(), __FUNCTION__, this, Length);

		return _pFileWriter->Write(aSegmentArray, Length & ~(_BytesPerSector - 1));
	}

	virtual ULONG GetRecvBuffers(WSABUF lpBuffers[2], void** ppv)
	{
		dbgp_0("%08x:GetRecvBuffers_0(%x)\n", GetCurrentThreadId(), _dataSize);

		if (!_bittest(&_dwFlags, _bHandshakeDone))
		{
			return CTcpEndpoint::GetRecvBuffers(lpBuffers, ppv);
		}

		_dwNumberOfBytesRead = 0;

		ULONG len = 0, data_size = m_packet->getDataSize(), MaximumMessage = getMaximumMessage(), cb = getHeaderSize()+getTrailerSize();

		data_size = data_size > cb ? data_size - cb : 0;

		if (data_size >= MaximumMessage)
		{
			__debugbreak();
			return 0;
		}

		if (ULONG dwBufferCount = _dwBufferCount)
		{
			WSABUF* Buf = _Buffers;
			do 
			{
				len += Buf++->len;
			} while (--dwBufferCount);
		}

		if (len < MaximumMessage)
		{
			__debugbreak();
			return 0;
		}

		*ppv = lpBuffers->buf = m_packet->getFreeBuffer(), lpBuffers->len = m_packet->getFreeSize();

		if (lpBuffers->len > (len -= data_size))
		{
			lpBuffers->len = len;
		}

		dbgp_0("%08x:GetRecvBuffers(%x, %x, %x)\n", GetCurrentThreadId(), data_size, len, m_packet->getFreeSize());

		return 1;
	}

	virtual BOOL OnRecv(PSTR Buf, ULONG cbTransferred)
	{
		_dwNumberOfBytesRead = 0;

		dbgp_0("\n%08x:OnRecv begin(%x) {%x}(%x)\n", GetCurrentThreadId(), cbTransferred, _bittest(&_dwFlags, _bHandshakeDone), _dataSize);

		BOOL f = _bittest(&_dwFlags, _bSSL) ? OnData(Buf, cbTransferred) : OnUserData(Buf, cbTransferred);

		if (_dwNumberOfBytesRead)
		{
			dbgp("[%08x][%x]:%s<%p> ++++ OnRecv:OnReadEnd(%x)(%x)\n", GetCurrentThreadId(), getIOcount(), __FUNCTION__, this, _dwNumberOfBytesRead, _dataSize);

			if (!_bittestandreset(&_dwFlags, _bWriteActive))
			{
				__debugbreak();
			}

			EndWrite(_dwNumberOfBytesRead);
			// -> ReadTo() can be called from here

			dbgp("[%08x][%x]:%s<%p> ---- OnRecv:OnReadEnd(%x)(%x)\n", GetCurrentThreadId(), getIOcount(), __FUNCTION__, this, _dwNumberOfBytesRead, _dataSize);

			return _bittest(&_dwFlags, _bNotRead) ? 0 : -1;
		}

		dbgp_0("%08x: ++++ OnRecv:OnReadContinue\n", GetCurrentThreadId());

		if (!f && _bittest(&_dwFlags, _bSSL) && !_bittest(&_dwFlags, _bRedirected))
		{
			//Shutdown();
			Send("", 1);
		}
		return f;
	}

	virtual bool BeginWrite(WSABUF* lpBuffers, ULONG dwBufferCount)
	{
		dbgp("[%08x][%x]:%s<%p> (%x) [%x]\n", GetCurrentThreadId(), getIOcount(), __FUNCTION__, this, dwBufferCount, _bittest(&_dwFlags, _bSSL));
		
		if (_bittestandset(&_dwFlags, _bWriteActive))
		{
			__debugbreak();
		}

		if (!_bittest(&_dwFlags, _bConnected))
		{
			return false;
		}

		if (_bittest(&_dwFlags, _bSSL))
		{
			_dwBufferCount = dwBufferCount;
			memcpy(_Buffers, lpBuffers, dwBufferCount * sizeof(WSABUF));

			dbgp("[%08x][%x]:%s<%p> ReadTo(%d) (%p,%x)%c(%p,%x)\n", GetCurrentThreadId(), getIOcount(), __FUNCTION__, this, dwBufferCount, lpBuffers->buf, lpBuffers->len, dwBufferCount == 1 ? 0 : ' ', lpBuffers[1].buf, lpBuffers[1].len);
			dbgp("\n");
			Recv();
		}
		else
		{
			_dwBufferCount = 0;
			if (_bittest(&_dwFlags, _bNotRead))
			{
				dbgp_0("readto:__nop()\n");
			}
			else
			{
				dbgp_0("%08x:ReadTo [%x], (%p,%x)\n%c\t(%p,%x)\n", GetCurrentThreadId(), dwBufferCount, lpBuffers->buf, lpBuffers->len, dwBufferCount == 1 ? 0 : ' ', lpBuffers[1].buf, lpBuffers[1].len);

				Recv(lpBuffers, dwBufferCount, GetBuffer());
			}
		}

		return true;
	}

	virtual BOOL IsServer(PBOOLEAN pbMutualAuth = 0)
	{
		if (pbMutualAuth)
		{
			*pbMutualAuth = FALSE;
		}
		return FALSE;
	}

	virtual void OnDisconnect()
	{
		dbgp_1("[%08x][%u]:%s<%p>(f=%x %S)\n", GetCurrentThreadId(), TickNow(_t), __FUNCTION__, this, _dwFlags, _FileName);
		
		SaveTick(_t);

		Log& log = *_log;
		if (&log)
		{
			log << "\r\nOnDisconnect\r\n";
		}

		if (_bittest(&_dwFlags, _bRedirected))
		{
			PostMessageW(_hwnd, e_text, _id, (LPARAM)L"redirect...");
		}
		else
		{
			PostMessageW(_hwnd, e_disconnect, _id, _pFileWriter->IsCreated() && 
				(_bittest(&_dwFlags, _bUnknownLength) || !_cbBytesNeed.QuadPart) ? _bittestandset(&_dwFlags, _bOk), STATUS_SUCCESS : _status);
		}

		StopSSL();

		_bittestandreset(&_dwFlags, _bConnected);

		if (_bittestandreset(&_dwFlags, _bWriteActive))
		{
			EndWrite(0);
		}

		if (_bittestandreset(&_dwFlags, _bIoStart))
		{
			Stop();
		}
	}

	virtual void CloseObjectHandle(HANDLE hFile)
	{
		__super::CloseObjectHandle(hFile);

		Log& log = *_log;
		if (&log)
		{
			log("CloseObjectHandle(%08X)\r\n", _dwFlags);
		}

		if (_bittestandreset(&_dwFlags, _bReCreate))
		{
			if (CTcpEndpoint::Create(SI::dwAllocationGranularity + 1))
			{
				Next();
			}
			else
			{
				dbgp("[%u]:%s<%p>(%s)\n", TickNow(_t), __FUNCTION__, this, ZRingBuffer::GetBuffer());
				OnIp(_ip);
			}
		}
	}

	virtual BOOL OnConnect(ULONG dwError)
	{
		_dwHeadSize = 0;

		NTSTATUS status = dwError ? RtlGetLastNtStatus() : STATUS_SUCCESS;

		if (RtlNtStatusToDosErrorNoTeb(status) == dwError)
		{
			if (dwError)
			{
				dwError = HRESULT_FROM_NT(status);
			}
		}
		else
		{
			status = HRESULT_FROM_WIN32(dwError);
		}

		Log& log = *_log;
		if (&log)
		{
			log("OnConnect(%x)\r\n", dwError & ~FACILITY_NT_BIT);
			if (dwError)
			{
				log[dwError];
			}
		}

		dbgp_1("[%u]:%s<%p>(%u(%x)) [f=%x] %S\n", TickNow(_t), __FUNCTION__, this, dwError, status, _dwFlags, _FileName);
		SaveTick(_t);

		switch (status)
		{
		case STATUS_ADDRESS_ALREADY_EXISTS:
		case STATUS_CONNECTION_ACTIVE:
			_bittestandset(&_dwFlags, _bReCreate);
			Close();
			return FALSE;
		}

		_ip = 0;

		PostMessageW(_hwnd, e_connect, _id, status);

		if (dwError)
		{
			_status = dwError;
			Next();
			return FALSE;
		}

		if (_bittest(&_dwFlags, _bSSL) && !StartSSL())
		{
			return FALSE;
		}

		_bittestandset(&_dwFlags, _bConnected);
		_bittestandset(&_dwFlags, _bIoStart);
		ZRingBuffer::Start();

		return  -1;
	}

	virtual ULONG GetConnectData(void** ppSendBuffer)
	{
		return _bittest(&_dwFlags, _bSSL) ? 0 : (*ppSendBuffer = ZRingBuffer::GetBuffer(), _dwGetDataSize);
	}

	virtual SECURITY_STATUS OnEndHandshake()
	{
		dbgp("%s<%p>\n", __FUNCTION__, this);
		PostMessageW(_hwnd, e_text, _id, (LPARAM)L"EndHandshake");

		_bittestandset(&_dwFlags, _bHandshakeDone);

		_MinWriteSize = (getMaximumMessage() + _BytesPerSector - 1) & ~(_BytesPerSector - 1);

		if (ULONG dwError = SendUserData(ZRingBuffer::GetBuffer(), _dwGetDataSize))
		{
			PostMessageW(_hwnd, e_send, _id, (LPARAM)dwError);
			return HRESULT_FROM_WIN32(dwError);
		}
		return SEC_E_OK;
	}

	// return size of headers
	ULONG CheckResponce(PSTR Buf, ULONG cbTransferred)
	{
		if (PSTR body = strnstr(cbTransferred, Buf, 4, "\r\n\r\n"))
		{
			//PrintStr(Buf, RtlPointerToOffset(Buf, body));
			Log& log = *_log;
			if (&log)
			{
				log.write(Buf, RtlPointerToOffset(Buf, body));
			}
		}

		ULONG StatusCode, LineCount;

		PSTR headers = ParseHTTPStatusLine(Buf, cbTransferred, &StatusCode);

		if (headers)
		{
			enum X : ULONG {
				f_Content_Length = 0x12bc2f1c,
				f_Location = 0x5e9e89cb, /* Location */
			};

			ULONG h;
			BOOL fRedirect = FALSE;

			switch (StatusCode)
			{
			case 200:
				h = f_Content_Length;
				break;
			case 301:
			case 302:
				h = f_Location;
				fRedirect = TRUE;
				break;
			default : return 0;
			}

			if (PSTR body = ParseHTTPHeaders(headers, Buf + cbTransferred, &LineCount))
			{
				if (LineCount)
				{
					PSTR* values = (PSTR*)alloca(LineCount * (sizeof(PSTR) + sizeof(ULONG)));
					PULONG hash = (PULONG)(values + LineCount);
					GetHTTPHeaders(headers, hash, values, LineCount);

					do 
					{
						if (*hash++ == h)
						{
							if (fRedirect)
							{
								body = *values;
								while (*body == ' ') body++;

								INTERNET_SCHEME nScheme;
								INTERNET_PORT nPort;
								PSTR lpszUrlPath, lpszHostName;

								if (CrackUrlA(body, &nScheme, &lpszHostName, &nPort, &lpszUrlPath))
								{
									switch (nScheme)
									{
									case INTERNET_SCHEME_HTTP:
										_bittestandreset(&_dwFlags, _bSSL);
										break;
									case INTERNET_SCHEME_HTTPS:
										_bittestandset(&_dwFlags, _bSSL);
										break;
									default: __assume(false);
									}

									int len = (int)strlen(lpszHostName);

									if (PVOID pv = _malloca(++len))
									{
										memcpy(pv, lpszHostName, len);

										_nPort = _byteswap_ushort(nPort);

										STATIC_ASTRING(format, "GET /%s HTTP/1.0\r\n"
											"Host: %s\r\n"
											"User-Agent: Microsoft-Symbol-Server/10.0.0.0\r\n"
											"Connection: Close\r\n"
											"\r\n");

										PSTR buf = (PSTR)ZRingBuffer::GetBuffer();

										len = sprintf_s(buf, ZRingBuffer::GetSize(), format, lpszUrlPath, pv);

										_freea(pv);

										if (0 < len)
										{
											_dwGetDataSize = len;

											_bittestandset(&_dwFlags, _bRedirected);

											//PrintStr(buf, len);
											Log& log = *_log;
											if (&log)
											{
												log.write(buf, len);
											}

											// try prevent STATUS_ADDRESS_ALREADY_EXISTS
											Sleep(100);
										}
									}

									return 0;
								}
							}
							else
							{
								PSTR c;
								if (ULONG64 size = _strtoui64(*values, &c, 10))
								{
									if (!*c)
									{
										_cbBytesNeed.QuadPart = size;
										static LONG scc[64-20];
										size >>= 19;
										int i = 0;
										while (size >>= 1) i++;
										
										InterlockedIncrementNoFence(scc + i);

										return RtlPointerToOffset(Buf, body);
									}
								}
							}

							break;
						}

					} while (values++, --LineCount);

					if (StatusCode == 200)
					{
						_bittestandset(&_dwFlags, _bUnknownLength);
						_cbBytesNeed.QuadPart = 0x200000000;//8Gb
						return RtlPointerToOffset(Buf, body);
					}
				}
			}
		}

		return 0;
	}

	virtual BOOL OnUserData(PSTR Buf, ULONG cbTransferred)
	{
		dbgp_0("%08x:OnUserData(%p, %x)\n", GetCurrentThreadId(), Buf, cbTransferred);

		ULONG cb, len, dwBufferCount, cbReaded = 0;

		if (!_cbBytesNeed.QuadPart)
		{
			// first recv
			STATIC_ASTRING(empty_line, "\r\n\r\n");

			dbgp_0("_dwHeadSize=%x _http_head_buffer=%p\n", _dwHeadSize, _http_head_buffer);

			if (_dwHeadSize)
			{
				cb = e_http_head_max_size - _dwHeadSize;

				if (cb > cbTransferred)
				{
					cb = cbTransferred;
				}

				memcpy(_http_head_buffer + _dwHeadSize, Buf, cb);

				len = _dwHeadSize, _dwHeadSize += cb;

				if (!strnstr(_dwHeadSize, _http_head_buffer, LP(empty_line)))
				{
					dbgp_0("_dwHeadSize=%x->%x\n", len, _dwHeadSize);

					if (e_http_head_max_size != _dwHeadSize)
					{
						return TRUE;
					}
					PostMessageW(_hwnd, e_text, _id, (LPARAM)L"too big http header");
					_status = STATUS_NAME_TOO_LONG;
					_bittestandset(&_dwFlags, _bNotRead);
					return FALSE;
				}

				if (cb = CheckResponce(_http_head_buffer, _dwHeadSize))
				{
					cb -= len;
					dbgp_0("final_1 _dwHeadSize=%x(%x)\n", cb, len);
				}
			}
			else if (strnstr(cbTransferred, Buf, LP(empty_line)))
			{
				cb = CheckResponce(Buf, cbTransferred);
				dbgp_0("final_0 _dwHeadSize=%x\n", cb);
			}
			else
			{
				if (
					cbTransferred >= e_http_head_max_size ||
					(!_http_head_buffer && !(_http_head_buffer = new char[e_http_head_max_size]))
					)
				{
					dbgp_0("bad header\n");
					PostMessageW(_hwnd, e_text, _id, (LPARAM)L"bad http header");
					_status = STATUS_OBJECT_NAME_INVALID;
					_bittestandset(&_dwFlags, _bNotRead);
					return FALSE;
				}
				memcpy(_http_head_buffer, Buf, cbTransferred);
				_dwHeadSize = cbTransferred;
				dbgp_0("partial data, first _dwHeadSize=%x\n", cbTransferred);
				return TRUE;
			}

			if (cb)
			{
				// 200 ok

				if (_cbBytesNeed.QuadPart > 0x2000000 && !_task->IsSingle())
				{
					// pdb too big ( > 32mb)
					dbgp("[%u]:%s<%p>:!!!! %I64u - %S\n", TickNow(_t), __FUNCTION__, this, _cbBytesNeed.QuadPart, _FileName);
					_status = STATUS_FILE_TOO_LARGE;
					_bittestandset(&_dwFlags, _bNotRead);

					return FALSE;
				}

				UNICODE_STRING ObjectName;
				OBJECT_ATTRIBUTES oa = { sizeof(oa), _hRoot, &ObjectName };
				RtlInitUnicodeString(&ObjectName, _FileName);

				NTSTATUS status = _pFileWriter->Create(&oa, &_cbBytesNeed, _bittest(&_dwFlags, _bUnknownLength));

				if (_hRoot)
				{
					NtClose(_hRoot);
					_hRoot = 0;
				}

				if (0 > status)
				{
					_status = status;
					_bittestandset(&_dwFlags, _bNotRead);
					PostMessageW(_hwnd, e_pdbcreate, _id, (LPARAM)status);
					return FALSE;
				}

				_dwExtraSize = (_BytesPerSector - _cbBytesNeed.LowPart) & (_BytesPerSector - 1);

				NotifyUI(e_length);

				if (!(cbTransferred -= cb))
				{
					// yet no data
					return TRUE;// continue read
				}

				Buf += cb;

				if (!_bittest(&_dwFlags, _bSSL))
				{
					memcpy(ZRingBuffer::GetBuffer(), Buf, cbTransferred);
				}
			}
			else
			{
				// redirect or fail
				_status = STATUS_OBJECT_NAME_NOT_FOUND;
				_bittestandset(&_dwFlags, _bNotRead);
				if (!_bittest(&_dwFlags, _bRedirected))
				{
					Log& log = *_log;
					if (&log)
					{
						if (PSTR body = strnstr(cbTransferred, Buf, 4, "\r\n\r\n"))
						{
							log.write(body, cbTransferred - RtlPointerToOffset(Buf, body));
						}
					}
				}
				return FALSE;
			}
		}

		if (_dwBufferCount) 
		{
			dwBufferCount = _dwBufferCount;
			WSABUF* pBuf = _Buffers;
			do 
			{
				if (len = pBuf->len)
				{
					memcpy(pBuf->buf, Buf, len = min(len, cbTransferred));
					cbReaded += len, Buf += len, pBuf->len -= len, pBuf->buf += len;
					if (!(cbTransferred -= len))
					{
						break;
					}
				}
			} while (pBuf++, --dwBufferCount);
		}
		else
		{
			cbReaded = cbTransferred;
		}

		dbgp_0("%08x:OnUserData(%x)\n", GetCurrentThreadId(), cbReaded);

		if (cbReaded)
		{
			_dwNumberOfBytesRead += cbReaded;

			if (0 >= (_cbBytesNeed.QuadPart -= cbReaded))
			{
				_bittestandset(&_dwFlags, _bNotRead);

				dbgp_0("%08x:read end (%u)\n", GetCurrentThreadId());
				// read end
				_dwNumberOfBytesRead += _dwExtraSize;
				dbgp_0("%08x:OnUserData-end(%x)\n", GetCurrentThreadId(), cbReaded);
			}

			NotifyUI(e_recv);
		}
		else
		{
			__debugbreak();
		}

		return !_bittest(&_dwFlags, _bNotRead);
	}

	void NotifyUI(UINT msg)
	{
		PostMessageW(_hwnd, msg, _id, _bittest(&_dwFlags, _bUnknownLength) ? (ULONG)(_cbBytesNeed.QuadPart >> 3) : _cbBytesNeed.LowPart);
	}

	virtual void OnIp(ULONG ip)
	{
		dbgp("[%u]:%s<%p><%S>(%s) -> %x:%x\n", TickNow(_t), __FUNCTION__, this, _FileName, (PSTR)ZRingBuffer::GetBuffer() + _dwGetDataSize, ip, _byteswap_ushort(_nPort));
		
		SaveTick(_t);

		Log& log = *_log;
		if (&log)
		{
			char sz[24];
			ULONG n = _countof(sz);
			RtlIpv4AddressToStringExA((in_addr *)&ip, _nPort, sz, &n);
			log("OnIp(%s)\r\n", sz);
		}

		if (ip)
		{
			_ip = ip;

			if (ULONG err = Connect(ip, _nPort))
			{
				_ip = 0;
				PostMessageW(_hwnd, e_connect, _id, err);
			}
			else
			{
				PostMessageW(_hwnd, e_text, _id, (LPARAM)L"connecting...");
				return ;
			}
		}
		else
		{
			PostMessageW(_hwnd, e_connect, _id, DNS_ERROR_RECORD_DOES_NOT_EXIST);
		}
		Next();
	}

	~CFileDownloadS()
	{
		dbgp("[%u]:%s<%p>\n", TickNow(_t), __FUNCTION__, this);
		_bittestandreset(&_dwFlags, _bRedirected);

		Log& log = *_log;
		if (&log)
		{
			if (!_bittest(&_dwFlags, _bOk))
			{
				if (PWSTR psz = log)
				{
					if (!PostMessageW(_hwnd, e_packet, 0, (LPARAM)psz))
					{
						LocalFree(psz);
					}
				}
			}

			delete &log;
			_log = 0;
		}

		Cleanup();

		if (_http_head_buffer)
		{
			delete [] _http_head_buffer;
		}

		if (PVOID pv = ZRingBuffer::GetBuffer())
		{
			VirtualFree(pv, 0, MEM_RELEASE);
		}

		_task->DecActive();
		_task->Release();
	}

	void Cleanup()
	{
		dbgp_1("[%u]:%s<%p>([f=%x] %p %S)\n", TickNow(_t), __FUNCTION__, this, _dwFlags, _hRoot, _FileName);

		_cbBytesNeed.QuadPart = 0;
		_dwBufferCount = 0;
		_dwNumberOfBytesRead = 0;

		_status = STATUS_UNSUCCESSFUL;

		_bittestandreset(&_dwFlags, _bWriteActive);
		_bittestandreset(&_dwFlags, _bNotRead);
		_bittestandreset(&_dwFlags, _bHandshakeDone);
		_bittestandreset(&_dwFlags, _bConnected);
		_bittestandreset(&_dwFlags, _bIoStart);
		_bittestandreset(&_dwFlags, _bUnknownLength);

		if (!_bittestandreset(&_dwFlags, _bRedirected))
		{
			_bittestandreset(&_dwFlags, _bSSL);

			union {
				PWSTR FileName;
				HANDLE hRoot;
			};

			if (FileName = _FileName)
			{
				delete [] FileName;
				_FileName = 0;
			}

			if (hRoot = _hRoot)
			{
				NtClose(hRoot);
				_hRoot = 0;
			}
		}
	}

public:

	virtual void AddRef()
	{
		IO_OBJECT::AddRef();
	}

	virtual void Release()
	{
		IO_OBJECT::Release();
	}

	void Start()
	{
		_task->Register(this, _id);
		Next();
	}

	void Next()
	{
		dbgp("[%u]:%s<%p> <- %p\n", TickNow(_t), __FUNCTION__, this, _ReturnAddress());

		BOOLEAN bRedirected = _bittest(&_dwFlags, _bRedirected);

		Cleanup();

		if (getHandleNoLock() && !_task->IsStop())
		{
			if (bRedirected)
			{
				PostMessageW(_hwnd, e_text, _id, (LPARAM)L"resolving host...");
				//dbgp("%s<%p>(%s)\n", __FUNCTION__, this, (PSTR)ZRingBuffer::GetBuffer() + _dwGetDataSize);

				STATIC_ASTRING(Host, "\r\nHost: ");
				PSTR host = strnstr(_dwGetDataSize, (PSTR)ZRingBuffer::GetBuffer(), _countof(Host) - 1, Host);
				PSTR pc = strchr(host, '\r');
				*pc = 0;
				DnsToIp(host, DNS_RTYPE_A, DNS_QUERY_NO_WIRE_QUERY);
				*pc = '\r';
				return;
			}

			ULONG cb = 0, rcb;
			PVOID stack = alloca(guz);
			PWSTR path = 0;
			STATIC_WSTRING(globalroot, "\\\\.\\global\\globalroot");

			LONG n;

			ULONG iServer = _task->GetServer(), ip = _task->get_ip();

			while (!_task->IsStop())
			{
				if (PCSTR name = _task->GetNextName(&n))
				{
					rcb = ((ULONG)strlen(name) + 1) << 1;
					BOOL bNtPath = *name == '\\';
					if (bNtPath)
					{
						rcb += sizeof(globalroot) - sizeof(WCHAR);
					}

					if (cb < rcb)
					{
						cb = RtlPointerToOffset(path = (PWSTR)alloca(rcb - cb), stack);
					}

					if (bNtPath)
					{
						swprintf_s(path, cb >> 1, L"%s%S", globalroot, name);
					}
					else
					{
						swprintf_s(path, cb >> 1, L"%S", name);
					}

					NTSTATUS status = GetPdbforPE(iServer, path);

					if (status) 
					{
						PostMessageW(_hwnd, e_init, _id|(n << 8), status);
						continue;
					}

					dbgp("[%u]:%s<%p>(%S)\n", TickNow(_t), __FUNCTION__, this,_FileName);

					_nPort = 0x5000; //_byteswap_ushort(INTERNET_DEFAULT_HTTP_PORT);

					if (status = Connect(_ip = ip, 0x5000))
					{
						_ip = 0;
						PostMessageW(_hwnd, e_connect, _id, status);
					}
					else
					{
						PostMessageW(_hwnd, e_name, _id, n);
						return ;// -> Disconnect -> Next
					}
				}

				break;
			}
		}

		_task->Unregister(_id);

		if (_pFileWriter)
		{
			_pFileWriter->Release();
			_pFileWriter = 0;
		}
	}

	CFileDownloadS(ZDllVector* task) : CSSLEndpoint(task->getCred())
	{
		dbgp("%s<%p>\n", __FUNCTION__, this);

		task->AddRef();
		task->IncActive();
		_task = task;
		_hwnd = task->get_HWND();
		_id = task->get_ID();
	}

	NTSTATUS GetPdbforPE(ULONG iServer, PCWSTR lpszName)
	{
		HMODULE hmod = LoadLibraryExW(lpszName, 0, LOAD_LIBRARY_AS_DATAFILE);

		if (!hmod) return RtlGetLastNtStatus();

		NTSTATUS status = STATUS_NOT_FOUND;

		ULONG cb;
		BOOLEAN bMappedAsImage = !((DWORD_PTR)hmod & (PAGE_SIZE - 1));
		PIMAGE_DEBUG_DIRECTORY pidd = (PIMAGE_DEBUG_DIRECTORY)RtlImageDirectoryEntryToData(hmod, bMappedAsImage, IMAGE_DIRECTORY_ENTRY_DEBUG, &cb);
		if (pidd && cb && !(cb % sizeof IMAGE_DEBUG_DIRECTORY))
		{
			do 
			{
				struct CV_INFO_PDB 
				{
					ULONG CvSignature;
					GUID Signature;
					ULONG Age;
					char PdbFileName[];
				};

				if (pidd->Type == IMAGE_DEBUG_TYPE_CODEVIEW && pidd->SizeOfData > sizeof(CV_INFO_PDB))
				{
					if (ULONG PointerToRawData = bMappedAsImage ? pidd->AddressOfRawData : pidd->PointerToRawData)
					{
						CV_INFO_PDB* lpcvh = (CV_INFO_PDB*)RtlOffsetToPointer(PAGE_ALIGN(hmod), PointerToRawData);

						if (lpcvh->CvSignature == 'SDSR')
						{
							PCSTR PdbFileName = lpcvh->PdbFileName, c = strrchr(PdbFileName, L'\\');
							if (c)
							{
								PdbFileName = c + 1;
							}

							status = Init(iServer, PdbFileName, &lpcvh->Signature, lpcvh->Age);

							break;
						}
					}
				}

			} while (pidd++, cb -= sizeof IMAGE_DEBUG_DIRECTORY);
		}

		FreeLibrary(hmod);

		return status;
	}

	NTSTATUS AllocateRingBuffer(HANDLE hFile)
	{
		NTSTATUS status = _BytesPerSector ? STATUS_SUCCESS : InitBytesPerSector(hFile, &_BytesPerSector);

		if (0 <= status)
		{
			_MinWriteSize = _BytesPerSector;

			ULONG s = (2*_BytesPerSector + SI::dwAllocationGranularity) & ~SI::dwAllocationGranularity;

			if (s != ZRingBuffer::GetSize())
			{
				PVOID pv = ZRingBuffer::GetBuffer();

				if (pv)
				{
					VirtualFree(pv, 0, MEM_RELEASE);
					ZRingBuffer::Init(0, 0);
					pv = 0;
				}

				SIZE_T size = s;

				if (0 <= (status = ZwAllocateVirtualMemory(NtCurrentProcess(), &pv, 0, &size, MEM_COMMIT, PAGE_READWRITE)))
				{
					ZRingBuffer::Init(pv, s);
				}
			}
		}

		return status;
	}

	NTSTATUS Init(ULONG iServer, PCSTR PdbFileName, PCWSTR FileName, PGUID Signature, ULONG Age)
	{
		WCHAR sz[0x100];

		swprintf_s(sz, _countof(sz), L"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%x", 
			Signature->Data1, Signature->Data2, Signature->Data3,
			Signature->Data4[0], Signature->Data4[1], Signature->Data4[2], Signature->Data4[3], 
			Signature->Data4[4], Signature->Data4[5], Signature->Data4[6], Signature->Data4[7], Age);

		HANDLE hRoot;
		IO_STATUS_BLOCK iosb;
		UNICODE_STRING ObjectName;
		OBJECT_ATTRIBUTES oa = { sizeof(oa), _task->get_Root(), &ObjectName };
		RtlInitUnicodeString(&ObjectName, FileName);

		NTSTATUS status = NtCreateFile(&hRoot, FILE_ADD_SUBDIRECTORY|SYNCHRONIZE, &oa, &iosb, 0, 
			0, FILE_SHARE_VALID_FLAGS, FILE_OPEN_IF, FILE_DIRECTORY_FILE, 0, 0);

		dbgp("%s<%p>: %wZ\n", __FUNCTION__, this, &ObjectName);

		if (0 > status)
		{
			return status;
		}

		oa.RootDirectory = hRoot;

		RtlInitUnicodeString(&ObjectName, sz);

		if (0 <= (status = AllocateRingBuffer(hRoot)))
		{
			status = NtCreateFile(&_hRoot, FILE_ADD_SUBDIRECTORY|SYNCHRONIZE, &oa, &iosb, 0, 
				0, FILE_SHARE_VALID_FLAGS, FILE_OPEN_IF, FILE_DIRECTORY_FILE, 0, 0);
		}

		NtClose(oa.RootDirectory);

		if (0 > status)
		{
			return status;
		}

		RtlInitUnicodeString(&ObjectName, FileName);
		oa.RootDirectory = _hRoot;

		if (IsValidPDBExist(&oa, Signature, Age))
		{
			if (!_task->IsSingle())
			{
				return STATUS_OBJECT_NAME_EXISTS;
			}

			FormatMessage(FORMAT_MESSAGE_IGNORE_INSERTS|FORMAT_MESSAGE_FROM_HMODULE,
				GetModuleHandleW(L"ntdll"), STATUS_OBJECT_NAME_EXISTS, 0, sz, RTL_NUMBER_OF(sz), 0);

			if (MessageBox(_task->get_HWND(), sz, L"Download anyway ?", MB_YESNO|MB_ICONQUESTION) != IDYES)
			{
				return STATUS_OBJECT_NAME_EXISTS;
			}
		}

		static PCSTR s_paths[] = {
			"/download/symbols/", // msdl.microsoft.com
			"/", // chromium-browser-symsrv.commondatastorage.googleapis.com
			"/", // symbols.mozilla.org
			"/sites/downloads/symbols/", // software.intel.com
			"/dir/bin/", // download.amd.com
			"/", // driver-symbols.nvidia.com
		};

		STATIC_ASTRING(httpHeader, "GET %s%s/%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%x/%s HTTP/1.0"
			"\r\nUser-Agent: Microsoft-Symbol-Server/10.0.0.0"
			"\r\nHost: %s"
			"\r\nConnection: close\r\n\r\n");

		PSTR buf = (PSTR)ZRingBuffer::GetBuffer();

		int len = sprintf_s(buf, ZRingBuffer::GetSize(),
			httpHeader, s_paths[iServer],
			PdbFileName, Signature->Data1, Signature->Data2, Signature->Data3,
			Signature->Data4[0], Signature->Data4[1], Signature->Data4[2], Signature->Data4[3], 
			Signature->Data4[4], Signature->Data4[5], Signature->Data4[6], Signature->Data4[7], Age, PdbFileName,
			g_Servers[iServer]);

		if (0 >= len)
		{
			return STATUS_UNSUCCESSFUL;
		}

		_dwGetDataSize = len;
		//PrintStr(buf, _dwGetDataSize);
		Log& log = *_log;
		if (&log)
		{
			log.write(buf, len);
		}

		return status;
	}

	NTSTATUS Init(ULONG iServer, PCSTR PdbFileName, PGUID Signature, ULONG Age)
	{
		Cleanup();

		ULONG UnicodeStringLen = 0;
		PWSTR FileName = 0;

		while (UnicodeStringLen = MultiByteToWideChar(CP_UTF8, 0, PdbFileName, MAXULONG, FileName, UnicodeStringLen))
		{
			if (FileName)
			{
				_FileName = FileName;
				return Init(iServer, PdbFileName, FileName, Signature, Age);
			}

			if (UnicodeStringLen >= MAXSHORT)
			{
				return STATUS_NAME_TOO_LONG;
			}

			if (!(FileName = new WCHAR[UnicodeStringLen]))
			{
				return STATUS_NO_MEMORY;
			}
		}

		if (FileName)
		{
			delete [] FileName;
		}
		
		return STATUS_UNSUCCESSFUL;
	}

	ULONG Create()
	{
		if (!(_pFileWriter = new CFileWriter(this)))
		{
			return ERROR_NO_SYSTEM_RESOURCES;
		}

		if (ULONG dwError = CTcpEndpoint::Create(SI::dwAllocationGranularity + 1))
		{
			return dwError;
		}

		return NOERROR;
	}

	INTERNET_PORT SetProtocol(ULONG iServer)
	{
		switch (iServer)
		{
		case s_intel:
		case s_mozilla:
		case s_amd:
		case s_nvidia:
			_bittestandset(&_dwFlags, _bSSL);
			_nPort = 0xbb01;
			break;
		}

		return _nPort;
	}

	void SetLog(Log* log)
	{
		_log = log;
	}

	ULONG get_ID()
	{
		return _id;
	}
};

ULONG WorkItem(ZDllVector* task)
{
	if (CFileDownloadS* p = new CFileDownloadS(task))
	{
		if (!p->Create())
		{
			p->Start();
		}
		p->Release();
	}
	task->DecActive();
	task->Release();
	return 0;
}

ULONG CreateSingleDownload(SDP* params)
{
	ZDllVector* task = params->task;
	ULONG dwError = ERROR_NO_SYSTEM_RESOURCES;

	if (CFileDownloadS* p = new CFileDownloadS(task))
	{
		if (task->IsSingle())
		{
			if (Log* log = new Log)
			{
				if (log->Init(0x10000))
				{
					delete log;
				}
				else
				{
					p->SetLog(log);
				}
			}
		}

		ULONG iServer = task->GetServer();

		if (!(dwError = p->Create()) &&
			!(dwError = RtlNtStatusToDosError(params->type == SDP::e_path ? 
			p->GetPdbforPE(iServer, params->DllFileName) : p->Init(iServer, params->PdbFileName, &params->Signature, params->Age))))
		{
			task->Register(p, 0);

			PostMessageW(task->get_HWND(), e_text, p->get_ID(), (LPARAM)L"connecting(0)...");

			dwError = p->Connect(task->get_ip(), p->SetProtocol(iServer));
		}

		if (dwError)
		{
			p->Next();
		}

		p->Release();
	}

	return dwError;
}

_NT_END