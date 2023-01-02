// GetPdb.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include "resource.h"
#include "../inc/idcres.h"

_NT_BEGIN

#include "../inc/initterm.h"
#include "../asio/ssl.h"
#include "../asio/CiclicBuffer.h"
#include "dllVector.h"
#include "qpm.h"

ULONG WINAPI EnumAllDlls(PVOID );
BOOL IsValidPDBExist(POBJECT_ATTRIBUTES poa, PGUID Signature, DWORD Age);

HANDLE g_hDrv;

#include "../tkn/tkn.h"
#define FormatStatus(err, module, status) FormatMessage(\
	FORMAT_MESSAGE_IGNORE_INSERTS|FORMAT_MESSAGE_FROM_HMODULE,\
	GetModuleHandleW(L ## # module),status, 0, err, RTL_NUMBER_OF(err), 0)

#define FormatWin32Status(err, status) FormatStatus(err, kernel32.dll, status)
#define FormatNTStatus(err, status) FormatStatus(err, ntdll.dll, status)

void OnBrowse(_In_ HWND hwndDlg, 
			  _In_ UINT nIDDlgItem, 
			  _In_ UINT cFileTypes, 
			  _In_ const COMDLG_FILTERSPEC *rgFilterSpec, 
			  _In_ UINT iFileType = 0)
{
	IFileDialog *pFileOpen;

	if (0 <= CoCreateInstance(__uuidof(FileOpenDialog), NULL, CLSCTX_ALL, IID_PPV_ARGS(&pFileOpen)))
	{
		pFileOpen->SetOptions(FOS_NOVALIDATE|FOS_NOTESTFILECREATE|
			FOS_NODEREFERENCELINKS|FOS_DONTADDTORECENT|FOS_FORCESHOWHIDDEN);

		if (0 <= pFileOpen->SetFileTypes(cFileTypes, rgFilterSpec) && 
			0 <= pFileOpen->SetFileTypeIndex(1 + iFileType) && 
			0 <= pFileOpen->Show(hwndDlg))
		{
			IShellItem *pItem;

			if (0 <= pFileOpen->GetResult(&pItem))
			{
				PWSTR pszFilePath;
				if (0 <= pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath))
				{
					SetDlgItemTextW(hwndDlg, nIDDlgItem, pszFilePath);
					CoTaskMemFree(pszFilePath);
				}
				pItem->Release();
			}
		}

		pFileOpen->Release();
	}
}

void OnBrowse(_In_ HWND hwndDlg, _In_ UINT nIDDlgItem, _In_ PCWSTR lpszTitle)
{
	WCHAR buf[MAX_PATH];

	BROWSEINFO bi = { 
		0, 0, 0, lpszTitle, BIF_DONTGOBELOWDOMAIN|BIF_NEWDIALOGSTYLE|BIF_RETURNONLYFSDIRS
	};

	if (PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi))
	{
		if (SHGetPathFromIDListEx(pidl, buf, _countof(buf), GPFIDL_DEFAULT))
		{
			SetDlgItemTextW(hwndDlg, nIDDlgItem, buf);
		}

		CoTaskMemFree(pidl);
	}
}

LPWSTR xwcscpy(LPWSTR dst, LPCWSTR src)
{
	WCHAR c;
	do *dst++ = c = *src++; while(c);
	return dst - 1;
}

STATIC_WSTRING(global, "\\GLOBAL??\\");

enum { TimerID = 1 };

NTSTATUS OpenFolderIf(PHANDLE phFile, PCWSTR sz, PCWSTR path)
{
	HANDLE hFile = 0;
	IO_STATUS_BLOCK iosb;
	UNICODE_STRING ObjectName = { sizeof(global) - sizeof(WCHAR), MAXUSHORT - 1, (PWSTR)sz };
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName };
	BOOL bFirstSlash = TRUE;

	NTSTATUS status;

	for (;;) 
	{
		switch (*path++)
		{
		case 0:
			*phFile = hFile;
			return hFile ? 0 : STATUS_OBJECT_PATH_INVALID;
		case '\\':
			if (bFirstSlash)
			{
				bFirstSlash = FALSE;
			}
			else
			{
				if (hFile)
				{
					NtClose(hFile);
				}

				if (0 > (status = NtCreateFile(&hFile, FILE_ADD_SUBDIRECTORY|SYNCHRONIZE, &oa, &iosb, 0, 
					0, FILE_SHARE_VALID_FLAGS, FILE_OPEN_IF, FILE_DIRECTORY_FILE, 0, 0)))
				{
					return status;
				}
			}
		}

		ObjectName.Length += sizeof(WCHAR);
	}
}

DWORD WorkItem(ZDllVector* task);

class MsIp : public CSocketObject
{
	HWND m_hwnd;
	ULONG m_iServer;

public:

	virtual void OnIp(DWORD ip)
	{
		PostMessage(m_hwnd, e_ip, m_iServer, ip);
	}

	MsIp(HWND hwnd, ULONG iServer) : m_iServer(iServer), m_hwnd(hwnd)
	{
	}
};

#ifdef _WIN64
#define CD_MAGIC 0x8e3420ad9691DAE6
#else
#define CD_MAGIC 0x9691DAE6
#endif

void FillCombo(HWND hwndCB)
{
	NTSTATUS status;
	DWORD cb = 0x40000;
	do 
	{
		if (PUCHAR buf = new UCHAR[cb += PAGE_SIZE])
		{
			if (0 <= (status = NtQuerySystemInformation(SystemProcessInformation, buf, cb, &cb)))
			{
				union {
					PBYTE pb;
					PSYSTEM_PROCESS_INFORMATION pspi;
				};

				pb = buf;

				ULONG NextEntryOffset = 0;
				WCHAR sz[0x100];
				int i0 = -1;

				do 
				{
					pb += NextEntryOffset;

					if (!pspi->UniqueProcessId)
					{
						RtlInitUnicodeString(&pspi->ImageName, L"For All loaded PE");
					}

					if (0 < swprintf_s(sz, _countof(sz), L"%04x(%04x) %x %3u %wZ", 
						(ULONG)(ULONG_PTR)pspi->UniqueProcessId, 
						(ULONG)(ULONG_PTR)pspi->InheritedFromUniqueProcessId,
						pspi->SessionId, 
						pspi->NumberOfThreads, 
						&pspi->ImageName))
					{
						int i = ComboBox_AddString(hwndCB, sz);
						if (0 <= i)
						{
							ComboBox_SetItemData(hwndCB, i, pspi->UniqueProcessId);
						}

						if (!pspi->UniqueProcessId)
						{
							i0 = i;
						}
					}

				} while (NextEntryOffset = pspi->NextEntryOffset);

				if (0 <= i0) ComboBox_SetCurSel(hwndCB, i0);
			}

			delete [] buf;
		}
		else
		{
			break;
		}

	} while (status == STATUS_INFO_LENGTH_MISMATCH);
}

PCSTR g_Servers[] = {
	"msdl.microsoft.com", // https://msdl.microsoft.com/download/symbols/
	"chromium-browser-symsrv.commondatastorage.googleapis.com", // https://chromium-browser-symsrv.commondatastorage.googleapis.com/
	"symbols.mozilla.org", // https://symbols.mozilla.org/
	"software.intel.com", // https://software.intel.com/sites/downloads/symbols/
	"download.amd.com", // https://download.amd.com/dir/bin
	"driver-symbols.nvidia.com", // https://driver-symbols.nvidia.com/
};

class CDialog : public ZDllVector
{
	enum { e_LogSize = 0x10000 };
	struct DWL_PRG 
	{
		HWND hwndProgress, hwndStatus, hwndName;
	} m_arr[9];
	LONG m_nv[8];

	HWND m_hwnd, m_hwndCD;
	HANDLE m_hRoot = 0;
	PSTR m_szLog = 0;
	HFONT m_hFont = 0;
	LONG m_dwRef = 1, m_dx;
	ULONG m_nProcessed, m_nOk, m_nFail, m_nExist, m_cbFree, m_crc;
	BOOLEAN m_bDirChanged = TRUE, m_DownloadActive = FALSE, m_bAll = 0, m_bTimerActive = 0;

	//---------------------------------------------------------

	virtual HANDLE get_Root()
	{
		return m_hRoot;
	}

	virtual HWND get_HWND()
	{
		return m_hwnd;
	}

	//---------------------------------------------------------

	static INT_PTR CALLBACK DlgProc_s(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		return reinterpret_cast<CDialog*>(GetWindowLongPtr(hwnd, DWLP_USER))->DlgProc(hwnd, uMsg, wParam, lParam);
	}

	static INT_PTR CALLBACK StartDlgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		if (uMsg == WM_INITDIALOG)
		{
			SetWindowLongPtr(hwnd, DWLP_USER, lParam);
			SetWindowLongPtr(hwnd, DWLP_DLGPROC, (LONG_PTR)DlgProc_s);
			return reinterpret_cast<CDialog*>(GetWindowLongPtr(hwnd, DWLP_USER))->DlgProc(hwnd, uMsg, wParam, lParam);
		}

		return 0;
	}
	
	void OnTimer(HWND hwnd)
	{
		ULONG iServer = GetServer();
		if (MsIp* p = new MsIp(hwnd, iServer))
		{
			p->DnsToIp(g_Servers[iServer]);
			p->Release();
		}
	}

	void ActivateTimer(HWND hwnd)
	{
		OnTimer(hwnd);
		m_bTimerActive = SetTimer(hwnd, TimerID, 2000, 0) != 0;
	}

	void OnInitDialog(HWND hwnd)
	{
		AddRef();

		m_hwnd = hwnd, m_hwndCD = 0, m_crc = 0;

		ActivateTimer(hwnd);

		SendMessage(hwnd, WM_SETICON, ICON_BIG, (LPARAM)LoadImage((HINSTANCE)&__ImageBase, 
			MAKEINTRESOURCE(IDI_ICON1), IMAGE_ICON, GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON), LR_SHARED));

		SendMessage(hwnd, WM_SETICON, ICON_SMALL, (LPARAM)LoadImage((HINSTANCE)&__ImageBase, 
			MAKEINTRESOURCE(IDI_ICON1), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_SHARED));
		
		WCHAR buf[MAX_PATH];

		if (ULONG cch = GetWindowsDirectory(buf, _countof(buf)))
		{
			if (!wcscpy_s(buf + cch, _countof(buf) - cch, L"\\symbols\\"))
			{
				SetDlgItemTextW(hwnd, IDC_EDIT2, buf);
			}
			if (!wcscpy_s(buf + cch, _countof(buf) - cch, L"\\system32\\"))
			{
				SetDlgItemTextW(hwnd, IDC_EDIT1, buf);
			}
		}

		int i = 9;

		do 
		{
			DWL_PRG* p = m_arr + --i;

			p->hwndProgress = GetDlgItem(hwnd, IDC_PROGRESS1 + i);
			p->hwndStatus = GetDlgItem(hwnd, IDC_STATIC1 + 2*i);
			p->hwndName = GetDlgItem(hwnd, IDC_STATIC2 + 2*i);
		} while (i);

		m_bAll = FALSE;

		static PCWSTR Servers[] = {
			L"nvidia", // https://driver-symbols.nvidia.com/
			L"amd", // https://download.amd.com/dir/bin
			L"intel", // https://software.intel.com/sites/downloads/symbols/
			L"mozilla", // https://symbols.mozilla.org/
			L"google", // https://chromium-browser-symsrv.commondatastorage.googleapis.com/
			L"microsoft", // https://msdl.microsoft.com/download/symbols/
		};

		i = _countof(Servers);
		HWND hwndCB = GetDlgItem(hwnd, IDC_COMBO2);
		do 
		{
			--i;
			ComboBox_SetItemData(hwndCB, i, ComboBox_AddString(hwndCB, Servers[i]));
		} while (i);
		ComboBox_SetCurSel(hwndCB, 0);

		RECT rc, RC;
		m_dx = 0;
		if (GetWindowRect(GetDlgItem(hwnd, IDC_PROGRESS2), &RC) && GetWindowRect(hwnd, &rc))
		{
			if ((m_dx = rc.bottom - RC.top + GetSystemMetrics(SM_CYBORDER)))
			{
				MoveWindow(hwnd, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top - m_dx, FALSE);
			}
		}

		m_szLog = new CHAR[e_LogSize];

		NONCLIENTMETRICS ncm = { sizeof(NONCLIENTMETRICS) };
		if (SystemParametersInfo(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
		{
			ncm.lfStatusFont.lfQuality = CLEARTYPE_QUALITY;
			ncm.lfStatusFont.lfPitchAndFamily = FIXED_PITCH|FF_MODERN;
			wcscpy(ncm.lfStatusFont.lfFaceName, L"Courier New");

			if (HFONT hFont = CreateFontIndirect(&ncm.lfStatusFont))
			{
				m_hFont = hFont;
				SendDlgItemMessageW(hwnd, IDC_COMBO1, WM_SETFONT, (WPARAM)hFont, 0);
			}
		}

		if (HANDLE hi = LoadImage((HINSTANCE)&__ImageBase, 
			MAKEINTRESOURCE(IDI_ICON2), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_SHARED))
		{
			SendDlgItemMessageW(hwnd, IDC_BUTTON2, BM_SETIMAGE, IMAGE_ICON, (LPARAM)hi);
			SendDlgItemMessageW(hwnd, IDC_BUTTON3, BM_SETIMAGE, IMAGE_ICON, (LPARAM)hi);
		}
	}

	void toCtrl(HWND hwndCtrl)
	{
		MessageBeep(MAXDWORD);
		SetFocus(hwndCtrl);
	}

	void toCtrl(HWND hwnd, HWND hwndCtrl, ULONG error, PCWSTR caption)
	{
		NTSTATUS status = RtlGetLastNtStatus();
		if (RtlNtStatusToDosError(status) == error)
		{
			toCtrl(hwnd, hwndCtrl, status, caption);
		}
		else
		{
			WCHAR err[256];
			FormatWin32Status(err, error);
			SetFocus(hwndCtrl);
			MessageBox(hwnd, err, caption, MB_ICONWARNING);
		}
	}

	void toCtrl(HWND hwnd, HWND hwndCtrl, NTSTATUS status, PCWSTR caption)
	{
		WCHAR err[256];
		FormatNTStatus(err, status);
		UINT type;
		switch ((ULONG)status >> 30)
		{
		case 0:
			type = MB_OK;
			break;
		case 1:
			type = MB_OK|MB_ICONINFORMATION;
			break;
		case 2:
			type = MB_OK|MB_ICONWARNING;
			break;
		case 3:
			type = MB_OK|MB_ICONHAND;
			break;
		default:__assume(false);
		}
		SetFocus(hwndCtrl);
		MessageBox(hwnd, err, caption, type);

	}

	BOOL OpenFolder(HWND hwnd, HWND hwndCtrl)
	{
		if (int len = GetWindowTextLength(hwndCtrl))
		{
			PWSTR buf = (PWSTR)alloca(((len + 1) << 1) + sizeof(global)), path = buf + RTL_NUMBER_OF(global) - 1;
			
			memcpy(buf, global, sizeof(global) - sizeof(WCHAR));

			if (len == GetWindowText(hwndCtrl, path, len + 1))
			{
				if (path[len - 1] != '\\')
				{
					path[len] = '\\';
					path[len + 1] = 0;
				}

				if (m_hRoot)
				{
					NtClose(m_hRoot);
					m_hRoot = 0;
				}

				NTSTATUS status = OpenFolderIf(&m_hRoot, buf, path);

				if (0 > status)
				{
					toCtrl(hwnd, hwndCtrl, status, L"Open Folder");
				}
				else
				{
					m_crc = RtlComputeCrc32(0, _wcsupr(path), ((ULONG)wcslen(path)-1)*sizeof(WCHAR));
					m_bDirChanged = FALSE;
					return TRUE;
				}
			}
		}
		toCtrl(hwndCtrl);

		return FALSE;
	}
	
	void StartStop(HWND hwnd, BOOLEAN bStart)
	{
		EnableWindow(GetDlgItem(hwnd, IDOK), !bStart);
		EnableWindow(GetDlgItem(hwnd, IDCANCEL), bStart);
		EnableWindow(GetDlgItem(hwnd, IDC_EDIT2), !bStart);
		EnableWindow(GetDlgItem(hwnd, IDC_BUTTON3), !bStart);
		EnableWindow(GetDlgItem(hwnd, IDC_CHECK1), !bStart && !GetServer());
		EnableWindow(GetDlgItem(hwnd, IDC_COMBO1), !bStart && !GetServer());
		EnableWindow(GetDlgItem(hwnd, IDC_BUTTON1), !bStart && !GetServer());
		EnableWindow(GetDlgItem(hwnd, IDC_COMBO2), !bStart);
		if (!m_bAll) 
		{
			EnableWindow(GetDlgItem(hwnd, IDC_EDIT1), !bStart);
			EnableWindow(GetDlgItem(hwnd, IDC_BUTTON2), !bStart);
		}
		m_DownloadActive = bStart;
	}

	void DoLog(UINT i, PCSTR msg, NTSTATUS status)
	{
		if (m_bAll)
		{
			if (PCSTR name = GetName(m_nv[i]))
			{
				LONG len = sprintf_s(m_szLog + e_LogSize - m_cbFree, m_cbFree, "%s - %s - %x\r\n", name, msg, status);
				if (0 < len)
				{
					m_cbFree -= len;
				}
			}
		}
	}

	void SetOverallProgress(NTSTATUS status)
	{
		switch (status)
		{
		case 0:
			m_nOk++;
			break;
		case STATUS_OBJECT_NAME_EXISTS:
			m_nExist++;
			break;
		default:
			m_nFail++;
		}

		if (m_bAll)
		{
			PostMessage(m_arr[8].hwndProgress, PBM_SETPOS, ++m_nProcessed, GetDllCount());
			WCHAR sz[32];
			swprintf_s(sz, _countof(sz), L"%u / %u", m_nProcessed, GetDllCount());
			SetWindowText(m_arr[8].hwndStatus, sz);
		}
	}

	void ToggleSize(HWND hwnd)
	{
		if (m_dx = -m_dx)
		{
			RECT rc;
			if (GetWindowRect(hwnd, &rc))
			{
				MoveWindow(hwnd, rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top - m_dx, TRUE);
			}
		}
	}

	INT_PTR DlgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		static const COMDLG_FILTERSPEC rgSpec[] =
		{ 
			{ L"Dll files", L"*.dll" },
			{ L"Exe files", L"*.exe" },
			{ L"Sys files", L"*.sys" },
			{ L"All files", L"*" },
		};

		HWND hwndCtrl;
		DWORD len;
		WCHAR sz[128];

		switch(uMsg)
		{
		case WM_SETCURSOR:
			if (IsDebuggerPresent())
			{
				SetWindowTextW(hwnd, L"debugging..");
			}
			break;

		case WM_TIMER:
			OnTimer(hwnd);
			break;

		case e_packet:
			if (hwnd = CreateWindowExW(0, WC_EDIT, L"Fail", 
				WS_OVERLAPPEDWINDOW|WS_VSCROLL|WS_HSCROLL|ES_MULTILINE|ES_AUTOHSCROLL|ES_AUTOVSCROLL, 
				CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, 0, 0, 0, 0))
			{
				if (m_hFont)
				{
					SendMessage(hwnd, WM_SETFONT, (WPARAM)m_hFont, 0);
				}

				HLOCAL hMem = (HLOCAL)SendMessage(hwnd, EM_GETHANDLE, 0, 0);
				SendMessage(hwnd, EM_SETHANDLE, lParam, 0);
				lParam = (LPARAM)hMem;

				ShowWindow(hwnd, SW_SHOW);
			}
			LocalFree((PVOID)lParam);
			break;

		case e_List:
			Init((PULONG)lParam, (ULONG)wParam);
			if ((ULONG)wParam)
			{
				m_nProcessed = 0, m_nOk = 0, m_nFail = 0, m_nExist = 0;
				PostMessage(m_arr[8].hwndProgress, PBM_SETRANGE32, 0, GetDllCount());
				PostMessage(m_arr[8].hwndProgress, PBM_SETPOS, 0, 0);
				int n = 9;
				do 
				{
					SetWindowText(m_arr[--n].hwndStatus, 0);
					SetWindowText(m_arr[n].hwndName, 0);
				} while (n);
				swprintf_s(sz, _countof(sz), L"%u / %u", 0, GetDllCount());
				n = 8;//8
				do 
				{
					AddRef();
					IncActive();
					if (!QueueUserWorkItem((PTHREAD_START_ROUTINE)WorkItem, static_cast<ZDllVector*>(this), 0))
					{
						DecActive();
						Release();
					}
				} while (--n);
			}
			DecActive();
			SetWindowLongPtr(hwnd, DWLP_MSGRESULT, e_List);
			return TRUE;

		case e_stop:
			StartStop(hwnd, FALSE);
			if (m_bAll && m_cbFree != e_LogSize)
			{
				if (hwnd = CreateWindowExW(0, WC_EDIT, L"Fail PDBs", 
					WS_OVERLAPPEDWINDOW|WS_VSCROLL|WS_HSCROLL|ES_MULTILINE|ES_AUTOHSCROLL|ES_AUTOVSCROLL, 
					CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, 0, 0, 0, 0))
				{
					if (m_hFont)
					{
						SendMessage(hwnd, WM_SETFONT, (WPARAM)m_hFont, 0);
					}

					SetWindowTextA(hwnd, m_szLog);
					ShowWindow(hwnd, SW_SHOW);
				}
			}
			m_nOk = 0, m_nFail = 0;
			break;

		case e_text:
			SetWindowText(m_arr[wParam].hwndStatus, (PCWSTR)lParam);
			break;

		case e_connect:
			if ((NTSTATUS)lParam)
			{
				swprintf_s(sz, _countof(sz), L"connect error %x", (ULONG)lParam);
				SetWindowText(m_arr[wParam].hwndStatus, sz);
				SetOverallProgress((NTSTATUS)lParam);
				DoLog((UINT)wParam, "connect", (NTSTATUS)lParam);
			}
			break;

		case e_send:
			swprintf_s(sz, _countof(sz), L"send error %x", (ULONG)lParam);
			SetWindowText(m_arr[wParam].hwndStatus, sz);
			SetOverallProgress((NTSTATUS)lParam);
			break;

		case e_pdbcreate:
			swprintf_s(sz, _countof(sz), L"pdb create = %x", (ULONG)lParam);
			SetWindowText(m_arr[wParam].hwndStatus, sz);
			SetOverallProgress((NTSTATUS)lParam);
			break;

		case e_disconnect:
			SetOverallProgress((NTSTATUS)lParam);
			if (lParam)
			{
				SetWindowText(m_arr[wParam].hwndStatus, L"download fail");
				DoLog((UINT)wParam, "download", (NTSTATUS)lParam);
			}
			else if (!m_bAll) 
			{
				SetWindowText(m_arr[wParam].hwndStatus, L"OK");
				if (m_hwndCD)
				{
					PostMessageW(m_hwndCD, WM_COMMAND, IDOK, 0);
				}
			}
			break;

		case e_ip:
			if ((ULONG)lParam)
			{
				if (wParam == GetServer())
				{
					set_ip((ULONG)lParam);
					EnableWindow(GetDlgItem(hwnd, IDOK), TRUE);
		case WM_DESTROY:
					if (m_bTimerActive)
					{
						m_bTimerActive = FALSE;
						KillTimer(hwnd, TimerID);
					}
				}
			}
			break;

		case e_recv:
			swprintf_s(sz, _countof(sz), L"downloading... %u", (ULONG)lParam);
			SetWindowText(m_arr[wParam].hwndStatus, sz);
			PostMessage(m_arr[wParam].hwndProgress, PBM_SETPOS, -lParam, 0);
			break;

		case e_length:
			swprintf_s(sz, _countof(sz), L"downloading... %u", (ULONG)lParam);
			SetWindowText(m_arr[wParam].hwndStatus, sz);
			PostMessage(m_arr[wParam].hwndProgress, PBM_SETRANGE32, -lParam, 0);
			break;

		case e_name:
			PostMessage(m_arr[wParam].hwndProgress, PBM_SETRANGE32, 0, 0);
			PostMessage(m_arr[wParam].hwndProgress, PBM_SETPOS, 0, 0);
			SetWindowTextA(m_arr[wParam].hwndName, strrchr(GetName((LONG)lParam), '\\') + 1);
			SetWindowText(m_arr[wParam].hwndStatus, L"connecting...");
			m_nv[wParam] = (LONG)lParam;
			break;

		case e_init:
			SetOverallProgress((NTSTATUS)lParam);
			if (lParam != STATUS_OBJECT_NAME_EXISTS)
			{
				m_nv[(UCHAR)wParam] = (DWORD)wParam >> 8;
				DoLog((UCHAR)wParam, "locate", (NTSTATUS)lParam);
			}
			break;

		case WM_CLOSE:
			if (!m_DownloadActive && !m_hwndCD)
			{
				EndDialog(hwnd, 0);
			}
			break;

		case WM_NCDESTROY:
			Release();
			break;

		case WM_INITDIALOG:
			OnInitDialog(hwnd);
			return 0;

		case WM_COPYDATA:
			if (reinterpret_cast<COPYDATASTRUCT*>(lParam)->dwData == CD_MAGIC)
			{
				m_hwndCD = 0;

				ULONG cb = reinterpret_cast<COPYDATASTRUCT*>(lParam)->cbData;
				if (cb && !(cb & 1))
				{
					if (PWSTR psz = (PWSTR)reinterpret_cast<COPYDATASTRUCT*>(lParam)->lpData)
					{
						PWSTR end = (PWSTR)RtlOffsetToPointer(psz, cb - sizeof(WCHAR));
						if (!*end)
						{
							len = (ULONG)wcslen(psz);
							if (len - 1 < MAXSHORT)
							{
								PWSTR name = psz + len + 1;
								if (name < end)
								{
									SetDlgItemTextW(hwnd, IDC_EDIT1, name--);
									SetDlgItemTextW(hwnd, IDC_EDIT2, psz);
									if (*--name == '\\')
									{
										*name = 0;
									}
									
									m_bDirChanged = (RtlComputeCrc32(0, _wcsupr(psz), (ULONG)wcslen(psz)*sizeof(WCHAR)) != m_crc);
									m_hwndCD = (HWND)wParam;

									SetWindowLongPtr(hwnd, DWLP_MSGRESULT, CD_MAGIC);
									return TRUE;
								}
							}
						}
					}
				}
			}
			return 0;

		case WM_COMMAND:
			switch(wParam)
			{
			case MAKEWPARAM(IDC_COMBO2, CBN_SELCHANGE):
				uMsg = ComboBox_GetCurSel((HWND)lParam);
				if (uMsg < _countof(g_Servers))
				{
					if (GetServer() != uMsg)
					{
						EnableWindow(GetDlgItem(hwnd, IDC_CHECK1), !uMsg);
						
						if (uMsg)
						{
							if (m_bAll)
							{
								m_bAll = FALSE;
								SendDlgItemMessageW(hwnd, IDC_CHECK1, BM_SETCHECK, BST_UNCHECKED, 0);
								EnableWindow(GetDlgItem(hwnd, IDC_EDIT1), TRUE);
								EnableWindow(GetDlgItem(hwnd, IDC_BUTTON2), TRUE);
								EnableWindow(GetDlgItem(hwnd, IDC_COMBO1), FALSE);
								EnableWindow(GetDlgItem(hwnd, IDC_BUTTON1), FALSE);
								ToggleSize(hwnd);
							}
						}

						SetServer(uMsg);
						EnableWindow(GetDlgItem(hwnd, IDOK), FALSE);
						if (!m_bTimerActive)
						{
							ActivateTimer(hwnd);
						}
					}
					SetFocus(GetDlgItem(hwnd, IDC_STATIC));
				}
				break;

			case IDC_BUTTON2:
				OnBrowse(hwnd, IDC_EDIT1, _countof(rgSpec), rgSpec);
				break;
			case IDC_BUTTON3:
				OnBrowse(hwnd, IDC_EDIT2, L"Save PDB in this directory:");
				break;

			case IDC_BUTTON1:
				ComboBox_ResetContent(hwnd = GetDlgItem(hwnd, IDC_COMBO1));
				FillCombo(hwnd);
				break;

			case MAKEWPARAM(IDC_CHECK1, BN_CLICKED):
				ToggleSize(hwnd);
				EnableWindow(GetDlgItem(hwnd, IDC_EDIT1), m_bAll);
				EnableWindow(GetDlgItem(hwnd, IDC_BUTTON2), m_bAll);

				if (m_bAll = !m_bAll)
				{
					FillCombo(GetDlgItem(hwnd, IDC_COMBO1));
				}
				else
				{
					ComboBox_ResetContent(GetDlgItem(hwnd, IDC_COMBO1));
				}

				EnableWindow(GetDlgItem(hwnd, IDC_COMBO1), m_bAll);
				EnableWindow(GetDlgItem(hwnd, IDC_BUTTON1), m_bAll);

				break;

			case MAKEWPARAM(IDC_EDIT2, EN_UPDATE):
				m_bDirChanged = TRUE;
				break;

			case IDCANCEL:
				StopAll();
				break;

			case IDOK:
				m_nOk = 0, m_nFail = 0;
				if (m_bDirChanged && !OpenFolder(hwnd, GetDlgItem(hwnd, IDC_EDIT2)))
				{
					return 0;
				}

				Reset();
				StartStop(hwnd, TRUE);

				if (m_bAll)
				{
					HWND hwndCB = GetDlgItem(hwnd, IDC_COMBO1);
					int i = ComboBox_GetCurSel(hwndCB);
					if (0 <= i)
					{
						IncActive();
						m_cbFree = e_LogSize;
						if (EnumData* p = new EnumData)
						{
							p->hwnd = hwnd;
							p->dwProcessId = ComboBox_GetItemData(hwndCB, i);
							if (HANDLE hThread = CreateThread(0, 0, EnumAllDlls, p, 0, 0))
							{
								NtClose(hThread);
							}
							else
							{
								delete p;
								DecActive();
							}
						}
					}
				}
				else
				{
					Single();

					if (len = GetWindowTextLength(hwndCtrl = GetDlgItem(hwnd, IDC_EDIT1)))
					{
						SDP params;
						
						params.type = SDP::e_path;
						params.task = this;
						params.DllFileName = (PWSTR)alloca((len + 1) << 1);
						GetWindowText(hwndCtrl, params.DllFileName, len + 1);
						PostMessage(m_arr[0].hwndProgress, PBM_SETRANGE32, 0, 0);
						PostMessage(m_arr[0].hwndProgress, PBM_SETPOS, 0, 0);
						PWSTR c = wcsrchr(params.DllFileName, '\\');
						SetWindowText(m_arr[0].hwndName, c ? c + 1 : params.DllFileName);
						SetWindowText(m_arr[0].hwndStatus, L"");

						ULONG err;
						if (c = wcschr(params.DllFileName, '*'))
						{
							params.type = SDP::e_sign;
							err = CreateSingleDownloadFromGuid(&params, c);
						}
						else
						{
							err = CreateSingleDownload(&params);
						}

						if (err && (err != ERROR_OBJECT_NAME_EXISTS))
						{
							toCtrl(hwnd, hwndCtrl, err, 0);
						}
					}
					else
					{
						toCtrl(hwndCtrl);
					}
				}

				DecActive();
				break;
			}
			break;
		}
		return 0;
	}

	ULONG CreateSingleDownloadFromGuid(SDP* params, PWSTR c)
	{
		PCWSTR DllFileName = params->DllFileName;

		PWSTR e;

		if (wcsrchr(c + 1, '*'))
		{
			return ERROR_INVALID_PARAMETER;
		}

		*c = 0;

		if (wcslen(++c) <= 32)
		{
			return ERROR_INVALID_PARAMETER;
		}

		params->Age = wcstoul(c += 32, &e, 16);

		if (*e != 0)
		{
			return ERROR_INVALID_PARAMETER;
		}

		int n = RTL_NUMBER_OF(params->Signature.Data4);

		do 
		{
			*c = 0;
			params->Signature.Data4[--n] = (UCHAR)wcstoul(c -= 2, &e, 16);

			if (*e != 0)
			{
				return ERROR_INVALID_PARAMETER;
			}
		} while (n);

		*c = 0;
		params->Signature.Data3 = (USHORT)wcstoul(c -= 4, &e, 16);

		if (*e != 0)
		{
			return ERROR_INVALID_PARAMETER;
		}

		*c = 0;
		params->Signature.Data2 = (USHORT)wcstoul(c -= 4, &e, 16);

		if (*e != 0)
		{
			return ERROR_INVALID_PARAMETER;
		}

		*c = 0;
		params->Signature.Data1 = wcstoul(c -= 8, &e, 16);

		if (*e != 0)
		{
			return ERROR_INVALID_PARAMETER;
		}

		ULONG len = 0;
		PSTR PdbFileName = 0;

		while (len = WideCharToMultiByte(CP_UTF8, 0, DllFileName, MAXDWORD, PdbFileName, len, 0, 0))
		{
			if (PdbFileName)
			{
				params->PdbFileName = PdbFileName;
				return CreateSingleDownload(params);
			}

			PdbFileName = (PSTR)alloca(len);
		}

		return ERROR_INVALID_PARAMETER;
	}

public:
	CDialog(SharedCred* Cred) : ZDllVector(Cred)
	{
	}

	~CDialog()
	{
		if (m_hFont)
		{
			DeleteObject(m_hFont);
		}
		if (m_szLog)
		{
			delete [] m_szLog;
		}

		if (m_hRoot)
		{
			ZwClose(m_hRoot);
		}
	}

	void Run()
	{
		DialogBoxParam((HINSTANCE)&__ImageBase, MAKEINTRESOURCE(IDD_GETPDB_DIALOG), HWND_DESKTOP, StartDlgProc, (LPARAM)this);
	}

	virtual void AddRef()
	{
		InterlockedIncrement(&m_dwRef);
	}

	virtual void Release()
	{
		if (!InterlockedDecrement(&m_dwRef))
		{
			delete this;
		}
	}
};

NTSTATUS AdjustPrivileges()
{
	HANDLE hToken;
	NTSTATUS status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (0 <= status)
	{
		BEGIN_PRIVILEGES(tp, 3)
			LAA(SE_DEBUG_PRIVILEGE),
			LAA(SE_LOAD_DRIVER_PRIVILEGE),
			LAA(SE_MANAGE_VOLUME_PRIVILEGE)
		END_PRIVILEGES	
		status = NtAdjustPrivilegesToken(hToken, FALSE, const_cast<PTOKEN_PRIVILEGES>(&tp), 0, 0, 0);
		NtClose(hToken);
	}
	return status;
}

void InitWow64();

void _ep()
{
#ifndef _WIN64
	PVOID wow;
	if (0 > ZwQueryInformationProcess(NtCurrentProcess(), ProcessWow64Information, &wow, sizeof(wow), 0) || wow)
	{
		MessageBox(0, L"The 32-bit version of this program is not compatible with the 64-bit Windows you're running.", 
			L"Machine Type Mismatch", MB_ICONWARNING);
		return;
	}
#else
	InitWow64();
#endif
	AdjustPrivileges();

	STATIC_UNICODE_STRING(tkn, "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\{FC81D8A3-6002-44bf-931A-352B95C4522F}");

	switch (ZwLoadDriver((PUNICODE_STRING)&tkn))
	{
	case 0:
	case STATUS_IMAGE_ALREADY_LOADED:
		IO_STATUS_BLOCK iosb;
		STATIC_OBJECT_ATTRIBUTES(oa, "\\device\\69766781178D422cA183775611A8EE55");
		NtOpenFile(&g_hDrv, SYNCHRONIZE, &oa, &iosb, FILE_SHARE_VALID_FLAGS, FILE_SYNCHRONOUS_IO_NONALERT);
		break;
	}

	if (0 <= CoInitializeEx(0, COINIT_APARTMENTTHREADED|COINIT_DISABLE_OLE1DDE))
	{
		WSADATA wd;
		if (!WSAStartup(WINSOCK_VERSION, &wd))
		{
			if (SharedCred* Cred = new SharedCred)
			{
				if (0 <= Cred->Acquire(SECPKG_CRED_OUTBOUND, 0, SCH_CRED_NO_DEFAULT_CREDS|SCH_CRED_MANUAL_CRED_VALIDATION))
				{
					if (CDialog* dlg = new CDialog(Cred))
					{
						dlg->Run();
						dlg->Release();
					}
				}
				Cred->Release();
			}

			WSACleanup();
		}
		CoUninitialize();
	}
}

void IO_RUNDOWN::RundownCompleted()
{
	destroyterm();
	ExitProcess(0);
}

//////////////////////////////////////////////////////////////////////////
void ep(void*)
{
	initterm();

	_ep();

	IO_RUNDOWN::g_IoRundown.BeginRundown();
}

_NT_END