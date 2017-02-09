#include "Headers.h"

cFunctionGuard::cFunctionGuard()
{

}

cFunctionGuard::~cFunctionGuard()
{
}

// Encrypts caller, decrypts callee with caller hash
//========================================================================
void cFunctionGuard::FunctionGuard(LPVOID lpCalleeBaseAddr, LPVOID lpCallerBaseAddr)
{
	DWORD dwHashLen, dwFunctionSize = cFunctionGuard::GetFunctionSize(lpCalleeBaseAddr), dwOldProtection = 0;
	PBYTE pbKey = cFunctionGuard::HashFunction(lpCallerBaseAddr, GetFunctionSize(lpCallerBaseAddr), &dwHashLen);

	//Allow Read, Write
	VirtualProtect(lpCalleeBaseAddr, dwFunctionSize, PAGE_EXECUTE_READWRITE, &dwOldProtection);

	//Write Encrypted/Decrypted Data
	for (DWORD dw = 0, dwKeylp = 0; dw < dwFunctionSize; dw++, dwKeylp++)
	{
		if (pbKey[dwKeylp] == (byte)'\0')
			dwKeylp = 0;

		*(PBYTE)(reinterpret_cast<DWORD_PTR>(lpCalleeBaseAddr)+dw) = *(PBYTE)(reinterpret_cast<DWORD_PTR>(lpCalleeBaseAddr)+dw) ^ pbKey[dwKeylp];
	}

	//Restore old page protect
	VirtualProtect(lpCalleeBaseAddr, dwFunctionSize, dwOldProtection, &dwOldProtection);

	//Delete other memory 
	delete [] pbKey;
	dwFunctionSize = 0;
	dwOldProtection = 0;
}

// Hashes caller
//========================================================================
PBYTE cFunctionGuard::HashFunction(LPVOID lpCallerBaseAddr, DWORD dwFunctionSize, DWORD *dwHashLen)
{
	HCRYPTHASH hHash;
	HCRYPTPROV hProv;
	DWORD dwHashLenSize = sizeof(DWORD);
	byte *pbOut;

	CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, NULL);

	CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash);

	CryptHashData(hHash, (PBYTE)reinterpret_cast<DWORD_PTR>(lpCallerBaseAddr), sizeof(lpCallerBaseAddr), 0);

	CryptGetHashParam(hHash, HP_HASHSIZE, (PBYTE)*&dwHashLen, &dwHashLenSize, NULL);

	pbOut = new byte[*dwHashLen +1]; // Null Term
	ZeroMemory(pbOut, *dwHashLen +1);
	CryptGetHashParam(hHash, HP_HASHVAL, pbOut, *&dwHashLen, NULL);

	CryptReleaseContext(hProv, NULL);
	CryptDestroyHash(hHash);
	dwHashLenSize = 0;

	return pbOut;
}

// Gets the function size by scanning for 0xCC & 0xC3
//========================================================================
DWORD_PTR cFunctionGuard::GetFunctionSize(LPVOID lpBaseAddr)
{
	//Retn = 0xC3
	//0R Debug = 0xF4

	for(DWORD_PTR dw = 0;; dw++)
		if(*(PBYTE)(reinterpret_cast<DWORD_PTR>(lpBaseAddr) + dw) == 0xC3) // Retn
			if(*(PBYTE)(reinterpret_cast<DWORD_PTR>(lpBaseAddr) + dw + 0x1) == 0xCC) // INT3
				return dw;
	return 0;
}