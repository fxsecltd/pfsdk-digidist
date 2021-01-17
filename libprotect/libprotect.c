// libprotect.c: определяет экспортированные функции для приложения DLL.
//
#include "libprotect.h"
//#define HOOK_CREATEFILEA
//#define HOOK_CREATEFILEW
//#define HOOK_CLOSEHANDLE
//#define HOOK_WRITEFILE
//#define HOOK_READFILE

#ifdef HOOK_CREATEFILEA
HANDLE __stdcall myCreateFileA(LPCSTR lpFileName,DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
#endif

#ifdef HOOK_CREATEFILEW
HANDLE __stdcall myCreateFileW(LPCWSTR lpFileName,DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
#endif

#ifdef HOOK_CLOSEHANDLE
BOOL __stdcall myCloseHandle(HANDLE hHandle);
#endif

#ifdef HOOK_WRITEFILE
BOOL __stdcall myWriteFile(HANDLE hFile,LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
#endif

#ifdef HOOK_READFILE
BOOL __stdcall myReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
#endif


ULONG_PTR ImageBase, hImage, CodeBase;
HINSTANCE gInst;
int pageTableCursor=0,tid;
ULONG_PTR *pageTable;
size_t ImageSize;
int *pageAccessTable;
int pageTableSize;
int TimerStarted;
int EraserStarted=0;
int thrTotal=1024,thrCount=0,insCount=0,Opaque=0;
HANDLE hSyncEvent,hPipe;
unsigned __int64 *ins=NULL;
char *seckey=NULL,*seciv=NULL;
ULONG_PTR cImage;
DWORD *threads;
HANDLE hMutex;
int First=1;
///////////////////////////////////////////////////////////////////////////////////////
BOOL __stdcall DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	DWORD tId;
	int i,k;
	switch (ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
			gInst = hModule;
			hMutex = CreateMutex(NULL,FALSE,NULL);
			threads = (DWORD *)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(HANDLE) * 1024);
			threads[thrCount++]=GetCurrentThreadId();
			break;
		case DLL_THREAD_ATTACH:
			WaitForSingleObject(hMutex,INFINITE);
			if(thrCount == thrTotal)
			{
				DWORD *tmp, *temp = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,thrTotal * 2 * sizeof(HANDLE));
				memmove(temp,threads,thrTotal * sizeof(HANDLE));
				tmp = threads;
				threads = temp;
				HeapFree(GetProcessHeap(),0,tmp);
				thrTotal *= 2;
			}
			threads[thrCount++]=GetCurrentThreadId();
			ReleaseMutex(hMutex);
			break;
		case DLL_THREAD_DETACH:
			WaitForSingleObject(hMutex,INFINITE);
			tId = GetCurrentThreadId();
			for(i=0;i<thrCount;i++)
			{
				if(threads[i] == tId)
				{
					for(k=i;k<thrCount;k++)
					{
						threads[k]=threads[k+1];
					}
					threads[thrCount--]=0;
				}
			}
			ReleaseMutex(hMutex);
			break;
		case DLL_PROCESS_DETACH:
			HeapFree(GetProcessHeap(),0,threads);
			CloseHandle(hMutex);
			break;
	}
	return TRUE;
}
///////////////////////////////////////////////////////////////////////////////////////
int SendRequestAndWaitReply(char *request, int requestLength, char **reply, int *replylength, HANDLE hPipe)
{
	R_RSA_PUBLIC_KEY *PUBLIC_KEY = GetKeyFromResource();
	int keyLen, partInReady = 0, len, keys, fConnected=1;
	char *encrypted, key[24], iv[8], *buffer;
	R_RANDOM_STRUCT randomStruct;
	R_ENVELOPE_CTX context;
	char *temp;
	int err,n;
	InitRandomStruct (&randomStruct);
    context.encryptionAlgorithm = EA_DES_EDE3_CBC;
    keyLen = 24;
	len = (keyLen + sizeof(iv) + requestLength);
	R_GenerateBytes (key, keyLen, &randomStruct);
	R_GenerateBytes (iv, 8, &randomStruct);
	CipherInit(&context, EA_DES_EDE3_CBC, key, iv, 0);
	buffer = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,len);
	keys = PUBLIC_KEY->bits/8;
	encrypted = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,keys);
	memmove(buffer,key,keyLen);
	memmove(buffer + keyLen,iv,sizeof(iv));
	memmove(buffer + keyLen + sizeof(iv),request,len - (keyLen + 8));
	err = RSAPublicEncrypt(encrypted, &keys, buffer, len, PUBLIC_KEY, &randomStruct);
	WriteFile(hPipe,&keys,sizeof(keys),&n,NULL);
	WriteFile(hPipe,encrypted,keys,&n,NULL);
	HeapFree(GetProcessHeap(),0,buffer);
	HeapFree(GetProcessHeap(),0,encrypted);
	HeapFree(GetProcessHeap(),0,PUBLIC_KEY);
	if(ReadFile(hPipe,&keys,sizeof(keys),&n,NULL))
	{
		temp = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,keys);
		if(ReadFile(hPipe,temp,keys,&n,NULL))
		{
			*reply = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,keys);
			*replylength = keys;
			CipherUpdate(&context,*reply,temp,keys);
			HeapFree(GetProcessHeap(),0,temp);
		}else
		{
			HeapFree(GetProcessHeap(),0,temp);
			return -2;
		}

	}else
	{
		return -1;
	}
	return 0;
}
///////////////////////////////////////////////////////////////////////////////////////
void *GetKeyFromResource()
{
	HGLOBAL aResourceHGlobal;
	HRSRC aResourceH;
	void *keys, *res;
	int fSize;
	aResourceH = FindResourceW(gInst, (LPCWSTR)4321, (LPCWSTR)1234);
	if(!aResourceH)return NULL;
	aResourceHGlobal = LoadResource(gInst, aResourceH);
	if(!aResourceHGlobal)return NULL;
	fSize = SizeofResource(gInst, aResourceH);
	keys = (unsigned char *)LockResource(aResourceHGlobal);
	if(!keys)return NULL;
	res = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,fSize);
	memmove(res,keys,fSize);
	UnlockResource(keys);
	FreeResource(keys);
	return res;
}
///////////////////////////////////////////////////////////////////////////////////////
void InitRandomStruct (randomStruct)
R_RANDOM_STRUCT *randomStruct;
{
  static unsigned int seedDword = 0;
  unsigned int bytesNeeded;
  seedDword = (unsigned int)__rdtsc();
  R_RandomInit (randomStruct);
  
  /* Initialize with all zero seed bytes, which will not yield an actual
       random number output.
   */
  while (1) {
    R_GetRandomBytesNeeded (&bytesNeeded, randomStruct);
    if (bytesNeeded == 0)
      break;
    
    R_RandomUpdate (randomStruct, (unsigned char *)&seedDword, 4);
  }
}
///////////////////////////////////////////////////////////////////////////////////////
LONG __stdcall NoAccessHandler(PEXCEPTION_POINTERS pExPtrs)
{
	unsigned __int64 tst;
	R_ENVELOPE_CTX ctx;
	ULONG_PTR ofs;
	DWORD tId,old;
	size_t delta;
	char opcode;
	HANDLE thr;
	int i;
	if((char *)pExPtrs->ExceptionRecord->ExceptionInformation[1] >= (char *)CodeBase)
	{
		if((char *)pExPtrs->ExceptionRecord->ExceptionInformation[1] < (char *)CodeBase + ImageSize)
		{
			if(pExPtrs->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION)
			{
				WaitForSingleObject(hMutex,INFINITE);
				tId = GetCurrentThreadId();
				for(i=0;i<thrCount;i++)
				{
					if(threads[i]!=tId)
					{
						thr = OpenThread(THREAD_SUSPEND_RESUME,FALSE,threads[i]);
						SuspendThread(thr);
						CloseHandle(thr);
					}
				}
				delta = (char *)pExPtrs->ExceptionRecord->ExceptionInformation[1] - (char *)CodeBase;
				delta >>= 12;
				delta <<= 12;
				VirtualProtect(&((char *)CodeBase)[delta],0x1000,PAGE_EXECUTE_READWRITE,&old);
				if(((char *)CodeBase)[delta] == ((char *)cImage)[delta])
				{
					memset(&ctx,0,sizeof(ctx));
					ctx.encryptionAlgorithm = EA_DES_CBC;
					CipherInit(&ctx, EA_DES_CBC, seckey, seciv, 0);
					CipherUpdate(&ctx,&((char *)CodeBase)[delta],&((char *)cImage)[delta],0x1000);
					for(i=0;i<insCount;i++)
					{
						tst = ins[i];
						opcode = (char)(tst >> 56);
						tst &= 0xFFFFFFFFFFFFFF;
						ofs = (ULONG_PTR)tst;
						if((char *)ofs >= &((char *)CodeBase)[delta] && (char *)ofs < &((char *)CodeBase)[delta] + 0x1000)
						{
							if(opcode & 0x80)//push reg pop reg
							{
								((char *)ofs)[0] = 0x50 | opcode & 0x07;
								((char *)ofs)[1] = 0x58 | (opcode >> 3) & 0x07;
							}else//mov reg32/64,reg32/64
							{
								if(sizeof(ULONG_PTR)==8)
								{
									((char *)ofs)[0] = 0x48;
									((char *)ofs)[1] = 0x8B;
									((char *)ofs)[2] = 0xC0 | opcode & 0x3F;
								}else
								{
									((char *)ofs)[0] = 0x8B;
									((char *)ofs)[1] = 0xC0 | opcode & 0x3F;
								}
							}
						}
					}
					VirtualProtect(&((char *)CodeBase)[delta],0x1000,PAGE_EXECUTE_READ,&old);
				}
				for(i=0;i<thrCount;i++)
				{
					if(threads[i]!=tId)
					{
						thr = OpenThread(THREAD_SUSPEND_RESUME,FALSE,threads[i]);
						ResumeThread(thr);
						CloseHandle(thr);
					}
				}
				ReleaseMutex(hMutex);
				if((pExPtrs->ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE))
				pExPtrs->ExceptionRecord->ExceptionFlags ^= EXCEPTION_NONCONTINUABLE;
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD __stdcall Timer(void *lpParam)
{
	int MemPurgeCounter=0,old,i;
	HANDLE thr;
	hSyncEvent = CreateEvent(NULL,TRUE,FALSE,NULL);
	if(seckey)
	{
		while(WaitForSingleObject(hSyncEvent,5000)==WAIT_TIMEOUT)
		{
			MemPurgeCounter++;
			if(!(MemPurgeCounter%3))
			{
				DWORD tId = GetCurrentThreadId();
				WaitForSingleObject(hMutex,INFINITE);
				for(i=0;i<thrCount;i++)
				{
					if(threads[i]!=tId)
					{
						thr = OpenThread(THREAD_SUSPEND_RESUME,FALSE,threads[i]);
						SuspendThread(thr);
						CloseHandle(thr);
					}
				}
				VirtualProtect((void *)CodeBase,ImageSize,PAGE_READWRITE,&old);
				memmove((void *)CodeBase,(void *)cImage,ImageSize);
				VirtualProtect((void *)CodeBase,ImageSize,PAGE_NOACCESS,&old);
				for(i=0;i<thrCount;i++)
				{
					if(threads[i]!=tId)
					{
						thr = OpenThread(THREAD_SUSPEND_RESUME,FALSE,threads[i]);
						ResumeThread(thr);
						CloseHandle(thr);
					}
				}
				ReleaseMutex(hMutex);
			}
		}
	}
	return 0;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD CalcHash(char *str)
{
	DWORD res = 0;
	char* dup = str;
	while(*dup) 
	{
		res = ((res << 7) & (DWORD)(-1))|(res >> (32-7));
		res = res^(*dup);
		dup++;
	}
	return res & 0x7FFFFFFF;
}
///////////////////////////////////////////////////////////////////////////////////////
LPVOID GetProcAddressEx(HMODULE hModule, DWORD dwApiHash, int *dwType)
{
	WORD *pwOrdinalPtr;
	DWORD *pdwNamePtr;
	DWORD *pAddrTable;
	size_t nOrdinal,i,k,n;
	void *ret;
	#ifndef WIN64
		PIMAGE_NT_HEADERS32 inh = (PIMAGE_NT_HEADERS32)((char*)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
	#else  
		PIMAGE_NT_HEADERS64 inh = (PIMAGE_NT_HEADERS64)((char*)hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew);
	#endif
	IMAGE_SECTION_HEADER* ish = IMAGE_FIRST_SECTION(inh);
	PIMAGE_EXPORT_DIRECTORY ied = (IMAGE_EXPORT_DIRECTORY*)RVATOVA(hModule, inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress); 
	char *dwRva,*dwEatStart = (char *)inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	char *dwEatEnd = dwEatStart + inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	char *dwDataStart = (char *)(inh->OptionalHeader.BaseOfCode + inh->OptionalHeader.SizeOfCode + (char *)hModule);
	char *dwDataEnd = dwDataStart + inh->OptionalHeader.SizeOfInitializedData + inh->OptionalHeader.SizeOfUninitializedData;

	if (HIWORD((DWORD)dwApiHash) == 0) 
	{
		nOrdinal = (LOWORD((DWORD)dwApiHash)) - ied->Base;
	} else 
	{
		pdwNamePtr = (DWORD*)RVATOVA(hModule, ied->AddressOfNames);
		pwOrdinalPtr = (WORD*)RVATOVA(hModule, ied->AddressOfNameOrdinals);
		for (i = 0; i < ied->NumberOfNames; i++, pdwNamePtr++, pwOrdinalPtr++)
		{
			if (CalcHash((char*)RVATOVA(hModule, *pdwNamePtr)) == dwApiHash)
			{
				nOrdinal = *pwOrdinalPtr;
				break;
			}
		}
		if (i == ied->NumberOfNames)return 0;
	}

	pAddrTable = (PDWORD)RVATOVA(hModule, ied->AddressOfFunctions);
	dwRva = (char *)pAddrTable[nOrdinal];
	if(dwRva >= dwEatStart && dwRva < dwEatEnd)
	{
		char *lpFwd = (char *)RVATOVA(hModule, dwRva);
		size_t dwFwdLen = strlen(lpFwd);
		char NameFwdBuff[256];
		char DllFwdBuff[256];
		ZeroMemory(NameFwdBuff,sizeof(NameFwdBuff));
		ZeroMemory(DllFwdBuff,sizeof(DllFwdBuff));
		for(i=n=k=0;i<dwFwdLen;i++)
		{
			if(lpFwd[i]=='.')
			{
				k++;
				n=0;
			}else if(k)
			{
				NameFwdBuff[n++]=lpFwd[i];
			}else
			{
				DllFwdBuff[n++]=lpFwd[i];
			}
		}
		ret = GetProcAddressEx(GetModuleHandleExt(DllFwdBuff,0,1),CalcHash(NameFwdBuff),dwType);
		if((char *)ret >= dwDataStart && (char *)ret < dwDataEnd)*dwType=1;
		return ret;
	}else
	{
		ret = (void *)RVATOVA(hModule, dwRva);
		if((char *)ret >= dwDataStart && (char *)ret < dwDataEnd)*dwType=1;
		return ret;
	}
}
///////////////////////////////////////////////////////////////////////////////////////
HMODULE GetModuleHandleExt( LPCSTR ModuleName, int ModuleHash, int Load )
{
	PLIST_ENTRY pebModuleHeader, ModuleLoop;
	LDR *Module;
	PPEB_LDR_DATA pebModuleLdr;
	DWORD BadModuleCount = 0,type;
	WCHAR ModuleUnicodeName[1024];

	if(Load)
	{
		if(!hLL)
		{
			HMODULE kernel32 = GetModuleHandleExt(0,CalcHash("kernel32.dll"),FALSE);
			hLL = GetProcAddressEx(kernel32,CalcHash("LoadLibraryA"),&type);
		}
		return hLL(ModuleName);
	}

	#ifndef WIN64
		pebModuleLdr = ( PPEB_LDR_DATA ) *( ( ULONG_PTR * ) __readfsdword( 0x30 ) + 12 / sizeof( ULONG_PTR ) );
	#else
		pebModuleLdr = ( PPEB_LDR_DATA ) *( ( ULONG_PTR * ) __readgsqword( 0x60 ) + 24 / sizeof( ULONG_PTR ) );
	#endif

	pebModuleHeader = ( PLIST_ENTRY ) &pebModuleLdr->InLoadOrderModuleList;

	Module = ( LDR * ) pebModuleHeader->Flink;
	ModuleLoop = pebModuleHeader->Flink;

	if(ModuleName)
	{
		int k,m = strlen(ModuleName);
		memset(&ModuleUnicodeName,0,sizeof(ModuleUnicodeName));
		for(k=0;k<m;k++)((WCHAR *)ModuleUnicodeName)[k] = (WCHAR)((char *)ModuleName)[k];
		while( pebModuleHeader != ModuleLoop->Flink)
		{
			if( !wcscmp( ModuleUnicodeName, Module->BaseDllName.Buffer ) )return ( HMODULE ) Module->BaseAddress;
			Module = ( LDR * ) ModuleLoop->Flink;
			ModuleLoop = ModuleLoop->Flink;
		}
	}else
	{
		char namebuff[1024];
		while( pebModuleHeader != ModuleLoop->Flink )
		{
			int k,m = Module->BaseDllName.Length / sizeof(WCHAR);
			memset(&namebuff,0,sizeof(namebuff));
			for(k=0;k<m;k++)((char *)namebuff)[k] = (char)((WCHAR *)Module->BaseDllName.Buffer)[k];
			if (CalcHash(_strlwr(namebuff)) == ModuleHash)return ( HMODULE ) Module->BaseAddress;
			Module = ( LDR * ) ModuleLoop->Flink;
			ModuleLoop = ModuleLoop->Flink;
		}
	}
	return 0;
}
///////////////////////////////////////////////////////////////////////////////////////
void initialize()
{
	ULONG_PTR *ofret = _AddressOfReturnAddress();
	DWORD backup;
	size_t corrector = 0;
	corrector = 0x12345678;
	hImage = *ofret - corrector;
	backup = (int)_AddressOfReturnAddress() - (int)hImage;
	//if(!hImage)hImage = (ULONG_PTR)GetModuleHandle(NULL);
#ifdef _DEBUG
	Sleep(30000);
#endif
	if(!TimerStarted++)
	{
		IMAGE_NT_HEADERS* inh = (IMAGE_NT_HEADERS*)(hImage + ((IMAGE_DOS_HEADER*)hImage)->e_lfanew);
		IMAGE_NT_HEADERS64* inh2 = (IMAGE_NT_HEADERS64*)(hImage + ((IMAGE_DOS_HEADER*)hImage)->e_lfanew);
		IMAGE_SECTION_HEADER* ish = (IMAGE_SECTION_HEADER*)(hImage + ((IMAGE_DOS_HEADER*)hImage)->e_lfanew + inh->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4);
		size_t scnt,ISAMD64 = inh->FileHeader.Machine == 0x8664 ? 1 : 0;
		int i,old,replylen, apicount,liblen,libhash,apihash,type,profiler=0;
		ULONG_PTR iofs=0,lib=0,api=0,tofs=0;
		if(ISAMD64)scnt = (size_t)inh2->FileHeader.NumberOfSections;
		else scnt = (size_t)inh->FileHeader.NumberOfSections;
		ImageBase = (ULONG_PTR)hImage;
		for(i=0;i<inh->FileHeader.NumberOfSections;i++)
		{
			if(!strcmpi(ish[i].Name,".rdata"))
			{
				int old;
				VirtualProtect(&ish[i].Characteristics,4,PAGE_READWRITE,&old);
				ish[i].Characteristics &= ~IMAGE_SCN_MEM_WRITE;
				VirtualProtect(&ish[i].Characteristics,4,old,&old);
			}
		}
		hPipe = CreateFile(L"\\\\.\\\\pipe\\TESTPIPENAMETESTPIPENAMETESTPIPENAMETESTPIPENAMETESTPIPENAME",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
		if(hPipe != INVALID_HANDLE_VALUE)
		{
			char *wrap,*libname, *reply,*rq = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,16);
			int replycursor=0;
			__cpuid((int *)rq,0);
			((int *)rq)[0] = GetCurrentPid();
			replycursor = 0;
			if(!SendRequestAndWaitReply(rq,16,&reply,&replylen,hPipe))
			{
				while(replycursor < replylen)
				{
					memmove(&apicount,&reply[replycursor],4);
					replycursor += 4;
					if(!apicount)break;//end of API list
					memmove(&liblen,&reply[replycursor],4);
					replycursor += 4;
					memmove(&libhash,&reply[replycursor],4);
					replycursor += 4;
					libname = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,liblen+1);
					memmove(libname,&reply[replycursor],liblen);
					replycursor += liblen;
					if(!(lib=(ULONG_PTR)GetModuleHandleExt(NULL,libhash,FALSE)))
					{
						for(i=0;i<liblen;i++)
						{
							((char *)libname)[i] -= ((char *)&libhash)[i%4];
						}
						lib = (ULONG_PTR)GetModuleHandleExt(libname,0,TRUE);
					}
					if(!lib)exit(-3);
					for(i=0;i<apicount;i++)
					{
						memmove(&apihash,&reply[replycursor],4);
						replycursor += 4;
						memmove(&iofs,&reply[replycursor],4);
						replycursor += 4;
						type = 0;
						api = 0;
						if(apihash & 0x80000000)
						{
							api = (ULONG_PTR)GetProcAddressEx((HMODULE)lib,apihash & 0x7FFFFFFF,&type);
						}else
						{
							api = (ULONG_PTR)GetProcAddressEx((HMODULE)lib,apihash,&type);
						}
						if(!api)exit(-4);
#ifdef HOOK_CREATEFILEA
						if(!(apihash & 0x80000000) && apihash == CalcHash("CreateFileA"))
						{
							api = (ULONG_PTR)myCreateFileA;
						}
#endif
#ifdef HOOK_CREATEFILEW
						if(!(apihash & 0x80000000) && apihash == CalcHash("CreateFileW"))
						{
							api = (ULONG_PTR)myCreateFileW;
						}
#endif
#ifdef HOOK_CLOSEHANDLE
						if(!(apihash & 0x80000000) && apihash == CalcHash("CloseHandle"))
						{
							api = (ULONG_PTR)myCloseHandle;
						}
#endif
#ifdef HOOK_WRITEFILE
						if(!(apihash & 0x80000000) && apihash == CalcHash("WriteFile"))
						{
							api = (ULONG_PTR)myWriteFile;
						}
#endif
#ifdef HOOK_READFILE
						if(!(apihash & 0x80000000) && apihash == CalcHash("ReadFile"))
						{
							api = (ULONG_PTR)myReadFile;
						}
#endif
						if(sizeof(ULONG_PTR)==8)
						{
							if(type)
							{
								memmove(&wrap,&api,sizeof(ULONG_PTR));//imm64
							}else
							{
								wrap = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,12);
								wrap[0] = 0x48;//REX
								wrap[1] = 0xB8;//mov rAX
								memmove(&wrap[2],&api,sizeof(ULONG_PTR));//imm64
								wrap[sizeof(ULONG_PTR)+2] = 0xFF;//
								wrap[sizeof(ULONG_PTR)+3] = 0xE0;//jmp eax
								VirtualProtect(wrap,12,PAGE_EXECUTE_READWRITE,&old);
							}
						}else
						{
							if(type)
							{
								memmove(&wrap,&api,sizeof(ULONG_PTR));//imm32
							}else
							{
								wrap = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,7);
								wrap[0] = 0xB8;//mov eAX
								memmove(&wrap[1],&api,sizeof(ULONG_PTR));//imm32/64
								wrap[sizeof(ULONG_PTR)+1] = 0xFF;//
								wrap[sizeof(ULONG_PTR)+2] = 0xE0;//jmp eax
								VirtualProtect(wrap,7,PAGE_EXECUTE_READWRITE,&old);
							}
						}
						tofs = (ULONG_PTR)((char *)ImageBase + (size_t)iofs);
						VirtualProtect((LPVOID)tofs,sizeof(ULONG_PTR),PAGE_READWRITE,&old);
						memmove((LPVOID)tofs,&wrap,sizeof(ULONG_PTR));
						VirtualProtect((LPVOID)tofs,sizeof(ULONG_PTR),old,&old);
					}
					HeapFree(GetProcessHeap(),0,libname);
				}
				//handling watermarks
				memmove(&apicount,&reply[replycursor],sizeof(int));
				replycursor += 4;
				if(apicount)//if watermarking was enable by protector
				{
					ins = (unsigned __int64 *)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,apicount*sizeof(unsigned __int64));
					insCount = apicount;
					memmove(ins,&reply[replycursor],apicount*sizeof(unsigned __int64));
					replycursor += apicount*sizeof(unsigned __int64);
				}
				memmove(&apicount,&reply[replycursor],sizeof(int));
				replycursor += 4;
				if(!apicount)//if page protection was enabled by protector
				{
					seckey = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,8);
					seciv = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,8);
					memmove(seckey,&reply[replycursor],8);
					replycursor += 8;
					memmove(seciv,&reply[replycursor],8);
					replycursor += 8;
					for(i=0;i<8;i++)seciv[i] ^= ((char *)rq)[i%8];
					for(i=0;i<8;i++)seckey[i] ^= ((char *)rq)[i%8+8];
					for(i=0;i<8;i++)seciv[i] ^= ((char *)rq)[i%8+8];
					for(i=0;i<8;i++)seckey[i] ^= ((char *)rq)[i%8];
				}
			}else exit(-1);
		}else exit(-2);
		if(ISAMD64)
		{
			ImageSize = (ish[0].SizeOfRawData >> 12) << 12;
			CodeBase = (ULONG_PTR)((ULONGLONG)ish[0].VirtualAddress + inh2->OptionalHeader.ImageBase);
		}else
		{
			ImageSize = (ish[0].SizeOfRawData >> 12) << 12;
			CodeBase = ish[0].VirtualAddress + inh->OptionalHeader.ImageBase;
		}	
		if(seckey)
		{
			//SetUnhandledExceptionFilter(NoAccessHandler);
			AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)NoAccessHandler);
			cImage = (ULONG_PTR)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,ImageSize);
			memmove((void *)cImage,(void *)CodeBase,ImageSize);
			VirtualProtect((LPVOID)CodeBase,ImageSize,PAGE_NOACCESS,&old);
		}else
		{
			if(ins)
			{
				VirtualProtect((void *)CodeBase,ImageSize,PAGE_EXECUTE_READWRITE,&old);
				for(i=0;i<insCount;i++)
				{
					unsigned __int64 tst = ins[i];
					char opcode = (char)(tst >> 56);
					ULONG_PTR ofs = (ULONG_PTR)(tst & 0xFFFFFFFFFFFFFF);
					if((char *)ofs >= (char *)CodeBase && (char *)ofs < (char *)CodeBase + ImageSize)
					{
						if(opcode & 0x80)//push reg pop reg
						{
							((char *)ofs)[0] = 0x50 | opcode & 0x07;
							((char *)ofs)[1] = 0x58 | (opcode >> 3) & 0x07;
						}else//mov reg32/64,reg32/64
						{
							if(sizeof(ULONG_PTR) == 8)
							{
								((char *)ofs)[0] = 0x48;
								((char *)ofs)[1] = 0x8B;
								((char *)ofs)[2] = 0xC0 | opcode & 0x3F;
							}else
							{
								((char *)ofs)[0] = 0x8B;
								((char *)ofs)[1] = 0xC0 | opcode & 0x3F;
							}
						}
					}
				}
				VirtualProtect((void *)CodeBase,ImageSize,PAGE_EXECUTE_READ,&old);
			}
		
		}
		CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)&Timer,NULL,0,&tid);
	}
}
////////////////////////////////////////////////////////////////////////////////////////
DWORD GetCurrentPid()
{
#ifndef WIN64
	return (DWORD)*( ( ULONG_PTR * ) __readfsdword( 0x18 ) + 0x20 / sizeof( ULONG_PTR ) );
#else
	return (DWORD)*( ( ULONG_PTR * ) __readgsqword( 0x30 ) + 0x40 / sizeof( ULONG_PTR ) );
#endif
}
////////////////////////////////////////////////////////////////////////////////////////
#ifdef HOOK_CREATEFILEA
HANDLE __stdcall myCreateFileA(LPCSTR lpFileName,DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	return CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}
#endif

#ifdef HOOK_CREATEFILEW
HANDLE __stdcall myCreateFileW(LPCWSTR lpFileName,DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	return CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}
#endif

#ifdef HOOK_CLOSEHANDLE
BOOL __stdcall myCloseHandle(HANDLE hHandle)
{
	return CloseHandle(hHandle);
}
#endif

#ifdef HOOK_WRITEFILE
BOOL __stdcall myWriteFile(HANDLE hFile,LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
	return WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}
#endif

#ifdef HOOK_READFILE
BOOL __stdcall myReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
	return ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}
#endif

