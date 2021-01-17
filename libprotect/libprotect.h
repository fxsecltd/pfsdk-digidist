#include <stdio.h>
#include <windows.h>
#include <intrin.h>
//#include <string.h>
#include <imagehlp.h>
#include "rsaref\\global.h"
#include "rsaref\\rsaref.h"
#include "rsaref\\r_random.h"
#include "rsaref\\rsa.h"
#pragma warning(disable:4996)
#define RVATOVA( base, offset ) ( (ULONG_PTR)base + (ULONG_PTR)offset )

typedef struct _LSA_UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
}UNICODE_STRING, *PUNICODE_STRING;


typedef struct _PEB_LDR_DATA
{
	ULONG      Length;
	BOOLEAN    Initialized;
	PVOID      SsHandle;
	LIST_ENTRY InLoadOrderModuleList;          
	LIST_ENTRY InMemoryOrderModuleList;        
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_MODULE
{
	LIST_ENTRY		InLoadOrderModuleList;          
	LIST_ENTRY		InMemoryOrderModuleList;        
	LIST_ENTRY		InInitializationOrderModuleList;
	PVOID			BaseAddress;
	PVOID			EntryPoint;
	size_t			SizeOfImage;
	UNICODE_STRING	FullDllName;
	UNICODE_STRING	BaseDllName;
	ULONG			Flags;
	SHORT			LoadCount;
	SHORT			TlsIndex;
	LIST_ENTRY		HashTableEntry;
	ULONG			TimeDateStamp;
} LDR;
HMODULE GetModuleHandleExt( LPCSTR ModuleName, int ModuleHash, int Load );
LPVOID GetProcAddressEx(HMODULE hModule, DWORD dwApiHash, int *dwType);
DWORD CalcHash(char *str);
DWORD __stdcall Timer(void *lpParam);
LONG __stdcall NoAccessHandler(PEXCEPTION_POINTERS pExPtrs);
int FindInTree(ULONG_PTR key);
int Compare(const ULONG_PTR a,const ULONG_PTR b);
void InitRandomStruct (randomStruct);
void *GetKeyFromResource();
int SendRequestAndWaitReply(char *request, int requestLength, char **reply, int *replylength, HANDLE hPipe);
BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved);
void initialize();
DWORD GetCurrentPid();
typedef HMODULE (__stdcall* ptLoadLibrary)(LPCSTR LibraryName);
ptLoadLibrary hLL;