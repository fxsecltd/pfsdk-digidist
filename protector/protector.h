#include <stdio.h>
#include <windows.h>
#include <shlwapi.h>
#include <imagehlp.h>
#include "udis86\\extern.h"
#include "udis86\\opcmap.h"
#include "rsaref\\global.h"
#include "rsaref\\rsaref.h"
#include "rsaref\\r_random.h"
#include "rsaref\\rsa.h"
#define API_BY_VALUE		 -9
#define API_BY_REFERENCE	 -10
#define VALUED 0x4000
#define WILDCARD 0x8000

typedef unsigned __int64 QWORD,*PQWORD;

typedef struct _sign_cache
{

	//Doublelinked list entry

	LIST_ENTRY n;

	//Name of described packer

	BYTE *name;

	//Type of described packer (packer, protector, compiler)

	ULONG type;

	//Pointer to cached signature data

	BYTE *sign;

	//Signature length (including wildcards)

	ULONG slen;
}sign_cache,*psc;



//some inline stuff for handling doublelinked list
#ifndef LIST_API
#define LIST_API
InitializeListHead(PLIST_ENTRY ListHead)
{
	ListHead->Flink=ListHead->Blink=ListHead;
}

BOOLEAN IsListEmpty(PLIST_ENTRY ListHead)
{
	return ListHead->Flink == ListHead && ListHead->Blink == ListHead;
}

PLIST_ENTRY RemoveHeadList(PLIST_ENTRY ListHead)
{
	PLIST_ENTRY Head=ListHead->Flink;
	PLIST_ENTRY Fwd=Head->Flink;
	PLIST_ENTRY Bwd=Head->Blink;
	Fwd->Blink=Bwd;
	Bwd->Flink=Fwd;
	return Head;
}

PLIST_ENTRY RemoveTailList(PLIST_ENTRY ListHead)
{
	PLIST_ENTRY Tail=ListHead->Blink;
	PLIST_ENTRY Fwd=Tail->Flink;
	PLIST_ENTRY Bwd=Tail->Blink;
	Fwd->Blink=Bwd;
	Bwd->Flink=Fwd;
	return Tail;
}

PLIST_ENTRY GetHeadList(PLIST_ENTRY ListHead)
{
	return ListHead->Flink;
}

PLIST_ENTRY GetTailList(PLIST_ENTRY ListHead)
{
	return ListHead->Blink;
}


VOID InsertTailList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry)
{
    PLIST_ENTRY _EX_Blink;
    PLIST_ENTRY _EX_ListHead;
    _EX_ListHead = ListHead;
    _EX_Blink = _EX_ListHead->Blink;
    Entry->Flink = _EX_ListHead;
    Entry->Blink = _EX_Blink;
    _EX_Blink->Flink = Entry;
    _EX_ListHead->Blink = Entry;
}

VOID InsertHeadList(PLIST_ENTRY ListHead, PLIST_ENTRY Entry)
{
    PLIST_ENTRY _EX_Flink;
    PLIST_ENTRY _EX_ListHead;
    _EX_ListHead = ListHead;
    _EX_Flink = _EX_ListHead->Flink;
    Entry->Flink = _EX_Flink;
    Entry->Blink = _EX_ListHead;
    _EX_Flink->Blink = Entry;
    _EX_ListHead->Flink = Entry;
}
#endif //ifndef LIST_API

typedef struct _api_data
{
	LIST_ENTRY nxt;
	char *libname;
	int dll_hash;
	int api_hash;
	void *iofs;
}api_data;

typedef struct _api_list
{
	char *libname;
	int dll_hash;
	int api_hash;
	void *iofs;
}api_list;

typedef struct api_nest
{
	int		totala;
	int		cursor;
	api_list  *api;
}api_nest;

typedef struct _switch_stains
{
	int count;
	int total;
	char **stp;
	int *stsz;
}switch_stains;


void MemoryMover(unsigned char **binBuffer, unsigned int *binPoint, unsigned int *binTotal, unsigned char *cursor, unsigned int size);
ULONG_PTR ScanForApiCall32(char *exeMem, size_t fSize, char *dllName, BOOL bIAT);
ULONG_PTR ScanForApiCall64(char *exeMem, size_t fSize, char *dllName, BOOL bIAT);
sign_cache *InitializePackerDetection(LPCSTR path, ULONG *TotalSigns);
BYTE *ScanForPacker(psc sc,BYTE *BaseAddr, BYTE *EP,size_t fSize, ULONG TotalSignsCount);
BOOL IsPacked (char *pStreamData, UINT64 u64StreamSize);
DWORD Rva2Raw(short NumOfSections, IMAGE_SECTION_HEADER* FSH, int rva);
DWORD Raw2Rva(short NumOfSections, IMAGE_SECTION_HEADER* FSH, int rva);
BOOL CheckImage(char *BaseAddr, UINT64 fSize, void *AvSelLpVirusId, LPWSTR FileName);
int __cdecl compareApi(void *elem1, void *elem2);
int __cdecl compareApi2(void *elem1, void *elem2);
void InitRandomStruct(R_RANDOM_STRUCT *randomStruct);
DWORD CalcHash(char *str);
api_nest anest;
api_list alist;
psc	   packdetect;
ULONG  TotalSigns;	
