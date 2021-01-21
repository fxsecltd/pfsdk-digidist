// fingerprinter.c: определяет точку входа для консольного приложения.
//

#include "fingerprinter.h"
#include "rsaref/global.h"
#include "rsaref/rsaref.h"
#include "rsaref/rsa.h"
#include "udis86/extern.h"
#include "udis86/opcmap.h"
#include "../sqlite3static/sqlite3.h"

#pragma warning (disable:4996)
#pragma warning (disable:4090)
#pragma warning (disable:4028)


__cdecl wmain( int argc, wchar_t *argv[ ], wchar_t *envp[ ] )
{
	HANDLE hFile,hMap,hProtect,hPMap;
	char namebuff[MAX_PATH*2];
	__int64 imageBase;
	int found;
    int result = 0;
    sqlite3 *db;
    sqlite3_stmt *statement;
    unsigned char *sql[MAX_PATH];
    if (sqlite3_open(argv[2], &db) != SQLITE_OK)
    {
        printf("Open database failed\n");
        exit(2);
    }
    sprintf(sql,"SELECT FILE FROM ITEMS WHERE NAME='%S'",argv[3])
    if (sqlite3_prepare_v2(db, sql, strlen(sql), &statement, 0) != SQLITE_OK)
    {
        printf("Open database failed\n");
        exit(3);
    }

#if _DEBUG
	LPWSTR param0=L"protector.exe";
	LPWSTR param1=L"..\\winrar.preload.exe";
	LPWSTR param2=L"..\\winrar.bin";
	LPWSTR testCmdLine[]={param0,param1,param2};
	argv = testCmdLine;
	argc=3;
#endif
	if(argc < 3)
	{
		printf("Fingerprinter - watermarking extraction module\n");
		printf("Usage: <fingerprinter.exe> [<preload>] [<prodata>] [<pipename>]\n");
		printf("where:\n");
		printf("<preload> - path to protected file\n");
		printf("<prodata> - path to companion data\n");
		printf("<pipename> - name of pipe within protected software\n");
		exit(0);
	}
	if(!PathFileExistsW(argv[1]))
	{
		memset(&namebuff,0,sizeof(namebuff));
		WideCharToMultiByte(CP_OEMCP,0,(LPCWSTR)argv[1],(int)wcslen((wchar_t *)argv[1]),(LPSTR)&namebuff,sizeof(namebuff),NULL,NULL);
		printf("Protected file's path %s is incorrect\n",&namebuff);
		exit(0);
	}
	printf("Fingerprinter.exe, version 1.0\nProfense SDK project watermarking extraction utility\n===================================================\n");
	hFile = CreateFile(argv[1],GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	if(hFile!=INVALID_HANDLE_VALUE)
	{
		hMap = CreateFileMapping(hFile,NULL,PAGE_READWRITE,0,0,NULL);
		if(hMap!=INVALID_HANDLE_VALUE)
		{
			char *fpdata,*decrypted,*BaseAddr = MapViewOfFile(hMap,FILE_MAP_WRITE,0,0,0);
			size_t fpptr=0,fptotal=1024,apicnt=0,fSize = GetFileSize(hFile,NULL);
			if(BaseAddr)
			{
				int i,k,done=0,cursor=0,total=1024,dbprotect_size,decrlen;
				DWORD currApi=0;
				IMAGE_NT_HEADERS* inh = (IMAGE_NT_HEADERS*)(BaseAddr + ((IMAGE_DOS_HEADER*)BaseAddr)->e_lfanew);
				IMAGE_NT_HEADERS64* inh2 = (IMAGE_NT_HEADERS64*)(BaseAddr + ((IMAGE_DOS_HEADER*)BaseAddr)->e_lfanew);
				IMAGE_SECTION_HEADER* ish = (IMAGE_SECTION_HEADER*)(BaseAddr + ((IMAGE_DOS_HEADER*)BaseAddr)->e_lfanew + inh->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4);
				BOOL ISAMD64 = inh->FileHeader.Machine == 0x8664;
				unsigned __int64 *excluded = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,1024*sizeof(unsigned __int64));
				char *dbprotect, opcode;
				if(ISAMD64)memmove(&imageBase,&inh2->OptionalHeader.ImageBase,sizeof(__int64));
				else memmove(&imageBase,&inh->OptionalHeader.ImageBase,sizeof(int));
				//memset(&namebuff,0,sizeof(namebuff));
				if(sqlite3_step(statement)==SQLITE_ROW)
				{
					DWORD nbr;
					void *lpRes;
					size_t dwRes;
                    int fSize = sqlite3_column_bytes(statement,0);
					lpBin = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,fSize);
					if(lpBin)
					{
                        unsigned char *p = (uchar*)sqlite3_column_blob(statement,0);
                        memmove(lpBin,p,fSize);
                    	sqlite3_reset(statement);
                        dbprotect = lpBin;
                        dbprotect_size = fSize;    
                    }
				}else
				{
					printf("Error opening protection database file %s\n, exit",argv[2]);
					exit(-10);
				}
                if(dbprotect && dbprotect_size)
                {
					R_RSA_PRIVATE_KEY *PRIVATE_KEY = (R_RSA_PRIVATE_KEY *)(dbprotect + dbprotect_size - sizeof(R_RSA_PRIVATE_KEY));
					//R_RSA_PUBLIC_KEY *PUBLIC_KEY = (R_RSA_PUBLIC_KEY *)(dbprotect + dbprotect_size - sizeof(R_RSA_PUBLIC_KEY) - sizeof(R_RSA_PRIVATE_KEY));
					//char *seciv = (char *)(dbprotect + dbprotect_size - sizeof(R_RSA_PUBLIC_KEY) - sizeof(R_RSA_PRIVATE_KEY) - CODE_DES_IV_SIZE);
					//char *seckey = (char *)(dbprotect + dbprotect_size - sizeof(R_RSA_PUBLIC_KEY) - sizeof(R_RSA_PRIVATE_KEY) - CODE_DES_IV_SIZE - CODE_DES_KEY_SIZE);
					int err,entries = *((int *)((char *)(dbprotect + dbprotect_size - sizeof(R_RSA_PUBLIC_KEY) - sizeof(R_RSA_PRIVATE_KEY) - CODE_DES_IV_SIZE - CODE_DES_KEY_SIZE) - NUM_ENTRIES_SIZE));
					unsigned __int64 *entry = (unsigned __int64 *)(dbprotect + dbprotect_size - NUM_ENTRIES_SIZE - sizeof(unsigned __int64) * entries - sizeof(R_RSA_PUBLIC_KEY) - sizeof(R_RSA_PRIVATE_KEY) - CODE_DES_IV_SIZE - CODE_DES_KEY_SIZE);
					struct ud uds;
					int seccnt,len,rawoffset;
					unsigned __int64 offset=0;
					if(ISAMD64)seccnt = inh2->FileHeader.NumberOfSections;
					else seccnt = inh->FileHeader.NumberOfSections;
					for(k=0;k<seccnt;k++)
					{
						if(ish[k].Characteristics & IMAGE_SCN_CNT_CODE && !strcmpi(ish[k].Name,".text"))
						{
							ud_init(&uds);
							ud_set_mode(&uds,ISAMD64?64:32);
							ud_set_input_buffer(&uds,(ULONG)ish[k].PointerToRawData+BaseAddr,min(ish[k].Misc.VirtualSize,ish[k].SizeOfRawData));
							rawoffset = ish[k].PointerToRawData;
							offset = (unsigned __int64)ish[k].VirtualAddress;
							if(ISAMD64)offset += inh2->OptionalHeader.ImageBase;
							else offset += (unsigned __int64)inh->OptionalHeader.ImageBase;
							while(len = ud_disassemble(&uds))
							{
								for(found=i=0;i<entries;i++)
								{
									if(offset == (entry[i] & 0xFFFFFFFFFFFFFF))
									{
										opcode = (char)(entry[i] >> 56);
										found=1;
										break;
									}
								}
								if(found)
								{
									if(uds.operand[0].type == UD_OP_REG && ((!ISAMD64 && uds.operand[0].size == 32) || (ISAMD64 && uds.operand[0].size == 64)))
									{
										if(fpptr/8 == fptotal)
										{
											char *tmp,*temp = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,fptotal * 2);
											memmove(temp,fpdata,fpptr/8);
											tmp = fpdata;
											fpdata = temp;
											HeapFree(GetProcessHeap(),0,tmp);
										}
										if(uds.mnemonic == UD_Ipush)
										{
											if((uds.operand[0].base - UD_R_EAX) == (opcode & 0x07))
											{
												fpdata[fpptr/8] |= 1 << (fpptr++ % 8);
											}
										}else if(uds.mnemonic == UD_Imov)
										{
											if((uds.operand[1].base - UD_R_EAX) == (opcode & 0x07))
											{
												fpptr++;
											}
										}
									}
								}
								rawoffset += len;
								offset += (unsigned __int64)len;
							}
							break;
						}
					}
					decrypted = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,((fpptr / 8) / 128) * 128);
					decrlen = (((int)fpptr / 8) / 128) * 128;
					if(decrypted)
					{
						err = RSAPrivateDecrypt(decrypted, &decrlen, fpdata, decrlen, PRIVATE_KEY);
						if(!err)
						{
							LARGE_INTEGER userid;
							for(i=0;i<decrlen / 128;i++)
							{
								memmove(&userid, &decrypted[i*128], sizeof(userid));
								printf("64bit userid: %ull, 32 bit userid: %u\n",userid.QuadPart,userid.LowPart);
							}
							HeapFree(GetProcessHeap(),0,decrypted);
							HeapFree(GetProcessHeap(),0,fpdata);
							printf("Extraction process finished succesfully, exit\n");
						}else
						{
							printf("Error in decryption of signature data, exit");
							exit(-14);
						}
					}else
					{
						printf("Error out of memory for decrypted signatures, exit");
						exit(-14);
					}
				}
				UnmapViewOfFile(BaseAddr);
				CloseHandle(hMap);
				CloseHandle(hFile);
			}else
			{
				printf("Target file's view of mapping IO error\n");
				exit(1);
			}
		}else
		{
			printf("Target file's mapping IO error\n");
			exit(1);
		}
	}else
	{
		printf("Target file %s opening error\n",argv[0]);
		exit(1);
	}
	return 0;
}
///////////////////////////////////////////////////////////////////////////////////////////
DWORD Rva2Raw(short NumOfSections, IMAGE_SECTION_HEADER* FSH, int rva)
{
	int i;
	if(rva<(int)FSH[0].VirtualAddress)return rva;
	for (i = (int)NumOfSections-1; i >= 0; i--)if ((int)FSH[i].VirtualAddress <= rva && (int)FSH[i].VirtualAddress + (int)FSH[i].Misc.VirtualSize > rva)return FSH[i].PointerToRawData + (rva - FSH[i].VirtualAddress);
	return 0xFFFFFFFF;
}
///////////////////////////////////////////////////////////////////////////////////////////
DWORD Raw2Rva(short NumOfSections, IMAGE_SECTION_HEADER* FSH, int rva)
{
	int i;
	if(rva<(int)FSH[0].PointerToRawData)return rva+FSH[0].VirtualAddress;
	for (i = (int)NumOfSections-1; i >= 0; i--)if ((int)FSH[i].PointerToRawData <= rva && rva <= (int)(FSH[i].PointerToRawData + min(FSH[i].Misc.VirtualSize,FSH[i].SizeOfRawData)))return FSH[i].VirtualAddress + rva - FSH[i].PointerToRawData;
	return 0xFFFFFFFF;
}
///////////////////////////////////////////////////////////////////////////////////////////
