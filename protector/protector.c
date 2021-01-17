// protector.c: определяет точку входа для консольного приложения.
//
#pragma warning (disable:4996)
#pragma warning (disable:4090)
#pragma warning (disable:4028)
//#include "..\personifier\personifier.h"
#include "..\\sqlite3static\\sqlite3.h"
#include "protector.h"


__cdecl wmain( int argc, wchar_t *argv[ ], wchar_t *envp[ ] )
{
	char namebuff[MAX_PATH*2];
	unsigned char *binBuffer;
	unsigned int binPoint;
	unsigned int binTotal;
	HANDLE hFile,hMap,hBin;
	int HeadSum,CheckSum,Limit=0,Options=0;
	__int64 imageBase;
	size_t fSize;
	DWORD ep;
	R_RSA_PROTO_KEY protoKey;
	R_RSA_PUBLIC_KEY PUBLIC_KEY;
	R_RSA_PRIVATE_KEY PRIVATE_KEY;
	R_RANDOM_STRUCT randomStruct;
#if _DEBUG
	LPWSTR param0=L"protector.exe";
	LPWSTR param1=L"..\\win32soko.exe";
	LPWSTR param2=L"..\\win32soko.preload.exe";
	LPWSTR param3=L"..\\win32soko.dll";
	LPWSTR param4=L"..\\win32soko.bin";
	LPWSTR param5=L"win32soko_control_pipe";
	LPWSTR param6=L"8";
	LPWSTR param7=L"102400";
	LPWSTR testCmdLine[]={param0,param1,param2,param3,param4,param5,param6};
	argv = testCmdLine;
	argc=7;
#endif
	if(argc < 6)
	{
		printf("Protector - protection applicator module demo\n");
		printf("Usage: <protector.exe> [<source>] [<preload>] [<predll>] [<prodata>] [<pipename>] [<options>] <prosize>\n");
		printf("where:\n");
		printf("<source> - path to file for protection's application\n");
		printf("<preload> - path to protected file\n");
		printf("<predll> - path to companion dll\n");
		printf("<prodata> - path to companion data\n");
		printf("<pipename> - name of pipe for link with companion library\n");
		printf("without \\\\.\\\\pipe\\ prefix\n");
		printf("<options> options of protection:\n");
		printf("0 - enable all options of protection\n");
		printf("1 - disable watermarking\n");
		printf("2 - disable page encryption & protection\n");
		printf("3 - disable page encryption & watermarking\n4 - delete SECIRITY section from IMAGE_DIRECTORY\т");
		printf("<prosize> - approx. size of watermark data, optional\n");
		exit(0);
	}
	if(!PathFileExistsW(argv[1]))
	{
		memset(&namebuff,0,sizeof(namebuff));
		WideCharToMultiByte(CP_OEMCP,0,(LPCWSTR)argv[1],(int)wcslen((wchar_t *)argv[1]),(LPSTR)&namebuff,sizeof(namebuff),NULL,NULL);
		printf("Target file's path %s is incorrect\n",&namebuff);
		exit(0);
	}
	Options = _wtoi(argv[6]);
	if(argc>7)Limit = _wtoi(argv[7]);
	printf("apply.exe, version 1.0\nProfense SDK project protection's applicator utility\n===================================================\n");
	CopyFile(argv[1],argv[2],FALSE);
	hFile = CreateFile(argv[2],GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
	fSize = GetFileSize(hFile,NULL);
	if(hFile!=INVALID_HANDLE_VALUE)
	{
		hMap = CreateFileMapping(hFile,NULL,PAGE_READWRITE,0,0,NULL);
		if(hMap!=INVALID_HANDLE_VALUE)
		{
			char *BaseAddr = MapViewOfFile(hMap,FILE_MAP_WRITE,0,0,0);
			size_t apicnt=0;
			if(BaseAddr)
			{
				if(!IsPacked(BaseAddr,fSize))
				{
					int seccnt,i,k,l,m,n,o,done=0,cursor=0,total=1024;
					switch_stains ss;
					DWORD currApi=0;
					ULONG_PTR apis;
					IMAGE_NT_HEADERS* inh = (IMAGE_NT_HEADERS*)(BaseAddr + ((IMAGE_DOS_HEADER*)BaseAddr)->e_lfanew);
					IMAGE_NT_HEADERS64* inh2 = (IMAGE_NT_HEADERS64*)(BaseAddr + ((IMAGE_DOS_HEADER*)BaseAddr)->e_lfanew);
					IMAGE_SECTION_HEADER* ish = (IMAGE_SECTION_HEADER*)(BaseAddr + ((IMAGE_DOS_HEADER*)BaseAddr)->e_lfanew + inh->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4);
					BOOL ISAMD64 = (inh->FileHeader.Machine == 0x8664);
					unsigned __int64 *excluded = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,1024*sizeof(unsigned __int64));
					R_ENVELOPE_CTX context;
					char key[8], iv[8], *buffer,*test;
					ss.stp = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,1024 * sizeof(char *)*1024);
					ss.stsz = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,1024 * sizeof(int)*1024);
					ss.count = 0;
					ss.total = 1024;
					if(ISAMD64)memmove(&imageBase,&inh2->OptionalHeader.ImageBase,sizeof(__int64));
					else memmove(&imageBase,&inh->OptionalHeader.ImageBase,sizeof(int));
					memset(&namebuff,0,sizeof(namebuff));
					WideCharToMultiByte(CP_OEMCP,0,(LPCWSTR)argv[3],(int)wcslen((wchar_t *)argv[3]),(LPSTR)&namebuff,sizeof(namebuff),NULL,NULL);
					if(ISAMD64)apis = ScanForApiCall64(BaseAddr,fSize,namebuff,(Options & 8));
					else apis = ScanForApiCall32(BaseAddr,fSize,namebuff,(Options & 8));
					if(ISAMD64)ep = inh2->OptionalHeader.AddressOfEntryPoint + 15;
					else ep = inh->OptionalHeader.AddressOfEntryPoint + 9;
					if(!(Options & 4))
					{
						if(ISAMD64)
						{
							if(inh2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size)
							{
								inh2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress=0;
								inh2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size=0;
							}
						}else
						{
							if(inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size)
							{
								inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress=0;
								inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size=0;
							}
						}
					}
					if(!(Options & 1))
					{
						struct ud uds,*udp=(struct ud *)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(uds)*6);
						int len,rawoffset,y,z;
						unsigned __int64 offset=0;
						if(ISAMD64)seccnt = inh2->FileHeader.NumberOfSections;
						else seccnt = inh->FileHeader.NumberOfSections;
						for(k=0;k<seccnt;k++)
						{
							if(ish[k].Characteristics & IMAGE_SCN_CNT_CODE && !strcmpi(ish[k].Name,".text"))
							{
								int found=0;
								ud_init(&uds);
								ud_set_mode(&uds,ISAMD64?64:32);
								ud_set_input_buffer(&uds,(ULONG)ish[k].PointerToRawData+BaseAddr,ish[k].SizeOfRawData);
								rawoffset = ish[k].PointerToRawData;
								offset = (unsigned __int64)ish[k].VirtualAddress;
								if(ISAMD64)offset += inh2->OptionalHeader.ImageBase;
								else offset += (unsigned __int64)inh->OptionalHeader.ImageBase;
								while(len = ud_disassemble(&uds))
								{
									if(!ISAMD64)
									{
										if(uds.mnemonic == UD_Ijmp
											&& uds.operand[0].type == UD_OP_MEM
											&& uds.operand[0].size == 32)
										{
											if(uds.operand[0].index != UD_NONE)
											{
												if(udp[1].mnemonic == UD_Icmp
													&& udp[1].operand[0].type == UD_OP_REG
													&& udp[1].operand[1].type == UD_OP_IMM 
													&& udp[1].operand[0].base == uds.operand[0].index)
												{
													if(udp[0].operand[0].type == UD_OP_JIMM)
													{
														if(ss.count + 1 == ss.total)
														{
															char **temp = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(char *)*ss.total*2);
															int *tempi = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(int)*ss.total*2);
															memmove(temp,ss.stp,ss.total* sizeof(char *));
															memmove(temp,ss.stsz,ss.total* sizeof(int));
															HeapFree(GetProcessHeap(),0,ss.stsz);
															HeapFree(GetProcessHeap(),0,ss.stp);
															ss.stp = temp;
															ss.stsz = tempi;
															ss.total *= 2;
														}
														ss.stp[ss.count] = (char *)uds.operand[0].lval.udword;
														ss.stsz[ss.count++] = (udp[1].operand[1].lval.udword + 1) * sizeof(DWORD);
													}
												}else if(udp[2].mnemonic == UD_Icmp			//4th opcode is CMP r32a,imm32
													&& udp[2].operand[0].type == UD_OP_REG	//
													&& udp[2].operand[1].type == UD_OP_IMM	//
													&& udp[1].operand[0].type == UD_OP_JIMM	//3rd opcode is Jxx 
													&& udp[2].operand[0].base == udp[0].operand[1].base//2rd opcode is MOV r32b,trans_table[r32a]
													&& uds.operand[0].index == udp[0].operand[0].base)//1st opcode is jmp jump_table[b]
												{
													char *tmp1,*tmp2;
													int sz1,sz2;
													if(ss.count + 2 >= ss.total)
													{
														char **temp = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(char *)*ss.total*2);
														int *tempi = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(int)*ss.total*2);
														memmove(temp,ss.stp,ss.total* sizeof(char *));
														memmove(temp,ss.stsz,ss.total* sizeof(int));
														HeapFree(GetProcessHeap(),0,ss.stsz);
														HeapFree(GetProcessHeap(),0,ss.stp);
														ss.stp = temp;
														ss.stsz = tempi;
														ss.total *= 2;
													}
													tmp1 = (char *)udp[0].operand[1].lval.udword;//translation table address
													sz1 = (udp[2].operand[1].lval.udword + 1) * (udp[0].operand[1].size/8);
													test = (char *)udp[0].operand[1].lval.udword;
													test -= inh->OptionalHeader.ImageBase;
													test -= ish[k].VirtualAddress;
													test += ish[k].PointerToRawData;
													test += (int)BaseAddr;
													for(z=y=0;y<udp[2].operand[1].lval.sdword;y++)
													{
														switch(udp[0].operand[1].size)
														{
															case 32:
																if(((int *)test)[y]>z)z = ((int *)test)[y];
																break;
															case 16:
																if(((short *)test)[y]>z)z = (int)((short *)test)[y];
																break;
															case 8:
																if(((char *)test)[y]>z)z = (int)((char *)test)[y];
																break;
															default:
																;
														}
													}
													tmp2 = (char *)uds.operand[0].lval.udword;//jump table address
													sz2 = sizeof(DWORD) * (z + 1);
													if(tmp2>tmp1)
													{
														ss.stp[ss.count] = tmp1;
														ss.stsz[ss.count++] = sz1;
														ss.stp[ss.count] = tmp2;
														ss.stsz[ss.count++] = sz2;
													}else
													{
														ss.stp[ss.count] = tmp2;
														ss.stsz[ss.count++] = sz2;
														ss.stp[ss.count] = tmp1;
														ss.stsz[ss.count++] = sz1;
													}
												}else if(udp[2].mnemonic == UD_Icmp
													&& udp[2].operand[0].type == UD_OP_REG
													&& udp[2].operand[1].type == UD_OP_IMM 
													&& udp[2].operand[0].base == uds.operand[0].index
													&& udp[1].operand[0].type != UD_OP_JIMM)
												{
													if(udp[1].operand[0].type == UD_OP_JIMM)
													{
														if(ss.count + 1 == ss.total)
														{
															char **temp = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(char *)*ss.total*2);
															int *tempi = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(int)*ss.total*2);
															memmove(temp,ss.stp,ss.total* sizeof(char *));
															memmove(temp,ss.stsz,ss.total* sizeof(int));
															HeapFree(GetProcessHeap(),0,ss.stsz);
															HeapFree(GetProcessHeap(),0,ss.stp);
															ss.stp = temp;
															ss.stsz = tempi;
															ss.total *= 2;
														}
														ss.stp[ss.count] = (char *)uds.operand[0].lval.udword;
														ss.stsz[ss.count++] = (udp[2].operand[1].lval.udword + 1) * sizeof(DWORD);
													}
												}else if(udp[3].mnemonic == UD_Icmp
													&& udp[3].operand[0].type == UD_OP_REG
													&& udp[3].operand[1].type == UD_OP_IMM 
													&& udp[3].operand[0].base == uds.operand[0].index
													&& udp[1].operand[0].type != UD_OP_JIMM
													&& udp[0].operand[0].type != UD_OP_JIMM)
												{
													if(udp[2].operand[0].type == UD_OP_JIMM)
													{
														if(ss.count + 1 == ss.total)
														{
															char **temp = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(char *)*ss.total*2);
															int *tempi = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(int)*ss.total*2);
															memmove(temp,ss.stp,ss.total* sizeof(char *));
															memmove(temp,ss.stsz,ss.total* sizeof(int));
															HeapFree(GetProcessHeap(),0,ss.stsz);
															HeapFree(GetProcessHeap(),0,ss.stp);
															ss.stp = temp;
															ss.stsz = tempi;
															ss.total *= 2;
														}
														ss.stp[ss.count] = (char *)uds.operand[0].lval.udword;
														ss.stsz[ss.count++] = (udp[3].operand[1].lval.udword + 1) * sizeof(DWORD);
													}
												}else if(udp[4].mnemonic == UD_Icmp
													&& udp[4].operand[0].type == UD_OP_REG
													&& udp[4].operand[1].type == UD_OP_IMM 
													&& udp[4].operand[0].base == uds.operand[0].index
													&& udp[2].operand[0].type != UD_OP_JIMM
													&& udp[1].operand[0].type != UD_OP_JIMM
													&& udp[0].operand[0].type != UD_OP_JIMM)
												{
													if(udp[3].operand[0].type == UD_OP_JIMM)
													{
														if(ss.count + 1 == ss.total)
														{
															char **temp = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(char *)*ss.total*2);
															int *tempi = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(int)*ss.total*2);
															memmove(temp,ss.stp,ss.total* sizeof(char *));
															memmove(temp,ss.stsz,ss.total* sizeof(int));
															HeapFree(GetProcessHeap(),0,ss.stsz);
															HeapFree(GetProcessHeap(),0,ss.stp);
															ss.stp = temp;
															ss.stsz = tempi;
															ss.total *= 2;
														}
														ss.stp[ss.count] = (char *)uds.operand[0].lval.udword;
														ss.stsz[ss.count++] = (udp[4].operand[1].lval.udword + 1) * sizeof(DWORD);
													}
												}else if(udp[5].mnemonic == UD_Icmp
													&& udp[5].operand[0].type == UD_OP_REG
													&& udp[5].operand[1].type == UD_OP_IMM 
													&& udp[5].operand[0].base == uds.operand[0].index
													&& udp[3].operand[0].type != UD_OP_JIMM
													&& udp[2].operand[0].type != UD_OP_JIMM
													&& udp[1].operand[0].type != UD_OP_JIMM
													&& udp[0].operand[0].type != UD_OP_JIMM)
												{
													if(udp[4].operand[0].type == UD_OP_JIMM)
													{
														if(ss.count + 1 == ss.total)
														{
															char **temp = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(char *)*ss.total*2);
															int *tempi = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(int)*ss.total*2);
															memmove(temp,ss.stp,ss.total* sizeof(char *));
															memmove(temp,ss.stsz,ss.total* sizeof(int));
															HeapFree(GetProcessHeap(),0,ss.stsz);
															HeapFree(GetProcessHeap(),0,ss.stp);
															ss.stp = temp;
															ss.stsz = tempi;
															ss.total *= 2;
														}
														ss.stp[ss.count] = (char *)uds.operand[0].lval.udword;
														ss.stsz[ss.count++] = (udp[5].operand[1].lval.udword + 1) * sizeof(DWORD);
													}
												}
											}
										}
										if(ss.count)
										{
											do
											{
												int tested = found;
												for(z=0;z<ss.count;z++)
												{
													if(ss.stp[z] == (char *)offset)
													{
														rawoffset += ss.stsz[z];
														offset += (unsigned __int64)ss.stsz[z];
														for(y=z+1;y<ss.count+1;y++)
														{
															ss.stsz[y-1] = ss.stsz[y];
															ss.stp[y-1] = ss.stp[y];
														}
														ss.count--;
														ud_init(&uds);
														ud_set_mode(&uds,32);
														ud_set_input_buffer(&uds,BaseAddr+rawoffset,ish[k].SizeOfRawData-rawoffset+ish[k].PointerToRawData);
														found++;
														break;
													}
												}
												if(tested==found)break;
											}while(found);
											if(found)
											{
												found=0;
												continue;
											}
										}
										for(y=0;y<6;y++)
										{
											if(!y)memmove(&udp[y],&uds,sizeof(uds));
											else memmove(&udp[y],&udp[y-1],sizeof(uds));
										}
									}
									if((rawoffset % 0x1000) < ((rawoffset + len) % 0x1000))//avoid opcodes on page boundaries
									{
										if(uds.operand[0].type == UD_OP_REG && ((!ISAMD64 && uds.operand[0].size == 32) || (ISAMD64 && uds.operand[0].size == 64)))
										{
											if(uds.operand[1].type == UD_OP_REG && ((!ISAMD64 && uds.operand[1].size == 32) || (ISAMD64 && uds.operand[1].size == 64)))
											{
												if(uds.mnemonic == UD_Imov)
												{
													if(!ISAMD64 || ((ISAMD64 && uds.operand[0].base >= UD_R_RAX && uds.operand[0].base <= UD_R_RSI) && 
														(ISAMD64 && uds.operand[1].base >= UD_R_RAX && uds.operand[1].base <= UD_R_RSI)))
													{
														if((!ISAMD64 && uds.operand[0].base != UD_R_ESP && uds.operand[0].base != UD_R_EBP) || (ISAMD64 && uds.operand[0].base != UD_R_RSP && uds.operand[0].base != UD_R_RBP))
														{
															if((!ISAMD64 && uds.operand[1].base != UD_R_ESP && uds.operand[1].base != UD_R_EBP) || (ISAMD64 && uds.operand[1].base != UD_R_RSP && uds.operand[1].base != UD_R_RBP))
															{
																if(cursor==total)
																{
																	unsigned __int64 *temp = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(unsigned __int64) * total * 2);
																	MoveMemory(temp,excluded,sizeof(unsigned __int64) * total);
																	HeapFree(GetProcessHeap(),0,excluded);
																	excluded = temp;
																	total *= 2;
																}
																if(!ISAMD64)excluded[cursor++] = offset | ((unsigned __int64)((uds.operand[1].base - UD_R_EAX | (uds.operand[0].base - UD_R_EAX) << 3)) << 56);
																else excluded[cursor++] = offset | ((unsigned __int64)((uds.operand[1].base - UD_R_RAX | (uds.operand[0].base - UD_R_RAX) << 3)) << 56);
																for(i=0;i<len;i++)BaseAddr[rawoffset+i]=0x90;
															}
														}
													}
												}
											}
										}
									}
									if(Limit)if(cursor * 8 > Limit)break;
									rawoffset += len;
									offset += (unsigned __int64)len;
								}
								break;
							}
						}
						if(ss.stsz)HeapFree(GetProcessHeap(),0,ss.stsz);
						if(ss.stp)HeapFree(GetProcessHeap(),0,ss.stp);
					}
					if(!(Options & 2))
					{
						InitRandomStruct (&randomStruct);
						context.encryptionAlgorithm = EA_DES_CBC;
						R_GenerateBytes (key, 8, &randomStruct);
						R_GenerateBytes (iv, 8, &randomStruct);
						for(k=0;k<seccnt;k++)
						{
							if(ish[k].Characteristics & IMAGE_SCN_CNT_CODE && !strcmpi(ish[k].Name,".text"))
							{
								int pagecnt = ish[k].SizeOfRawData >> 12;//number of pages
								buffer = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,0x1000);
								for(i=0;i<pagecnt;i++)
								{
									MoveMemory(buffer,ish[k].PointerToRawData + BaseAddr + i * 0x1000,0x1000);
									memset(&context,0,sizeof(context));
									context.encryptionAlgorithm = EA_DES_CBC;
									CipherInit(&context, EA_DES_CBC, key, iv, 1);
									CipherUpdate(&context,ish[k].PointerToRawData + BaseAddr + i * 0x1000,buffer,0x1000);
								}
								HeapFree(GetProcessHeap(),0,buffer);
								break;
							}
						}
					}
					if(CheckSumMappedFile(BaseAddr, fSize, &HeadSum,&CheckSum))
					{
						IMAGE_NT_HEADERS* inh = (IMAGE_NT_HEADERS*)(BaseAddr + ((IMAGE_DOS_HEADER*)BaseAddr)->e_lfanew);
						IMAGE_NT_HEADERS64* inh2 = (IMAGE_NT_HEADERS64*)(BaseAddr + ((IMAGE_DOS_HEADER*)BaseAddr)->e_lfanew);
						if(ISAMD64)inh2->OptionalHeader.CheckSum = CheckSum;
						else inh->OptionalHeader.CheckSum = CheckSum;
					}
					FlushViewOfFile(BaseAddr,fSize);
					CloseHandle(hMap);
					CloseHandle(hFile);
					protoKey.bits = 1024;
					protoKey.useFermat4 = 1;
					printf("Generating PKCS keypair...\n");
					InitRandomStruct(&randomStruct);
					R_GeneratePEMKeys(&PUBLIC_KEY, &PRIVATE_KEY, &protoKey, &randomStruct);
					binBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024);
					binTotal = 1024;
					binPoint = 0;
					if(binBuffer)
					{
						for(k=i=l=0;k<anest.cursor;k++)
						{
							if(currApi != anest.api[k].dll_hash)
							{
								if(k)
								{
									////insert api data in api table with base record id
									apicnt += i;
									MemoryMover(&binBuffer, &binPoint, &binTotal, &i, 4);
									o=(int)strlen(anest.api[l].libname);
									MemoryMover(&binBuffer, &binPoint, &binTotal, &o, 4);
									for(m=0;m<o;m++)anest.api[l].libname[m]+=((char *)&currApi)[m%4];
									MemoryMover(&binBuffer, &binPoint, &binTotal, &currApi, 4);
									MemoryMover(&binBuffer, &binPoint, &binTotal, anest.api[l].libname, o);
									for(m=0;m<i;m++)
									{
										MemoryMover(&binBuffer, &binPoint, &binTotal, &anest.api[l + m].api_hash, 4);
										MemoryMover(&binBuffer, &binPoint, &binTotal, &anest.api[l + m].iofs, 4);
									}
								}
								i=1;
								l=k;
								currApi = anest.api[k].dll_hash;
							}else i++;
						}
						apicnt+=i;
						if(i)
						{
							MemoryMover(&binBuffer, &binPoint, &binTotal, &i, 4);
							o=(int)strlen(anest.api[l].libname);
							MemoryMover(&binBuffer, &binPoint, &binTotal, &o, 4);
							for(m=0;m<o;m++)anest.api[l].libname[m]+=((char *)&currApi)[m%4];
							MemoryMover(&binBuffer, &binPoint, &binTotal, &currApi, 4);
							MemoryMover(&binBuffer, &binPoint, &binTotal, anest.api[l].libname, o);
							for(m=0;m<i;m++)
							{
								MemoryMover(&binBuffer, &binPoint, &binTotal, &anest.api[l + m].api_hash, 4);
								MemoryMover(&binBuffer, &binPoint, &binTotal, &anest.api[l + m].iofs, 4);
							}
						}
						printf("Stored %d APIs\n",apicnt);
						for(k=0;k<anest.cursor;k++)HeapFree(GetProcessHeap(),0,anest.api[k].libname);
						HeapFree(GetProcessHeap(),0,anest.api);
						k=0;
						MemoryMover(&binBuffer, &binPoint, &binTotal, &k, 4);
						if(Options & 1)cursor = 0;
						MemoryMover(&binBuffer, &binPoint, &binTotal, &cursor, 4);
						for (i = 0; i<cursor; i++)MemoryMover(&binBuffer, &binPoint, &binTotal, &excluded[i], sizeof(unsigned __int64));
						if(Options & 2)cursor = 0xFFFFFFFF;//without page protection
						else cursor = 0; 
						MemoryMover(&binBuffer, &binPoint, &binTotal, &cursor, 4);
						MemoryMover(&binBuffer, &binPoint, &binTotal, &key, sizeof(key));
						MemoryMover(&binBuffer, &binPoint, &binTotal, &iv, sizeof(iv));
						MemoryMover(&binBuffer, &binPoint, &binTotal, &PUBLIC_KEY, sizeof(PUBLIC_KEY));
						MemoryMover(&binBuffer, &binPoint, &binTotal, &PRIVATE_KEY, sizeof(PRIVATE_KEY));
						/////////////////////////////////////////////////////////////
						/////////////////WRITE DATA TO DATABASE IN TEXT FIELD////////
						/////////////////////////////////////////////////////////////
						if (1)
						{
							sqlite3 *db = NULL;
							int rc = sqlite3_open_v2(argv[4], &db, SQLITE_OPEN_READWRITE, NULL);
							if (rc != SQLITE_OK)
							{
								printf("Db %s open failed: %s\n", argv[4], sqlite3_errmsg(db));
							}
							else
							{
								unsigned char dbbuffer[256];
								sqlite3_stmt *stmt = NULL;
								sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS ITEMS(ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, NAME VARCHAR(255) NOT NULL, FROMTS DATETIME DEFAULT CURRENT_TIMESTAMP, FILE BLOB);", NULL, NULL, NULL);
								sprintf(dbbuffer, "INSERT INTO ITEMS(NAME, FILE) VALUES('%s', ?)", argv[5]);
								rc = sqlite3_prepare_v2(db, dbbuffer, -1, &stmt, NULL);
								if (rc != SQLITE_OK)
								{
									printf("Db prepare failed: %s\n", sqlite3_errmsg(db));
								}
								else
								{
									// SQLITE_STATIC because the statement is finalized
									// before the buffer is freed:
									rc = sqlite3_bind_blob(stmt, 1, binBuffer, binPoint, SQLITE_STATIC);
									if (rc != SQLITE_OK)
									{
										printf("Db bind failed: %s\n", sqlite3_errmsg(db));
									}
									else
									{
										rc = sqlite3_step(stmt);
										if (rc != SQLITE_DONE)printf("Db execution failed: %s\n", sqlite3_errmsg(db));
									}
								}
								sqlite3_finalize(stmt);
							}
							sqlite3_close(db);
						}
						HeapFree(GetProcessHeap(), 0, binBuffer);
						hBin = BeginUpdateResource(argv[3],FALSE);
						if(UpdateResource(hBin,MAKEINTRESOURCE(1234),MAKEINTRESOURCE(4321),0,&PUBLIC_KEY,sizeof(PUBLIC_KEY)))
						{
							if(!EndUpdateResource(hBin,FALSE))
							{
								printf("Saving updated resources in companion dll causes error, discarded\n");
								exit(1);
							}else
							{
								hBin = CreateFile(argv[3],GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,NULL);
								if(hBin != INVALID_HANDLE_VALUE)
								{
									fSize = GetFileSize(hBin,NULL);
									hMap = CreateFileMapping(hBin,NULL,PAGE_READWRITE,0,0,NULL);
									if(hMap != INVALID_HANDLE_VALUE)
									{
										BaseAddr = MapViewOfFile(hMap,FILE_MAP_WRITE,0,0,0);
										if(BaseAddr)
										{
											LPWSTR genericname = L"TESTPIPENAMETESTPIPENAMETESTPIPENAMETESTPIPENAMETESTPIPENAME";
											size_t pipenamelen = wcslen(genericname);
											for(i=0;i<(int)(fSize - pipenamelen);i++)
											{
												if(!memcmp(&BaseAddr[i],genericname,pipenamelen))
												{
													memmove(&BaseAddr[i],argv[5],(wcslen(argv[5]) + 1) * sizeof(WCHAR));
													break;
												}
											}
											if(1)
											{
												DWORD ready=1;
												inh = (IMAGE_NT_HEADERS*)(BaseAddr + ((IMAGE_DOS_HEADER*)BaseAddr)->e_lfanew);
												inh2 = (IMAGE_NT_HEADERS64*)(BaseAddr + ((IMAGE_DOS_HEADER*)BaseAddr)->e_lfanew);
												ish = (IMAGE_SECTION_HEADER*)(BaseAddr + ((IMAGE_DOS_HEADER*)BaseAddr)->e_lfanew + inh->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4);
												ISAMD64 = inh->FileHeader.Machine == 0x8664;
												if(ISAMD64)seccnt = inh2->FileHeader.NumberOfSections;
												else seccnt = inh->FileHeader.NumberOfSections;
												for(k=0;k<seccnt;k++)
												{
													if(ish[k].Characteristics & IMAGE_SCN_CNT_CODE && !strcmpi(ish[k].Name,".text"))
													{
														for(i=0;i<(int)(ish[k].SizeOfRawData-4);i++)
														{
															if(*((DWORD *)&BaseAddr[i]) == 0x12345678)
															{
																*((DWORD *)&BaseAddr[i]) = ep;
																ready=0;
																break;
															}
														}
														if(ready)
														{
															printf("Error in search of correction value, exit\n");
															exit(-123);
														}else break;
													}
												}
											}
											if(CheckSumMappedFile(BaseAddr,(DWORD)fSize,&HeadSum,&CheckSum))
											{
												IMAGE_NT_HEADERS* inh = (IMAGE_NT_HEADERS*)(BaseAddr + ((IMAGE_DOS_HEADER*)BaseAddr)->e_lfanew);
												IMAGE_NT_HEADERS64* inh2 = (IMAGE_NT_HEADERS64*)(BaseAddr + ((IMAGE_DOS_HEADER*)BaseAddr)->e_lfanew);
												if(ISAMD64)inh2->OptionalHeader.CheckSum = CheckSum;
												else inh->OptionalHeader.CheckSum = CheckSum;
											}
											FlushViewOfFile(BaseAddr,fSize);
											CloseHandle(hMap);
											CloseHandle(hBin);
											printf("Protection done OK\n");
											exit(1);
										}
									}
								}
							}
						}else
						{
							printf("Updating resources in companion dll causes IO error\n");
							exit(1);
						}
					}else
					{
						printf("Protection data file opening IO error\n");
						exit(1);
					}
				}else
				{
					printf("Target file is packed or protected by external software\n");
					exit(1);
				}
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
void MemoryMover(unsigned char **binBuffer, unsigned int *binPoint, unsigned int *binTotal, unsigned char *cursor, unsigned int size)
{
	if (size + *binPoint < *binTotal)
	{
		RtlMoveMemory(*binBuffer[*binPoint], cursor, size);
		*binPoint += size;
	}
	else
	{
		unsigned char *temp = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *binTotal * 2);
		RtlMoveMemory(temp, *binBuffer, *binPoint);
		HeapFree(GetProcessHeap(), 0, *binBuffer);
		*binBuffer = temp;
		*binTotal *= 2;
	}
}
///////////////////////////////////////////////////////////////////////////////////////////
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
///////////////////////////////////////////////////////////////////////////////////////////
ULONG_PTR ScanForApiCall32(char *exeMem, size_t fSize, char *dllName, BOOL bIAT)
{
	IMAGE_NT_HEADERS* inh = (IMAGE_NT_HEADERS*)(exeMem + ((IMAGE_DOS_HEADER*)exeMem)->e_lfanew);
	IMAGE_SECTION_HEADER* ish = IMAGE_FIRST_SECTION(inh);
	IMAGE_IMPORT_DESCRIPTOR *first, *imports = (IMAGE_IMPORT_DESCRIPTOR*)inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	LARGE_INTEGER *list = VirtualAlloc(0,fSize*8,MEM_COMMIT,PAGE_READWRITE);
	size_t impBrw,impCnt=0,impRaw = imports?Rva2Raw(inh->FileHeader.NumberOfSections,ish,(DWORD)imports):0;
	DWORD total=0,i,enumerated=1,totaly=0;
	char *funcname = "initialize";
	IMAGE_THUNK_DATA32 *thunks=NULL,*othunk=NULL;
	int importRva,found=0,needspace = sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2 + sizeof(IMAGE_THUNK_DATA32) * 2 + strlen(dllName) + 1 + strlen(funcname) + 3 + 9;
	ULONG done=0;
	BYTE *res=NULL;
	anest.api = (api_list *)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(api_list)*1024);
	anest.totala = 1024;
	anest.cursor = 0;
	imports = (IMAGE_IMPORT_DESCRIPTOR*)Rva2Raw(inh->FileHeader.NumberOfSections, ish, (DWORD)imports);
	if(imports != (IMAGE_IMPORT_DESCRIPTOR*)0xFFFFFFFF)
	{
		first = imports = (IMAGE_IMPORT_DESCRIPTOR*)(exeMem + (ULONG)imports);
		while(first->Name)
		{
			impCnt++;
			first++;
		}
		if(bIAT)
		{
			IMAGE_IMPORT_DESCRIPTOR temp;
			size_t prevdll=1;
			impBrw = impCnt - ((needspace / sizeof(IMAGE_IMPORT_DESCRIPTOR)) + 1);
			for(i=impBrw;i<impCnt;i++)
			{
				char* lib = (char*)Rva2Raw(inh->FileHeader.NumberOfSections, ish, imports[i].Name);
				lib = lib + (ULONG)exeMem;
				if(strstr(lib,"d3dx"))
				{
					char *prevlib = (char *)imports[impBrw-prevdll].Name;
					prevlib = prevlib + (ULONG)exeMem;
					//store d3dx series dll reference in previous
					memmove(&temp,&imports[i],sizeof(temp));
					//check previous dll references for d3dx dlls
					while(impBrw > prevdll && strstr(prevlib,"d3dx"))
					{
						prevdll++;
						prevlib = (char *)imports[impBrw-prevdll].Name;
						prevlib = prevlib + (ULONG)exeMem;
					}
					//if we have a room for d3dx series dll in previous IAT references, we can replace it 
					if(prevdll == impBrw)
					{
						printf("Error in partial IAT encryption\n");
						exit(-15);
					}else
					{
						memmove(&imports[i],&imports[impBrw-prevdll],sizeof(temp));
						memmove(&imports[impBrw-prevdll],&temp,sizeof(temp));
					}
				}
			}
		}
		for(i=0;i<impCnt;i++,imports++)
		{
			char* libName = (char*)Rva2Raw(inh->FileHeader.NumberOfSections, ish, imports->Name);
			int k = 0;
			libName = libName + (ULONG)exeMem;
			thunks = (IMAGE_THUNK_DATA32 *)Rva2Raw(inh->FileHeader.NumberOfSections,ish,imports->FirstThunk);
			if(imports->OriginalFirstThunk)othunk = (IMAGE_THUNK_DATA32 *)Rva2Raw(inh->FileHeader.NumberOfSections,ish,imports->OriginalFirstThunk);
			if(thunks)
			{
				thunks = (IMAGE_THUNK_DATA32 *)(exeMem + (ULONG)thunks);
				if(othunk)othunk = (IMAGE_THUNK_DATA32 *)(exeMem + (ULONG)othunk);
				if(!bIAT || impBrw <= i)
				{
					if(imports->TimeDateStamp && othunk)
					{
						while(othunk->u1.AddressOfData)
						{
							char* curName = (char *)Rva2Raw(inh->FileHeader.NumberOfSections, ish, othunk->u1.ForwarderString);
							if(IMAGE_SNAP_BY_ORDINAL32(othunk->u1.Ordinal))
							{
								curName = (char *)othunk->u1.Ordinal;
							}else if(curName != (char *)0xFFFFFFFF)
							{
								curName = (ULONG)exeMem + curName;
							}else
							{ 
								othunk++;
								thunks++;
								continue;
							}
							totaly++;
							if(anest.cursor == anest.totala)
							{
								api_list *temp = (api_list *)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(api_list) * anest.totala * 2);
								memmove(temp,anest.api,sizeof(api_list) * anest.cursor);
								HeapFree(GetProcessHeap(),0,anest.api);
								anest.totala *= 2;
								anest.api = temp;
							}
							anest.api[anest.cursor].dll_hash = CalcHash(_strlwr(libName));
							if(IMAGE_SNAP_BY_ORDINAL32(othunk->u1.Ordinal))
							{
								anest.api[anest.cursor].api_hash = (int)othunk->u1.Ordinal;
							}else
							{
								anest.api[anest.cursor].api_hash = CalcHash(&curName[2]);
								memset(curName,0,strlen(&curName[2])+2);
							}
							anest.api[anest.cursor].iofs = (void *)(imports->FirstThunk + k*4);
							anest.api[anest.cursor].libname = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,strlen(libName)+1);
							memmove(anest.api[anest.cursor++].libname,_strlwr(libName),strlen(libName));
							memset(thunks,0,sizeof(IMAGE_THUNK_DATA32));
							memset(othunk,0,sizeof(IMAGE_THUNK_DATA32));
							thunks++;
							othunk++;
							k++;
						}
					}else
					{
						while(thunks->u1.AddressOfData)
						{
							char* curName = (char *)Rva2Raw(inh->FileHeader.NumberOfSections, ish, thunks->u1.ForwarderString);
							if(IMAGE_SNAP_BY_ORDINAL32(thunks->u1.Ordinal))
							{
								curName = (char *)thunks->u1.Ordinal;
							}else if(curName != (char *)0xFFFFFFFF)
							{
								curName = (ULONG)exeMem + curName;
							}else
							{ 
								thunks++;
								continue;
							}
							totaly++;
							if(anest.cursor == anest.totala)
							{
								api_list *temp = (api_list *)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(api_list) * anest.totala * 2);
								memmove(temp,anest.api,sizeof(api_list) * anest.cursor);
								HeapFree(GetProcessHeap(),0,anest.api);
								anest.totala *= 2;
								anest.api = temp;
							}
							anest.api[anest.cursor].dll_hash = CalcHash(_strlwr(libName));
							if(IMAGE_SNAP_BY_ORDINAL32(thunks->u1.Ordinal))
							{
								anest.api[anest.cursor].api_hash = (int)thunks->u1.Ordinal;
							}else
							{
								anest.api[anest.cursor].api_hash = CalcHash(&curName[2]);
								memset(curName,0,strlen(&curName[2])+2);
							}
							anest.api[anest.cursor].iofs = (void *)(imports->FirstThunk + k * sizeof(IMAGE_THUNK_DATA32));
							anest.api[anest.cursor].libname = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,strlen(libName)+1);
							memmove(anest.api[anest.cursor++].libname,_strlwr(libName),strlen(libName));
							memset(thunks,0,sizeof(IMAGE_THUNK_DATA32));
							if(othunk)memset(othunk,0,sizeof(IMAGE_THUNK_DATA32));
							thunks++;
							if(othunk)othunk++;
							k++;
						}
					}
					memset(libName,0,strlen(libName));
					memset(imports,0,sizeof(IMAGE_IMPORT_DESCRIPTOR));
				}
			}
		}
		importRva = inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		if(bIAT)importRva += impBrw * sizeof(IMAGE_IMPORT_DESCRIPTOR);
		imports = (IMAGE_IMPORT_DESCRIPTOR*)(Rva2Raw(inh->FileHeader.NumberOfSections, ish, importRva)+exeMem);
		imports[0].Name = importRva + sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2;//including zeroed final descriptor
		imports[0].FirstThunk = imports[0].Name + (int)strlen(dllName) + 1;
		imports[0].OriginalFirstThunk = 0;
		imports[1].Characteristics = 0;
		imports[1].FirstThunk = 0;
		imports[1].ForwarderChain = 0;
		imports[1].Name = 0;
		imports[1].OriginalFirstThunk = 0;
		imports[1].TimeDateStamp = 0;
		memset(Rva2Raw(inh->FileHeader.NumberOfSections, ish, imports[0].Name) + exeMem, 0, strlen(dllName) + 1);
		memmove(Rva2Raw(inh->FileHeader.NumberOfSections, ish, imports[0].Name) + exeMem, dllName, strlen(dllName));
		imports[0].Characteristics = imports[0].FirstThunk;
		thunks = (IMAGE_THUNK_DATA32*)(Rva2Raw(inh->FileHeader.NumberOfSections, ish, imports[0].FirstThunk) + exeMem);
		thunks[0].u1.ForwarderString = imports[0].FirstThunk + sizeof(IMAGE_THUNK_DATA32) * 2;
		memset(Rva2Raw(inh->FileHeader.NumberOfSections, ish, thunks[0].u1.ForwarderString) + exeMem, 0, strlen(funcname) + 3);
		memmove(Rva2Raw(inh->FileHeader.NumberOfSections, ish, thunks[0].u1.ForwarderString) + exeMem + 2, funcname, strlen(funcname));
		inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = thunks[0].u1.ForwarderString + (int)strlen(funcname) + 3 - inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size += 7;
		inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size &= ~7;
		if(bIAT)importRva -= impBrw * sizeof(IMAGE_IMPORT_DESCRIPTOR);
		for(i=0;i<inh->FileHeader.NumberOfSections;i++)
		{
			if((int)ish[i].VirtualAddress <= importRva && importRva < (int)ish[i].VirtualAddress + (int)ish[i].Misc.VirtualSize)
			{
				ULONG_PTR offs = imports[0].FirstThunk + inh->OptionalHeader.ImageBase;
				ULONG_PTR epof = inh->OptionalHeader.ImageBase + inh->OptionalHeader.AddressOfEntryPoint;
				int ptr = Rva2Raw(inh->FileHeader.NumberOfSections, ish, importRva + inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
				((char *)exeMem)[ptr]=0xB8;
				memmove(&((char *)exeMem)[ptr+1],&offs,sizeof(offs));//mov eax,initialize
				((char *)exeMem)[sizeof(offs) + ptr + 1]=0x8B;//mov eax,[eax]
				((char *)exeMem)[sizeof(offs) + ptr + 2]=0x00;//
				((char *)exeMem)[sizeof(offs) + ptr + 3]=0xFF;//call eax
				((char *)exeMem)[sizeof(offs) + ptr + 4]=0xD0;//
				((char *)exeMem)[sizeof(offs) + ptr + 5]=0xB8;//mov eax
				memmove(&((char *)exeMem)[sizeof(offs) + ptr + 6],&epof,sizeof(epof));//mov eax,entry point
				((char *)exeMem)[sizeof(offs)*2 + ptr + 6]=0xFF;//jmp eax
				((char *)exeMem)[sizeof(offs)*2 + ptr + 7]=0xE0;//
				inh->OptionalHeader.AddressOfEntryPoint = importRva + inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
				ish[i].Characteristics |= IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_WRITE;
				inh->FileHeader.Characteristics |= 1;//PE_IMAGE_RELOCATION_STRIPPED
				break;
			}
		}
		printf("Done %d IAT entries\n",totaly);
	}
	return (ULONG_PTR)&anest;
}
///////////////////////////////////////////////////////////////////////////////////////////
ULONG_PTR ScanForApiCall64(char *exeMem, size_t fSize, char *dllName, BOOL bIAT)
{
	IMAGE_NT_HEADERS64* inh = (IMAGE_NT_HEADERS64*)(exeMem + ((IMAGE_DOS_HEADER*)exeMem)->e_lfanew);
	IMAGE_SECTION_HEADER* ish = IMAGE_FIRST_SECTION(inh);
	IMAGE_IMPORT_DESCRIPTOR *first, *imports = (IMAGE_IMPORT_DESCRIPTOR*)inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	LARGE_INTEGER *list = VirtualAlloc(0,fSize*8,MEM_COMMIT,PAGE_READWRITE);
	size_t total=0,i,enumerated=1,totaly=0,impBrw,impCnt=0,impRaw = imports?Rva2Raw(inh->FileHeader.NumberOfSections,ish,(DWORD)imports):0;
	QWORD lowlim = inh->OptionalHeader.ImageBase;
	QWORD highlim = inh->OptionalHeader.ImageBase + inh->OptionalHeader.SizeOfImage;
	IMAGE_THUNK_DATA64 *thunks=NULL,*othunk=NULL;
	char *funcname = "initialize";
	int importRva,found=0,needspace = sizeof(IMAGE_IMPORT_DESCRIPTOR) + sizeof(IMAGE_THUNK_DATA32) * 2 + strlen(dllName) + 1 + strlen(funcname) + 3 + 9;
	ULONG done=0;
	BYTE *res=NULL;
	anest.api = (api_list *)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(api_list)*1024);
	anest.totala = 1024;
	anest.cursor = 0;
	imports = (IMAGE_IMPORT_DESCRIPTOR*)Rva2Raw(inh->FileHeader.NumberOfSections, ish, (DWORD)imports);
	if(imports != (IMAGE_IMPORT_DESCRIPTOR*)0xFFFFFFFF)
	{
		first = imports = (IMAGE_IMPORT_DESCRIPTOR*)(exeMem + (ULONG)imports);
		while(first->Name)
		{
			impCnt++;
			first++;
		}
		if(bIAT)
		{
			IMAGE_IMPORT_DESCRIPTOR temp;
			size_t prevdll=1;
			impBrw = impCnt - ((needspace / sizeof(IMAGE_IMPORT_DESCRIPTOR)) + 1);
			for(i=impBrw;i<impCnt;i++)
			{
				char* lib = (char*)Rva2Raw(inh->FileHeader.NumberOfSections, ish, imports[i].Name);
				lib = lib + (ULONG)exeMem;
				if(strstr(lib,"d3dx"))
				{
					char *prevlib = (char *)imports[impBrw-prevdll].Name;
					prevlib = prevlib + (ULONGLONG)exeMem;
					//store d3dx series dll reference in previous
					memmove(&temp,&imports[i],sizeof(temp));
					//check previous dll references for d3dx dlls
					while(impBrw > prevdll && strstr(prevlib,"d3dx"))
					{
						prevdll++;
						prevlib = (char *)imports[impBrw-prevdll].Name;
						prevlib = prevlib + (ULONGLONG)exeMem;
					}
					//if we have a room for d3dx series dll in previous IAT references, we can replace it 
					if(prevdll == impBrw)
					{
						printf("Error in partial IAT encryption\n");
						exit(-15);
					}else
					{
						memmove(&imports[i],&imports[impBrw-prevdll],sizeof(temp));
						memmove(&imports[impBrw-prevdll],&temp,sizeof(temp));
					}
				}
			}
		}
		for(i=0;i<impCnt;i++,imports++)
		{
			char* libName = (char*)Rva2Raw(inh->FileHeader.NumberOfSections, ish, imports->Name);
			int k = 0;
			libName = libName + (ULONG)exeMem;
			thunks = (IMAGE_THUNK_DATA64 *)Rva2Raw(inh->FileHeader.NumberOfSections,ish,imports->FirstThunk);
			if(imports->OriginalFirstThunk)othunk = (IMAGE_THUNK_DATA64 *)Rva2Raw(inh->FileHeader.NumberOfSections,ish,imports->OriginalFirstThunk);
			if(thunks)
			{
				thunks = (IMAGE_THUNK_DATA64 *)(exeMem + (ULONG)thunks);
				if(othunk)othunk = (IMAGE_THUNK_DATA64 *)(exeMem + (ULONG)othunk);
				if(!bIAT || impBrw <= i)
				{
					if(imports->TimeDateStamp && othunk)
					{
						while(othunk->u1.AddressOfData)
						{
							char* curName = (char *)Rva2Raw(inh->FileHeader.NumberOfSections, ish, (int)othunk->u1.ForwarderString);
							if(IMAGE_SNAP_BY_ORDINAL64(othunk->u1.Ordinal))
							{
								curName = (char *)othunk->u1.Ordinal;
							}else if(curName != (char *)0xFFFFFFFF)
							{
								curName = (ULONG)exeMem + curName;
							}else
							{	
								othunk++;
								thunks++;
								continue;
							}
							totaly++;
							if(anest.cursor == anest.totala)
							{
								api_list *temp = (api_list *)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(api_list) * anest.totala * 2);
								memmove(temp,anest.api,sizeof(api_list) * anest.cursor);
								HeapFree(GetProcessHeap(),0,anest.api);
								anest.totala *= 2;
								anest.api = temp;
							}
							anest.api[anest.cursor].dll_hash = CalcHash(_strlwr(libName));
							if(IMAGE_SNAP_BY_ORDINAL64(othunk->u1.Ordinal))
							{
								anest.api[anest.cursor].api_hash = (int)othunk->u1.Ordinal;
							}else
							{
								anest.api[anest.cursor].api_hash = CalcHash(&curName[2]);
								memset(curName,0,strlen(&curName[2])+2);
							}
							anest.api[anest.cursor].iofs = (void *)(imports->FirstThunk + k * sizeof(IMAGE_THUNK_DATA64));
							anest.api[anest.cursor].libname = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,strlen(libName)+1);
							memmove(anest.api[anest.cursor++].libname,_strlwr(libName),strlen(libName));
							memset(thunks,0,sizeof(IMAGE_THUNK_DATA64));
							memset(othunk,0,sizeof(IMAGE_THUNK_DATA64));
							thunks++;
							othunk++;
							k++;
						}
					}else
					{
						while(thunks->u1.AddressOfData)
						{
							char* curName = (char *)Rva2Raw(inh->FileHeader.NumberOfSections, ish, (int)thunks->u1.ForwarderString);
							if(IMAGE_SNAP_BY_ORDINAL64(thunks->u1.Ordinal))
							{
								curName = (char *)thunks->u1.Ordinal;
							}else if(curName != (char *)0xFFFFFFFF)
							{
								curName = (ULONG)exeMem + curName;
							}else
							{ 
								thunks++;
								continue;
							}
							totaly++;
							if(anest.cursor == anest.totala)
							{
								api_list *temp = (api_list *)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(api_list) * anest.totala * 2);
								memmove(temp,anest.api,sizeof(api_list) * anest.cursor);
								HeapFree(GetProcessHeap(),0,anest.api);
								anest.totala *= 2;
								anest.api = temp;
							}
							anest.api[anest.cursor].dll_hash = CalcHash(_strlwr(libName));
							if(IMAGE_SNAP_BY_ORDINAL64(thunks->u1.Ordinal))
							{
								anest.api[anest.cursor].api_hash = (int)thunks->u1.Ordinal;
								anest.api[anest.cursor].api_hash |= 0x80000000;
							}else
							{
								anest.api[anest.cursor].api_hash = CalcHash(&curName[2]);
								memset(curName,0,strlen(&curName[2])+2);
							}
							anest.api[anest.cursor].iofs = (void *)(imports->FirstThunk + k * sizeof(IMAGE_THUNK_DATA64));
							anest.api[anest.cursor].libname = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,strlen(libName)+1);
							memmove(anest.api[anest.cursor++].libname,_strlwr(libName),strlen(libName));
							memset(thunks,0,sizeof(IMAGE_THUNK_DATA64));
							if(othunk)memset(othunk,0,sizeof(IMAGE_THUNK_DATA64));
							thunks++;
							if(othunk)othunk++;
							k++;
						}
					}
					memset(libName,0,strlen(libName));
					memset(imports,0,sizeof(IMAGE_IMPORT_DESCRIPTOR));
				}
			}
		}
		importRva = inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		if(bIAT)importRva += impBrw * sizeof(IMAGE_IMPORT_DESCRIPTOR);
		imports = (IMAGE_IMPORT_DESCRIPTOR*)(Rva2Raw(inh->FileHeader.NumberOfSections, ish, inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)+exeMem);
		imports[0].Name = importRva + sizeof(IMAGE_IMPORT_DESCRIPTOR) * 2;//including zeroed final descriptor
		imports[0].FirstThunk = imports[0].Name + (int)strlen(dllName) + 1;
		imports[1].Characteristics = 0;
		imports[1].FirstThunk = 0;
		imports[1].ForwarderChain = 0;
		imports[1].Name = 0;
		imports[1].OriginalFirstThunk = 0;
		imports[1].TimeDateStamp = 0;
		memset(Rva2Raw(inh->FileHeader.NumberOfSections, ish, imports[0].Name) + exeMem, 0, strlen(dllName) + 1);
		memmove(Rva2Raw(inh->FileHeader.NumberOfSections, ish, imports[0].Name) + exeMem, dllName, strlen(dllName));
		imports[0].Characteristics = imports[0].FirstThunk;
		thunks = (IMAGE_THUNK_DATA64*)(Rva2Raw(inh->FileHeader.NumberOfSections, ish, imports[0].FirstThunk) + exeMem);
		thunks[0].u1.ForwarderString = imports[0].FirstThunk + sizeof(IMAGE_THUNK_DATA64) * 2;
		memset(Rva2Raw(inh->FileHeader.NumberOfSections, ish, (int)thunks[0].u1.ForwarderString) + exeMem, 0, (int)strlen(funcname) + 3);
		memmove(Rva2Raw(inh->FileHeader.NumberOfSections, ish, (int)thunks[0].u1.ForwarderString) + exeMem + 2, funcname, (int)strlen(funcname));
		inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = (DWORD)(thunks[0].u1.ForwarderString + strlen(funcname) + 3 - importRva);
		inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size += 7;
		inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size &= ~7;
		inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = imports[0].Name + (int)strlen(dllName) + 1;
		inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = sizeof(IMAGE_THUNK_DATA64) * 4;
		if(bIAT)importRva -= impBrw * sizeof(IMAGE_IMPORT_DESCRIPTOR);
		for(i=0;i<(size_t)(inh->FileHeader.NumberOfSections-1);i++)
		{
			if((int)ish[i].VirtualAddress <= importRva && importRva < (int)ish[i].VirtualAddress + (int)ish[i].Misc.VirtualSize)
			{
				unsigned __int64 offs = (unsigned __int64)imports[0].FirstThunk + inh->OptionalHeader.ImageBase;
				unsigned __int64 epof = inh->OptionalHeader.ImageBase + (unsigned __int64)inh->OptionalHeader.AddressOfEntryPoint;
				int ptr = Rva2Raw(inh->FileHeader.NumberOfSections, ish, importRva + inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
				((char *)exeMem)[ptr+0]=0x48;//REX
				((char *)exeMem)[ptr+1]=0xB8;//mov rax,
				memmove(&((char *)exeMem)[ptr+2],&offs,sizeof(offs));//mov rax,initialize
				((char *)exeMem)[sizeof(offs) + ptr + 2]=0x48;//mov rax,[rax]
				((char *)exeMem)[sizeof(offs) + ptr + 3]=0x8B;//
				((char *)exeMem)[sizeof(offs) + ptr + 4]=0x00;//
				((char *)exeMem)[sizeof(offs) + ptr + 5]=0xFF;//call rax
				((char *)exeMem)[sizeof(offs) + ptr + 6]=0xD0;//
				((char *)exeMem)[sizeof(offs) + ptr + 7]=0x48;//mov rax
				((char *)exeMem)[sizeof(offs) + ptr + 8]=0xB8;//
				memmove(&((char *)exeMem)[sizeof(offs) + ptr + 9],&epof,sizeof(epof));//mov rax,entry point
				((char *)exeMem)[sizeof(offs)*2 + ptr + 9]=0xFF;//jmp rax
				((char *)exeMem)[sizeof(offs)*2 + ptr + 10]=0xE0;//
				inh->OptionalHeader.AddressOfEntryPoint = importRva + inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
				ish[i].Characteristics |= IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_WRITE;
				inh->FileHeader.Characteristics |= 1;//PE_IMAGE_RELOCATION_STRIPPED
				//memmove(&ish[i].Name,".text",6);
				found++;
				break;
			}
		}
		printf("Done %d IAT entries\n",totaly);
	}
	return (ULONG_PTR)&anest;
}
///////////////////////////////////////////////////////////////////////////////////////////
sign_cache *InitializePackerDetection(ULONG *TotalSigns)
{
	ULONG i,k,fSize=0;
	char *signs;
	HMODULE gInst = GetModuleHandle(NULL);
	sign_cache *sc=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(sign_cache));
	HRSRC aResourceH;
	HGLOBAL aResourceHGlobal;
	aResourceH = FindResourceW(gInst, (LPCWSTR)54321, (LPCWSTR)12345);
	if(!aResourceH)return NULL;
	aResourceHGlobal = LoadResource(gInst, aResourceH);
	if(!aResourceHGlobal)return NULL;
	fSize = SizeofResource(gInst, aResourceH);
	signs = (unsigned char *)LockResource(aResourceHGlobal);
	if(!signs)return NULL;
	memset(sc,0,sizeof(sign_cache));
	*TotalSigns=0;
	InitializeListHead(&sc->n);
	for(i=0;i<fSize;)
	{
		unsigned char semiByte=0;
		unsigned char valByte=0;
		unsigned char *signStart,*signEnd,*nameStart,*nameEnd,*lineEnd;
		size_t signTotalCount=0,valuedCount=0,signCountOffset,wildcardCount=0,previousMode=WILDCARD,lenName,lenSign;
		psc ps=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(sign_cache));
		nameStart=signs+i+1;
		nameEnd=strstr(nameStart+1,"=");
		signStart=nameEnd;
		signEnd=signStart?strstr(signStart,"]"):NULL;
		lineEnd=strstr(signs+i,"]\r\n");
		lineEnd=lineEnd?lineEnd+3:NULL;
		lenName=(ULONG)(nameEnd-(ULONG)nameStart+1);
		lenSign=signEnd-signStart;
		if(!((ULONG)lineEnd & (ULONG)signEnd & (ULONG)signStart & (ULONG)nameStart))break;
		signStart++;
		memset(ps,0,sizeof(sign_cache));
		ps->name=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,lenName);
		ps->sign=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,lenSign*2);
		memset(ps->name,0,lenName);
		memset(ps->sign,0,lenSign);
		memmove(ps->name,signs+i+1,lenName-1);
		for(k=0;k<lenSign;k++)
		{
			if(!signTotalCount)signCountOffset=signTotalCount,signTotalCount+=2;
			if(signStart[k]==':')
			{
				if(previousMode!=WILDCARD)
				{
					if(valuedCount)
					{
						*((USHORT *)&ps->sign[signCountOffset])=(USHORT)valuedCount|VALUED;
						ps->slen+=(int)valuedCount;
						signCountOffset=signTotalCount,signTotalCount+=2;
					}
					previousMode=WILDCARD;
					valuedCount=0;
				}
				else if(semiByte)wildcardCount++;
			}else if(signStart[k]>='a' && signStart[k]<='f')
			{
				valByte|=(signStart[k]-'a'+0x0A)<<(4-(semiByte<<2));
			}else if(signStart[k]>='A' && signStart[k]<='F')
			{
				valByte|=(signStart[k]-'A'+0x0A)<<(4-(semiByte<<2));
			}else if(signStart[k]>='0' && signStart[k]<='9')
			{
				valByte|=(signStart[k]-'0')<<(4-(semiByte<<2));
			}else if(signStart[k]==' ')continue;
			if(signStart[k]!=':')
			{
				if(previousMode!=VALUED)
				{
					if(wildcardCount)
					{
						*((USHORT *)&ps->sign[signCountOffset])=(USHORT)wildcardCount|WILDCARD;
						ps->slen+=(int)wildcardCount;
						signCountOffset=signTotalCount,signTotalCount+=2;
					}
					wildcardCount=0;
					previousMode=VALUED;
				}else
				{ 
					if(semiByte)
					{
						ps->sign[signTotalCount++]=valByte,valByte=0,valuedCount++;
					}
				}
			}
			semiByte=-(--semiByte);
		}
		if(valuedCount)*((USHORT *)&ps->sign[signCountOffset])=(USHORT)valuedCount|VALUED,ps->slen+=(int)valuedCount;
		else *((USHORT *)&ps->sign[signCountOffset])=(USHORT)wildcardCount|WILDCARD,ps->slen+=(int)wildcardCount;
		InsertTailList(&sc->n,&ps->n);
		*TotalSigns+=1;
		i=(int)(lineEnd-signs);
	}
	UnlockResource(signs);
	FreeResource(signs);
	return sc;
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////
BYTE *ScanForPacker(psc sc,BYTE *BaseAddr, BYTE *EP,size_t fSize, ULONG TotalSignsCount)
{
	ULONG InSignOffset,i,k,n,l,len;
	psc csc=sc;
    BYTE *RT = NULL;
	for(InSignOffset=i=0;i<TotalSignsCount;i++,InSignOffset=0)
	{
		csc=(psc)GetHeadList(&csc->n);
		for(k=0;k<min(csc->slen,fSize);k++)
		{
			if(*((USHORT *)&csc->sign[InSignOffset]) & WILDCARD)
			{
				k+=((*((USHORT *)&csc->sign[InSignOffset]))^WILDCARD),InSignOffset+=2;
				k--;
			}else
			{ 
				for(n=0,l=*((USHORT *)&csc->sign[InSignOffset])^VALUED,InSignOffset+=2;n<l && k<min(csc->slen,fSize);n++,InSignOffset++,k++)
				{
					if(EP[k]!=csc->sign[InSignOffset])goto ScanNextSignature;
				}
				k--;
			}
		}
		RT=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,(len=(int)strlen(csc->name)+1));
		memmove(RT,csc->name,len);
		break;
ScanNextSignature:
		;
	}
	return RT;
}
///////////////////////////////////////////////////////////////////////////////////////
BOOL IsPacked (char *pStreamData, UINT64 u64StreamSize)
{
	if(CheckImage(pStreamData, (UINT)u64StreamSize, NULL,NULL))
	{
			IMAGE_NT_HEADERS* inh = (IMAGE_NT_HEADERS*)(pStreamData + ((IMAGE_DOS_HEADER*)pStreamData)->e_lfanew);
			IMAGE_NT_HEADERS64* inh2 = (IMAGE_NT_HEADERS64*)(pStreamData + ((IMAGE_DOS_HEADER*)pStreamData)->e_lfanew);
			IMAGE_SECTION_HEADER* ish = (IMAGE_SECTION_HEADER*)(pStreamData + ((IMAGE_DOS_HEADER*)pStreamData)->e_lfanew + inh->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + 4);
			BOOL ISAMD64 = inh->FileHeader.Machine == 0x8664;
			BYTE *packer,*EP=(BYTE *)Rva2Raw(inh->FileHeader.NumberOfSections,ish,ISAMD64?inh2->OptionalHeader.AddressOfEntryPoint:inh->OptionalHeader.AddressOfEntryPoint);
			if((ISAMD64 && inh2->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress) || 
				(!ISAMD64 && inh->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress))
			{
				printf(".NET CLR IMAGE\n");
				return TRUE;
			}
			if(!packdetect)packdetect = InitializePackerDetection(NULL, &TotalSigns);
			packer = ScanForPacker(packdetect,pStreamData,(ULONG)EP+pStreamData,(UINT)u64StreamSize,TotalSigns);
			if(packer)
			{
				printf("%s\n",packer);
				return TRUE;
			}
	}
	return FALSE;
}
///////////////////////////////////////////////////////////////////////////////////////////
DWORD Rva2Raw(short NumOfSections, IMAGE_SECTION_HEADER* FSH, int rva)
{
	int i;
	for (i = 0; i < NumOfSections; i++)
	{
		if (rva >= (int)FSH[i].VirtualAddress && (int)FSH[i].VirtualAddress + (int)FSH[i].Misc.VirtualSize > rva)
		{
			return FSH[i].PointerToRawData + (rva - (int)FSH[i].VirtualAddress);
		}
	}
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
BOOL CheckImage(char *BaseAddr, UINT64 fSize, void *AvSelLpVirusId, LPWSTR FileName)
{
	if(!((BaseAddr[0]=='M' && BaseAddr[1]=='Z') || (BaseAddr[0]=='Z' && 
	BaseAddr[1]=='M')) || !((ULONG)((IMAGE_DOS_HEADER*)BaseAddr)->e_lfanew < fSize) || 
	!(((IMAGE_NT_HEADERS*)(BaseAddr + ((IMAGE_DOS_HEADER*)BaseAddr)->e_lfanew))->Signature=='EP'))
	{
		return TRUE;
	}
	return FALSE;
}
///////////////////////////////////////////////////////////////////////////////////////////
int __cdecl compareApi(const void *elem1, const void *elem2)
{
	if ( ((api_list *)elem1)->dll_hash < ((api_list *)elem2)->dll_hash) return -1;
	else if (((api_list *)elem1)->dll_hash > ((api_list *)elem2)->dll_hash) return 1;
    else return 0;
}
///////////////////////////////////////////////////////////////////////////////////////////
void InitRandomStruct(R_RANDOM_STRUCT *randomStruct)
{
  unsigned int seedDword = 0;
  unsigned int bytesNeeded;
  seedDword = (unsigned int)__rdtsc();
  
  R_RandomInit (randomStruct);
  
  while (1) 
  {
    R_GetRandomBytesNeeded (&bytesNeeded, randomStruct);
    if (bytesNeeded == 0)
      break;
    
    R_RandomUpdate (randomStruct, (unsigned char *)&seedDword, 4);
  }
}
///////////////////////////////////////////////////////////////////////////////////////////
