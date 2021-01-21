#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>
#include "..\\personifier\\personifier.h"
#include "..\\sqlite3static\\sqlite3.h"
#pragma warning(disable:4996)
__cdecl wmain( int argc, wchar_t *argv[ ], wchar_t *envp[ ] )
{
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	int error;
	HANDLE hPipe,hBin;
    LARGE_INTEGER frequency, start_counter, end_counter;
/*
#if _DEBUG
	LPWSTR param0=L"client.exe";
	LPWSTR param1=L"..\\fs.preload.exe";
	LPWSTR param2=L"..\\fs.bin";
	LPWSTR param3=L"fs_control_pipe";
	LPWSTR testCmdLine[]={param0,param1,param2,param3};
	argv = testCmdLine;
	argc=4;
#endif 
*/
	if(argc>3)
	{
		void *lpBin;
		WCHAR pipename[MAX_PATH];
		ZeroMemory(pipename,sizeof(pipename));
		wcscat(pipename,L"\\\\.\\\\pipe\\");
		if((wcslen(argv[3]) + wcslen(pipename)) > MAX_PATH)
		{
			printf("Pipename too long, max length is 250\n");
			exit(1);
		}
		wcscat(pipename,argv[3]);
		hPipe = CreateNamedPipe(pipename,PIPE_ACCESS_DUPLEX,PIPE_TYPE_BYTE,2,0,0,0,NULL);
		if(hPipe != INVALID_HANDLE_VALUE)
		{
			DWORD NBW,NBR=1,reqSize;
			int bWritten, bRead,fConnected;
			char *request=NULL;
			int stage=1;
			wchar_t cd[MAX_PATH];
			GetCurrentDirectory(MAX_PATH,cd);
			ZeroMemory(&si,sizeof(si));
			si.cb = sizeof(STARTUPINFO);
			if(!CreateProcessW((LPCWSTR)argv[1],NULL,NULL,NULL,0,0,NULL,cd,&si,&pi))
			{
				error = GetLastError();
				printf("error creating process %d\n",error);
				exit(-1);
			}
			fConnected = ConnectNamedPipe(hPipe, NULL)?TRUE:(GetLastError()==ERROR_PIPE_CONNECTED); 
			if(fConnected)
			{
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
                        while(NBR)
						{
							bRead = ReadFile(hPipe,&reqSize,4,&NBR,NULL);
							if(!bRead || !NBR)
							{
								printf("IO error 0 from protect.dll\n");
								HeapFree(GetProcessHeap(),0,lpBin);
								exit(-2);
							}	
							request = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,reqSize);
							bRead = ReadFile(hPipe,request,reqSize,&NBR,NULL);

                            // measure processing time in personifier.dll
                            QueryPerformanceCounter(&start_counter);
                            error = process(request,(size_t)reqSize,(const unsigned char *)&request,4,lpBin,fSize,(unsigned char **)&lpRes,&dwRes);
                            QueryPerformanceCounter(&end_counter);
                            QueryPerformanceFrequency(&frequency);
                            printf("personifier processing time is %1.3f seconds\n", 
                                (double)(end_counter.QuadPart - start_counter.QuadPart) / frequency.QuadPart);

							if(!error)
							{
								bWritten = WriteFile(hPipe,&dwRes,4,&NBW,NULL);
								if(!bWritten || !NBW)
								{
									free(lpRes);
									printf("IO error 1 to protect.dll\n");
									HeapFree(GetProcessHeap(),0,lpBin);
									exit(-3);
								}
								bWritten = WriteFile(hPipe,lpRes,(DWORD)dwRes,&NBW,NULL);
								if(!bWritten || !NBW)
								{
									free(lpRes);
									printf("IO error 2 to protect.dll\n");
									HeapFree(GetProcessHeap(),0,lpBin);
									exit(-4);
								}
							}else
							{
								printf("Error 1 while processing protection data\n");
								HeapFree(GetProcessHeap(),0,lpBin);
								exit(-5);
							}
							CloseHandle(hPipe);
							hPipe = NULL;
							HeapFree(GetProcessHeap(),0,request);
							break;
						}
					}else
					{
						printf("Error reading protection data file\n");
						HeapFree(GetProcessHeap(),0,lpBin);
						exit(-9);
					}
				}else
				{
					printf("Error opening protection database file\n");
					exit(-10);
				}
			}else
			{
				printf("Error connecting pipe\n");
				exit(-11);
			}
		}else
		{
			printf("Error creating pipe\n");
			exit(-12);
		}
	}else printf("Usage:\nclient.exe [*.preload.exe] [*.bin] [pipename]\nwhere\n[*.preload.exe] - path to launching exe, mandatory\n[*.db] - path to protection data file, mandatory\n[pipename] - name of implemented in *.preload.exe name of pipe\n");                                        
	return 0;
}
////////////////////////////////////////////////////////////////////////////////////////
