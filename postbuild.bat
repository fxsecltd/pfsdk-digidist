echo %1
cd %1
copy ..\libprotect.dll.vmp
copy libprotect.dll winrar.dll
protector.exe ..\winrar.exe ..\winrar.preload.exe winrar.dll ..\winrar.bin winrar_control_pipe 8
REM move winrar.exe.dll libprotect.dll
REM ..\vmprotect\vmprotect_con libprotect.dll.vmp 
REM move libprotect.vmp.dll winrar.dll
copy /y personifier.dll ..\personifier.dll
copy /y winrar.dll ..\winrar.dll
copy /y client.exe ..\client.exe

REM 7C917CB2 -> 475038