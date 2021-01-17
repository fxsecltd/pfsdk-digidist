@echo off

@set currentDir=%~dp0
@set requestDir=%CD%
@CD %currentDir%

@set PROTECT_MODE=0
@set first_param="true"

:loop_start
@IF "%~1"=="" (
  @GOTO end_loop
)

@FOR /F "usebackq tokens=1,2 delims=:" %%i in ('%~1') do (
  @IF "%%i"=="n" (
    @set NAME=%%j
  )
  @IF "%%i"=="pm" (
    @set PROTECT_MODE=%%j
  )
  @IF "%%i"=="pn" (
    @set PIPE_NAME=%%j
  )
  @IF "%%i"=="help" (
    @IF %first_param%=="true" (
      IF "%~2"=="" (
        @GOTO help
      )
    )
  )

  @IF "%%j"=="" (
    @REM =========== Если всего был передан один параметр, то считаем, что он определяет название защищаемого модуля =============
    @IF %first_param%=="true" (
      IF "%~2"=="" (
        @set NAME=%%i
        @GOTO end_loop
      )
    )

    @echo Not defined value for key %%i
    @GOTO clean_on_error
  )

  @set first_param="false"
  @shift
  @GOTO loop_start
)

:end_loop

@IF "%NAME%"=="" (
  @echo Don't defined the filename that need to apply protection
  @GOTO end
)

@IF NOT EXIST %NAME%.exe (
  @GOTO filename_absence
)

@IF NOT DEFINED PIPE_NAME (
  @SET PIPE_NAME=%NAME%_pipe
)

@SET DESTDIR=out\%NAME%
@SET DEST_DIR_FILENAME=%DESTDIR%\%NAME%
@SET TMP_DIR=tmp\%NAME%
@SET TMP_DIR_FILENAME=%TMP_DIR%\%NAME%
@SET NAME_ORIGINAL=%NAME%.original.exe


@IF EXIST "%TMP_DIR%" (
  @RMDIR /S /Q "%TMP_DIR%"
)
@MKDIR "%TMP_DIR%"

@IF EXIST "%DESTDIR%" ( 
  @RMDIR /S /Q "%DESTDIR%"
)
@MKDIR "%DESTDIR%"

@copy %NAME%.exe "%DESTDIR%\%NAME_ORIGINAL%"
@copy libprotect.dll.original "%TMP_DIR_FILENAME%".dll
@copy protector.exe "%TMP_DIR%"\protector.exe
@copy %NAME%.exe "%TMP_DIR_FILENAME%".exe
@copy libprotect.map "%TMP_DIR%"\libprotect.map

@CD %TMP_DIR%
protector.exe %NAME%.exe %NAME%.protected.exe %NAME%.dll %NAME%.bin %PIPE_NAME% %PROTECT_MODE%
@CD %currentDir%

@IF %ERRORLEVEL% GEQ 1 (
  @echo protector.exe did finish with error code=%ERRORLEVEL%
  @GOTO clean_on_error
)

@move %TMP_DIR_FILENAME%.dll %TMP_DIR%\libprotect.dll
vmprotect\vmprotect_con %TMP_DIR%\libprotect.dll "%TMP_DIR_FILENAME%".dll -pf "%currentDir%"libprotect.vmp

@move "%TMP_DIR_FILENAME%".dll "%DEST_DIR_FILENAME%".dll
@move "%TMP_DIR_FILENAME%".protected.exe "%DEST_DIR_FILENAME%".exe
@move "%TMP_DIR_FILENAME%".bin "%DEST_DIR_FILENAME%".bin

@RMDIR /S /Q "%TMP_DIR%"

@GOTO end

:filename_absence
(
  @echo File with a name %NAME%.exe is absence
  @GOTO clean_on_error
)

:clean_on_error
(
  IF EXIST "%TMP_DIR%" (
    @RMDIR /S /Q "%TMP_DIR%"
  )
  @IF EXIST "%DESTDIR%" ( 
    @RMDIR /S /Q "%DESTDIR%"
  )
  @GOTO end   
)

:help
(
  @echo *************************************************************************
  @echo * Use pairs key:value that you need pass into the script                *
  @echo * n:name        - set name of execution file to apply protection        *
  @echo * [pn:pipename] - set name of the pipe. By default set to the name_pipe *
  @echo * [pm:number]   - set protect mode. By default set to 0                 *
  @echo *                                                                       * 
  @echo * If you need pass into the script only name of execution file, you may *
  @echo * omit key "n" preceding a "name"                                       *
  @echo *************************************************************************
  @GOTO end
)

:end
@CD "%requestDir%"
@echo on