@echo off
setlocal

set "SRCDIR=%~dp0src"
set "OUTDIR=%~dp0out"
set "PLUGNAME=tc_s3_plugin"

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

set "GCC=D:\05_tools\mingw64\bin\gcc.exe"

if not exist "%GCC%" (
    echo [ERROR] gcc not found: %GCC%
    pause
    exit /b 1
)

echo [BUILD] %GCC%
"%GCC%" -O2 -Wall -DUNICODE -D_UNICODE -D_WIN32_WINNT=0x0601 -m64 -shared "%SRCDIR%\plugin.c" "%SRCDIR%\aws_s3.c" "%SRCDIR%\plugin.def" -o "%OUTDIR%\%PLUGNAME%.wfx64" -lwinhttp -lbcrypt -lshlwapi -lshell32 -Wl,--kill-at

if %ERRORLEVEL%==0 (
    echo [OK] %OUTDIR%\%PLUGNAME%.wfx64
) else (
    echo [FAIL] Build failed.
    pause
    exit /b 1
)

pause
