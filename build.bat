@echo off
setlocal
echo ===================================================
echo   Desynq - 1-Click Production Build Script
echo ===================================================

echo [1/3] Building frontend assets...
cd ui\frontend
call npm install
call npm run build
if %errorlevel% neq 0 (
    echo [ERROR] Frontend build failed!
    cd ..\..
    pause
    exit /b 1
)
cd ..\..

echo [2/3] Compiling standalone Desynq (pure GUI, 0 terminal)...
go build -ldflags="-H windowsgui -s -w" -tags desktop,production -o desynq.exe ./ui
if %errorlevel% neq 0 (
    echo [ERROR] desynq.exe build failed!
    pause
    exit /b 1
)

echo [3/3] Building installer (Desynq-Setup.exe)...
set MAKENSIS_CMD="C:\Program Files (x86)\NSIS\makensis.exe"
if not exist %MAKENSIS_CMD% set MAKENSIS_CMD=makensis
%MAKENSIS_CMD% build\installer.nsi >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Desynq-Setup.exe built successfully!
) else (
    echo [NOTE] NSIS not found or skipped. Standalone desynq.exe is ready.
)

echo ===================================================
echo   BUILD SUCCESSFUL!
echo   Outputs:
echo     - desynq.exe        (Standalone GUI Application)
if exist Desynq-Setup.exe echo     - Desynq-Setup.exe  (1-Click Windows Installer)
echo ===================================================
