@echo off
REM Simple wrapper to run the PowerShell script in Windows
setlocal
pushd %~dp0
if exist .venv\Scripts\python.exe (
  powershell -ExecutionPolicy Bypass -File "%~dp0run_dev.ps1"
) else (
  echo Virtual environment not found. Creating and running via PowerShell.
  powershell -ExecutionPolicy Bypass -File "%~dp0run_dev.ps1"
)
popd
endlocal
