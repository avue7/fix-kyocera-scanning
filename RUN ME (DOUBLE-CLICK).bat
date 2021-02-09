@echo off

::powershell Set-ExecutionPolicy Bypass

::COMMENT: if you need to find absolute path
::for /f "delims=" %%a in ('powershell echo "(Get-Childitem -Path C:\*\*\Desktop\*\FIX_SCAN.ps1 | Select-Object FullName)"') do set "ScriptPath=%%a"

::powershell -Command 'Start-Process Powershell -ExecutionPolicy Bypass -File "%ScriptPath%" -Verb RunAs'

Powershell -ExecutionPolicy Bypass -File "%~dp0SCAN_QUICK_FIX.ps1" -Verb RunAs

::Powershell -ExecutionPolicy Bypass -Command 'Start-Process Powershell -Verb RunAs'

::cmd /k