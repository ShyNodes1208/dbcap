@echo off
setlocal EnableExtensions
REM DBCAP V1 Offline Launcher (ASCII only)
REM Thin launcher: no paren IF-blocks that expand user paths (R15).
REM Exit codes from DBCAP:
REM   0 = analysis OK, no blocking capture-quality issue
REM   1 = program failure
REM   2 = analysis OK, but capture quality degraded

REM Delayed expansion OFF so paths containing ! are not reinterpreted.
set "HOME=%~dp0"
set "HOME=%HOME:~0,-1%"
set "DBCAP_HOME=%HOME%"
set "PY=%HOME%\runtime\python\python.exe"
set "TSHARK_BUNDLE=%HOME%\tools\tshark\tshark.exe"
set "RC=1"

if exist "%TSHARK_BUNDLE%" set "DBCAP_TSHARK=%TSHARK_BUNDLE%"
set "PATH=%HOME%\tools\tshark;%PATH%"
set "PYTHONNOUSERSITE=1"
set "PYTHONPATH="

if /I "%~1"=="doctor" goto do_doctor
if "%~1"=="" goto usage
if "%~2"=="" goto usage
if not exist "%PY%" goto no_python

REM Default output: HOME\output\<pcap_stem>_YYYYMMDD_HHMMSS
REM Optional 3rd arg overrides. No IF (...) blocks around paths.
for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set "TS=%%i"
set "OUT=%HOME%\output\%~n1_%TS%"
if not "%~3"=="" set "OUT=%~3"

echo DBCAP Home : %HOME%
echo PCAP       : %~1
echo Port       : %~2
echo Output     : %OUT%
echo.

"%PY%" -I -m dbcap -f "%~1" -p "%~2" -o "%OUT%"
set "RC=%ERRORLEVEL%"
exit /b %RC%

:do_doctor
call "%HOME%\doctor.bat"
set "RC=%ERRORLEVEL%"
exit /b %RC%

:no_python
echo [ERROR] Built-in Python runtime not found.
echo Check: runtime\python\python.exe
echo Run: doctor.bat
exit /b 1

:usage
echo Usage:
echo   run.bat ^<pcap_file^> ^<db_port^> [output_dir]
echo   run.bat doctor
echo.
echo Examples:
echo   run.bat H:\case\2.pcap 5236
echo   run.bat input\case01.pcap 5236
exit /b 1
