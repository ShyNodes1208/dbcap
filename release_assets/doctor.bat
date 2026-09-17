@echo off
setlocal EnableExtensions
REM DBCAP doctor launcher (ASCII only)
REM No delayed expansion; no paren blocks expanding user paths.

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

if not exist "%PY%" goto no_python

"%PY%" -I -m dbcap doctor -o "%HOME%\output"
set "RC=%ERRORLEVEL%"
exit /b %RC%

:no_python
echo [ERROR] Built-in Python runtime not found.
echo Check: runtime\python\python.exe
echo Overall: FAIL
exit /b 1
