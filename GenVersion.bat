REM
REM Automatically generate version.h based on version.h.in for Windows
REM The version string comes from VERSION
REM @echo off
REM

setlocal enableextensions disabledelayedexpansion

set "search=%%%%LIBPCAP_VERSION%%%%"
set /p replace=<%1

set "inputTextFile=%2"
set "outputTextFile=%3"

echo Abuot to try to remove "%outputTextFile%"
if exist "%outputTextFile%" del "%outputTextFile%" 2>nul
echo Removed "%outputTextFile%" if it exists

echo About to try to type "%inputTextFile%"
type "%inputTextFile%"
echo typed "%inputTextFile%"
for /f "delims=" %%i in ('type "%inputTextFile%"' ) do (
	set "line=%%i"
	setlocal enabledelayedexpansion
	set "line=!line:%search%=%replace%!"
	>>"%outputTextFile%" echo(!line!
	endlocal
)

echo version.h generated
