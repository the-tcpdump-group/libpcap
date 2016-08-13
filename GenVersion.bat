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

echo Abuot to try to remove %3
if exist %3 del %3 2>nul
echo Removed %3 if it exists

for /f "delims=" %%i in ('type %1' ) do (
	set "line=%%i"
	setlocal enabledelayedexpansion
	set "line=!line:%search%=%replace%!"
	>>%2 echo(!line!
	endlocal
)

echo version.h generated
