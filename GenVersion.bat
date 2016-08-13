REM
REM Automatically generate version.h based on version.h.in for Windows
REM The version string comes from VERSION
REM @echo off
REM

setlocal enableextensions disabledelayedexpansion

set "search=%%%%LIBPCAP_VERSION%%%%"
set /p replace=<%0\..\VERSION

set "inputTextFile=%0\..\version.h.in"
set "outputTextFile=%0\..\version.h"

del "%outputTextFile%" 2>nul

for /f "delims=" %%i in ('type "%inputTextFile%"' ) do (
	set "line=%%i"
	setlocal enabledelayedexpansion
	set "line=!line:%search%=%replace%!"
	>>"%outputTextFile%" echo(!line!
	endlocal
)

echo version.h generated
