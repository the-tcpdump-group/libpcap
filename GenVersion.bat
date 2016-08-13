REM
REM Automatically generate version.h based on version.h.in for Windows
REM The version string comes from VERSION
REM @echo off
REM

setlocal enableextensions disabledelayedexpansion

set "search=%%%%LIBPCAP_VERSION%%%%"
set /p replace=<%0\%1

set "inputTextFile=%0\%2"
echo inputTextFile:
echo %inputTextFile%
set "outputTextFile=%0\%3"
echo outputTextFile:
echo %outputTextFile%

del "%outputTextFile%" 2>nul

for /f "delims=" %%i in ('type "%inputTextFile%"' ) do (
	set "line=%%i"
	setlocal enabledelayedexpansion
	set "line=!line:%search%=%replace%!"
	>>"%outputTextFile%" echo(!line!
	endlocal
)

echo version.h generated
