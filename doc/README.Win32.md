# Introduction

To configure and to build this project entirely in Visual Studio IDE,
Visual Studio 2017 or later is needed.

Other methods of configuring and building can be adapted from this documentation.

Use the `Open Folder` Visual Studio command to open this CMake project.


# Building rpcapd over Npcap

## Prerequisites

The following external dependencies are needed for compilation:

  - [Win flex-bison](https://sourceforge.net/projects/winflexbison/)
  - [Npcap DLLs](https://nmap.org/npcap/) click on "Npcap _version_ installer" to download
       and during installation uncheck all options, should not be installed in WinPcap API-compatible Mode.
  - [Npcap SDK](https://nmap.org/npcap/)  click on "Npcap SDK _version_" to download

The paths of these dependencies should be referenced in CMake settings.

## CMake settings

In Visual Studio, Menu `Project -> CMake Settings`.

Configuration type: choose `Release` to build production binaries.

CMake variables:

`LEX_EXECUTABLE`: `path_to_winflexbison/win_flex.exe`

`PACKET_DLL_DIR`: `C:/Windows/System32/Npcap`

`PACKET_INCLUDE_DIR`: `path_to_npcap-sdk/Include`

`PACKET_LIBRARY`: `path_to_npcap-sdk/Lib/x64/Packet.lib`

`PCAP_TYPE`: `npf`

`YACC_EXECUTABLE`: `path_to_winflexbison/win_bison.exe`

If a CMake variable is not shown, click on `Edit JSON` to append it in CMakeSettings.json file.

Save these settings by Menu `File -> Save CMakeSettings.json`, or by keyboard shortcut `Ctrl+S`.

## Building

Menu `Build -> Build All` or keyboard shortcut `Ctrl+Shift+B`.

Resulted binaries `rpcapd.exe` and `pcap.dll` are in subdirectory `out\build\x64-Release\run`.


# Execution

The DLL `Packet.dll` from Npcap should be copied from `C:\Windows\System32\Npcap`
either in `C:\Windows\System32` (replacing existing one from WinPcap), or in the directory of `rpcapd.exe`.
