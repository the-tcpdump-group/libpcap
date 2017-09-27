#
# Copyright (C) 2017 Ali Abdulkadir <autostart.ini@gmail.com>.
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sub-license, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# FindPacket
# ==========
#
# Find the Packet library and include files.
#
# This module defines the following variables:
#
#    PACKET_INCLUDE_DIR   - absolute path to the directory containing Packet32.h.
#    PACKET_LIBRARY       - absolute path to the Packet library to link with.
#    PACKET_FOUND         - true if the Packet library *and* its headers are found.
#
# Hints and Backward Compatibility
# ================================
#
# To tell this module where to look, a user may set the environment variable
# PACKET_DLL_DIR to point cmake to the *root* of a directory with include and lib
# subdirectories for packet.dll (e.g WpdPack/npcap-sdk).
# Alternatively, PACKET_DLL_DIR may also be set from cmake command line or GUI
# (e.g cmake -DPACKET_DLL_DIR=/path/to/packet [...])
#

if(NOT PACKET_DLL_DIR)
  set(PACKET_DLL_DIR $ENV{PACKET_DLL_DIR})
endif()

# The 64-bit Packet.lib is located under /x64
# MinGW users may manually define TARGET_IS_MINGW64 to point to /x64
set(64BIT_SUBDIR "")
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(64BIT_SUBDIR "/x64")
endif()

# Are we a submodule?
if(IS_DIRECTORY ${CMAKE_HOME_DIRECTORY}/../../Common)
# We are!
  set(SUBMOD_INCLUDE_DIR ${CMAKE_HOME_DIRECTORY}/../../Common)

# Are we Npcap or WinPcap?
  if(IS_DIRECTORY ${CMAKE_HOME_DIRECTORY}/../../packetWin7)
  # We are Npcap!
  # The only four build configurations Npcap uses and developers are likely to get
  # support for are "Release No NetMon and AirPcap" and "Debug No NetMon and
  # AirPcap" (both Win32 and x64).
  # This module should probably only add the library output directories of these
  # configurations to HINTS.
    if(CMAKE_CL_64)
      if(${CMAKE_BUILD_TYPE} STREQUAL Debug)
        set(SUBMOD_LIB_DIR "${CMAKE_HOME_DIRECTORY}/../../packetWin7/Dll/Project/x64/Debug No NetMon and AirPcap")
      else()
        set(SUBMOD_LIB_DIR "${CMAKE_HOME_DIRECTORY}/../../packetWin7/Dll/Project/x64/Release No NetMon and AirPcap")
      endif()
    else()
      if(${CMAKE_BUILD_TYPE} STREQUAL Debug)
        set(SUBMOD_LIB_DIR "${CMAKE_HOME_DIRECTORY}/../../packetWin7/Dll/Project/Debug No NetMon and AirPcap")
      else()
        set(SUBMOD_LIB_DIR "${CMAKE_HOME_DIRECTORY}/../../packetWin7/Dll/Project/Release No NetMon and AirPcap")
      endif()
    endif()
  elseif(IS_DIRECTORY ${CMAKE_HOME_DIRECTORY}/../../Packet9x AND ${CMAKE_HOME_DIRECTORY}/../../Packet9x)
  # We are WinPcap!
  # Although most of WinPcap's build configurations seem to work,
  # the project itself is abandoned. The only libpcap branch it is know to work
  # with is libpcap_1_0_rel0b.
  # But there are forks (SoftEtherVPN's Win10Pcap) and many adventures developers.
  # For them, this module will point the "Release" and "Debug" library output
  # directories to ${SUBMOD_LIB_DIR}. If you prefer any other output folder, define
  # ${SUBMOD_LIB_DIR} manually.
    if(CMAKE_CL_64)
      if(${CMAKE_BUILD_TYPE} STREQUAL Debug)
        set(SUBMOD_LIB_DIR "${CMAKE_HOME_DIRECTORY}/../../packetNtx/Dll/Project/x64/Debug")
      else()
        set(SUBMOD_LIB_DIR "${CMAKE_HOME_DIRECTORY}/../../packetNtx/Dll/Project/x64/Release")
      endif()
    else()
      if(${CMAKE_BUILD_TYPE} STREQUAL Debug)
        set(SUBMOD_LIB_DIR "${CMAKE_HOME_DIRECTORY}/../../packetNtx/Dll/Project/Debug")
      else()
        set(SUBMOD_LIB_DIR "${CMAKE_HOME_DIRECTORY}/../../packetNtx/Dll/Project/Release")
      endif()
    endif()
  else()
  # something's not right. Point SUBMOD_LIB_DIR to nothing.
    set(SUBMOD_LIB_DIR "")
  endif()
endif()


# Find the header
find_path(PACKET_INCLUDE_DIR Packet32.h
  HINTS
  "${PACKET_DLL_DIR}"
  "${SUBMOD_INCLUDE_DIR}"
  PATH_SUFFIXES include Include
)

if(PACKET_INCLUDE_DIR)
  message(STATUS "Found Packet32.h: ${PACKET_INCLUDE_DIR}")
# else()
# message(FATAL_ERROR "Could not find Packet32.h. See README.Win32 for more information.")
endif()

# Find the library
find_library(PACKET_LIBRARY
  NAMES Packet packet
  HINTS
  "${PACKET_DLL_DIR}"
  "${SUBMOD_LIB_DIR}"
  PATH_SUFFIXES Lib${64BIT_SUBDIR} lib${64BIT_SUBDIR}
)

if(PACKET_LIBRARY)
  message(STATUS "Found Packet library: ${PACKET_LIBRARY}")
  set(HAVE_PACKET ${PACKET_LIBRARY})
# else()
  # message(FATAL_ERROR "Could not find Packet library. See README.Win32 for more information.")
endif()

if(PACKET_INCLUDE_DIR AND PACKET_LIBRARY)
  set(PACKET_FOUND TRUE)
endif()

mark_as_advanced(PACKET_INCLUDE_DIR PACKET_LIBRARY)
