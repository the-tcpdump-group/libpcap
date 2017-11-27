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
# PACKET_INCLUDE_DIR     - absolute path to the directory containing Packet32.h.
#
# PACKET_LIBRARY         - relative or absolute path to the Packet library to
#                          link with. An absolute path is will be used if the
#                          Packet library is not located in the compiler's
#                          default search path. See e.g. PACKET_DLL_DIR
#                          variable below.

# PACKET_FOUND           - TRUE if the Packet library *and* header are found.
#
# Hints and Backward Compatibility
# ================================
#
# To tell this module where to look, a user may set the environment variable
# PACKET_DLL_DIR to point cmake to the *root* of a directory with include and
# lib subdirectories for packet.dll (e.g WpdPack/npcap-sdk).
# Alternatively, PACKET_DLL_DIR may also be set from cmake command line or GUI
# (e.g cmake -DPACKET_DLL_DIR=/path/to/packet [...])
#

if(NOT PACKET_DLL_DIR)
# Compile a source file to see if the library and include files are
# already reachable.
  include(CheckCSourceCompiles)
  include(CMakePushCheckState)

  cmake_push_check_state()
  set(CMAKE_REQUIRED_QUIET true)
  set(CMAKE_REQUIRED_LIBRARIES packet)
  check_c_source_compiles(
"#include <Packet32.h>

int main()
{
  return 0;
}" PACKET_SYSTEM_LIBRARY)
  cmake_pop_check_state()

  if(PACKET_SYSTEM_LIBRARY)
    set(PACKET_LIBRARY packet)
  else()
    set(PACKET_DLL_DIR $ENV{PACKET_DLL_DIR})
  endif()
endif()

# The 64-bit Packet.lib is located under /x64
set(64BIT_SUBDIR "")
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(64BIT_SUBDIR "/x64")
endif()

# Find the header
find_path(PACKET_INCLUDE_DIR Packet32.h
  HINTS "${PACKET_DLL_DIR}"
  PATH_SUFFIXES include Include
)

if(PACKET_SYSTEM_LIBRARY)
# Find the library
  find_library(PACKET_LIBRARY
    NAMES Packet packet
    HINTS "${PACKET_DLL_DIR}"
    PATH_SUFFIXES Lib${64BIT_SUBDIR} lib${64BIT_SUBDIR}
  )
endif()

# Set PACKET_FOUND to TRUE if PACKET_INCLUDE_DIR and PACKET_LIBRARY are TRUE.
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PACKET
  REQUIRED_VARS PACKET_INCLUDE_DIR PACKET_LIBRARY
)

mark_as_advanced(PACKET_INCLUDE_DIR PACKET_LIBRARY)
