cmake_minimum_required(VERSION 2.8.6)

#
# Apple doesn't build with an install_name starting with @rpath, and
# neither do we with autotools; don't do so with CMake, either, and
# suppress warnings about that.
#
if(POLICY CMP0042)
    cmake_policy(SET CMP0042 OLD)
endif()

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

project(pcap)
#
# Call the library "wpcap" on Windows, for backwards compatibility.
#
if(WIN32)
    set(LIBRARY_NAME wpcap)
else()
    set(LIBRARY_NAME pcap)
endif()

###################################################################
#   Parameters
###################################################################

option(INET6 "Enable IPv6" ON)
if(WIN32)
    option(USE_STATIC_RT "Use static Runtime" ON)
endif(WIN32)
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
if(WIN32)
    set(PACKET_DLL_DIR "" CACHE PATH "Path to directory with include and lib subdirectories for packet.dll")
endif(WIN32)

# To pacify those who hate the protochain instruction
option(NO_PROTOCHAIN "Disable protochain instruction" OFF)

#
# Start out with the capture mechanism type unspecified; the user
# can explicitly specify it and, if they don't, we'll pick an
# appropriate one.
#
set(PCAP_TYPE "" CACHE STRING "Packet capture type")

#
# Default to having remote capture support on Windows and, for now, to
# not having it on UN*X.
#
if(WIN32)
    option(HAVE_REMOTE "Enable remote capture" ON)
else()
    option(HAVE_REMOTE "Enable remote capture" OFF)
endif(WIN32)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    option(PCAP_SUPPORT_PACKET_RING "Enable Linux packet ring support" ON)
    option(BUILD_WITH_LIBNL "Build with libnl" ON)
endif()

option(DISABLE_USB "Disable USB sniffing support" OFF)
option(DISABLE_BLUETOOTH "Disable Bluetooth sniffing support" OFF)
option(DISABLE_NETMAP "Disable netmap support" OFF)
#
# We don't support D-Bus sniffing on macOS; see
#
# https://bugs.freedesktop.org/show_bug.cgi?id=74029
#
if(APPLE)
    option(DISABLE_DBUS "Disable D-Bus sniffing support" ON)
else(APPLE)
    option(DISABLE_DBUS "Disable D-Bus sniffing support" OFF)
endif(APPLE)
option(DISABLE_RDMA "Disable RDMA sniffing support" OFF)

option(DISABLE_DAG "Disable DAG card support" OFF)
set(DAG_ROOT "/usr/local" CACHE PATH "Path to directory with include and lib subdirectories for DAG API")

option(DISABLE_SEPTEL "Disable Septel card support" OFF)
set(SEPTEL_ROOT "${CMAKE_SOURCE_DIR}/../septel" CACHE PATH "Path to directory with include and lib subdirectories for Septel API")

option(DISABLE_SNF "Disable Myricom SNF support" OFF)
set(SNF_ROOT "/opt/snf" CACHE PATH "Path to directory with include and lib subdirectories for Myricom Sniffer API")

option(DISABLE_TURBOCAP "Disable Riverbed TurboCap support" OFF)
set(TURBOCAP_ROOT "" CACHE PATH "Path to directory with include and lib subdirectories for Riverbed TurboCap API")

option(BDEBUG "Build optimizer debugging code" OFF)
option(YYDEBUG "Build parser debugging code" OFF)

###################################################################
#   Versioning
###################################################################

# Get, parse, format and set pcap's version string from [pcap_root]/VERSION
# for later use.
 
# Get MAJOR, MINOR, PATCH & SUFFIX
file(STRINGS ${pcap_SOURCE_DIR}/VERSION
    PACKAGE_VERSION
    LIMIT_COUNT 1 # Read only the first line
)

# Get "just" MAJOR
string(REGEX MATCH "^([0-9]+)" PACKAGE_VERSION_MAJOR "${PACKAGE_VERSION}")

# Get MAJOR, MINOR & PATCH
string(REGEX MATCH "^([0-9]+.)?([0-9]+.)?([0-9]+)" PACKAGE_VERSION_NOSUFFIX "${PACKAGE_VERSION}")

if(WIN32) 
    # Convert PCAP_VERSION_NOSUFFIX to Windows preferred version format
    string(REPLACE "." "," PACKAGE_VERSION_PREDLL ${PACKAGE_VERSION_NOSUFFIX})

    # Append NANO (used for Windows internal versioning) to PCAP_VERSION_PREDLL
    # 0 means unused.
    set(PACKAGE_VERSION_DLL "${PACKAGE_VERSION_PREDLL},0")
endif(WIN32)

set(PACKAGE_NAME "${LIBRARY_NAME}")
set(PACKAGE_STRING "${LIBRARY_NAME} ${PACKAGE_VERSION}")

######################################
# Project settings
######################################

add_definitions(-DHAVE_CONFIG_H)

include_directories(
    ${CMAKE_CURRENT_BINARY_DIR}
    ${pcap_SOURCE_DIR}
)

include(CheckFunctionExists)
include(CMakePushCheckState)

if(WIN32)

    if(IS_DIRECTORY ${CMAKE_HOME_DIRECTORY}/../../Common)
        include_directories(${CMAKE_HOME_DIRECTORY}/../../Common)
    endif(IS_DIRECTORY ${CMAKE_HOME_DIRECTORY}/../../Common)

    find_package(Packet)
    if(PACKET_FOUND)
        set(HAVE_PACKET32 TRUE)
        include_directories(${PACKET_INCLUDE_DIR})
        #
        # Check whether we have the NPcap PacketIsLoopbackAdapter()
        # function.
        #
        cmake_push_check_state()
        set(CMAKE_REQUIRED_LIBRARIES ${PACKET_LIBRARY})
        check_function_exists(PacketIsLoopbackAdapter HAVE_PACKET_IS_LOOPBACK_ADAPTER)
        cmake_pop_check_state()
    endif(PACKET_FOUND)

endif(WIN32)

add_definitions(-DBUILDING_PCAP)

if(MSVC)
    add_definitions(-D__STDC__)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions("-D_U_=")
elseif(CMAKE_COMPILER_IS_GNUCXX)
    add_definitions("-D_U_=__attribute__((unused))")
else(MSVC)
    add_definitions("-D_U_=")
endif(MSVC)

if(USE_STATIC_RT)
    message(STATUS "Use STATIC runtime")
        if(MSVC)
            foreach(RT_FLAG
                CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
                CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO
                CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
                CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
                string(REGEX REPLACE "/MD" "/MT" ${RT_FLAG} "${${RT_FLAG}}")
            endforeach(RT_FLAG)
        elseif(MINGW)
            set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libgcc")
        endif()
else (USE_STATIC_RT)
    message(STATUS "Use DYNAMIC runtime")
endif(USE_STATIC_RT)

###################################################################
#   Detect available platform features
###################################################################

include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckStructHasMember)
include(CheckTypeSize)

#
# Header files.
#
check_include_file(inttypes.h HAVE_INTTYPES_H)
check_include_file(stdint.h HAVE_STDINT_H)
check_include_file(unistd.h HAVE_UNISTD_H)
if(NOT HAVE_UNISTD_H)
    add_definitions(-DYY_NO_UNISTD_H)
endif(NOT HAVE_UNISTD_H)
check_include_file(bitypes.h HAVE_SYS_BITYPES_H)
check_include_file(sys/ioccom.h HAVE_SYS_IOCCOM_H)
check_include_file(sys/sockio.h HAVE_SYS_SOCKIO_H)
check_include_file(sys/select.h HAVE_SYS_SELECT_H)
check_include_file(limits.h HAVE_LIMITS_H)
check_include_file(netpacket/packet.h HAVE_NETPACKET_PACKET_H)
check_include_file(net/pfvar.h HAVE_NET_PFVAR_H)
if(HAVE_NET_PFVAR_H)
    #
    # Check for various PF actions.
    #
    check_c_source_compiles(
"#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/pfvar.h>

int
main(void)
{
    return PF_NAT+PF_NONAT+PF_BINAT+PF_NOBINAT+PF_RDR+PF_NORDR;
}
"
        HAVE_PF_NAT_THROUGH_PF_NORDR)
endif()
check_include_file(netinet/if_ether.h HAVE_NETINET_IF_ETHER_H)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    check_include_file(linux/sockios.h HAVE_LINUX_SOCKIOS_H)
    #
    # linux/if_bonding.h requires sys/socket.h.
    #
    check_include_files("sys/socket.h;linux/if_bonding.h" HAVE_LINUX_IF_BONDING_H)
endif()

#
# Functions.
#
check_function_exists(strerror HAVE_STRERROR)
check_function_exists(strlcpy HAVE_STRLCPY)
check_function_exists(strlcat HAVE_STRLCAT)
check_function_exists(snprintf HAVE_SNPRINTF)
check_function_exists(vsnprintf HAVE_VSNPRINTF)
check_function_exists(strtok_r HAVE_STRTOK_R)

#
# Find library needed for gethostbyname.
# NOTE: if you hand check_library_exists as its last argument a variable
# that's been set, it skips the test, so we need different variables.
#
include(CheckLibraryExists)
check_function_exists(gethostbyname STDLIBS_HAVE_GETHOSTBYNAME)
if(NOT STDLIBS_HAVE_GETHOSTBYNAME)
    check_library_exists(nsl gethostbyname "" LIBNSL_HAS_GETHOSTBYNAME)
    if(LIBNSL_HAS_GETHOSTBYNAME)
        set(PCAP_LINK_LIBRARIES ${PCAP_LINK_LIBRARIES} nsl)
    endif()
endif()

#
# Data types.
#
# XXX - there's no check_struct() macro that's like check_struct_has_member()
# except that it only checks for the existence of the structure type,
# so we use check_struct_has_member() and look for ss_family.
#
check_struct_has_member("struct sockaddr_storage" ss_family sys/socket.h  HAVE_SOCKADDR_STORAGE)
set(CMAKE_EXTRA_INCLUDE_FILES unistd.h sys/socket.h)
check_type_size("socklen_t" SOCKLEN_T)
set(CMAKE_EXTRA_INCLUDE_FILES unistd.h)

#
# Structure fields.
#
check_struct_has_member("struct sockaddr" sa_len sys/socket.h HAVE_SOCKADDR_SA_LEN)

#
# Do we have ffs(), and is it declared in <strings.h>?
#
include(CheckSymbolExists)
check_function_exists(ether_hostton HAVE_FFS)
if(HAVE_FFS)
    #
    # OK, we have ffs().  Is it declared in <strings.h>?
    #
    # This test fails if we don't have <strings.h> or if we do
    # but it doesn't declare ffs().
    #
    check_symbol_exists(ffs strings.h STRINGS_H_DECLARES_FFS)
endif()

#
# You are in a twisty little maze of UN*Xes, all different.
# Some might not have ether_hostton().
# Some might have it and declare it in <net/ethernet.h>.
# Some might have it and declare it in <netinet/ether.h>
# Some might have it and declare it in <sys/ethernet.h>.
# Some might have it and declare it in <arpa/inet.h>.
# Some might have it and declare it in <netinet/if_ether.h>.
# Some might have it and not declare it in any header file.
#
# Before you is a C compiler.
#
check_function_exists(ether_hostton HAVE_ETHER_HOSTTON)
if(HAVE_ETHER_HOSTTON)
    #
    # OK, we have ether_hostton().  Is it declared in <net/ethernet.h>?
    #
    # This test fails if we don't have <net/ethernet.h> or if we do
    # but it doesn't declare ether_hostton().
    #
    check_symbol_exists(ether_hostton net/ethernet.h NET_ETHERNET_H_DECLARES_ETHER_HOSTTON)
    if(NET_ETHERNET_H_DECLARES_ETHER_HOSTTON)
        #
        # Yes - we have it declared.
        #
        set(HAVE_DECL_ETHER_HOSTTON TRUE)
    endif()
    #
    # Did that succeed?
    #
    if(NOT HAVE_DECL_ETHER_HOSTTON)
        #
        # No - how about <netinet/ether.h>, as on Linux?
        #
        # This test fails if we don't have <netinet/ether.h>
        # or if we do but it doesn't declare ether_hostton().
        #
        check_symbol_exists(ether_hostton netinet/ether.h NETINET_ETHER_H_DECLARES_ETHER_HOSTTON)
        if(NETINET_ETHER_H_DECLARES_ETHER_HOSTTON)
            #
            # Yes - we have it declared.
            #
            set(HAVE_DECL_ETHER_HOSTTON TRUE)
        endif()
    endif()
    #
    # Did that succeed?
    #
    if(NOT HAVE_DECL_ETHER_HOSTTON)
        #
        # No - how about <sys/ethernet.h>, as on Solaris 10 and later?
        #
        # This test fails if we don't have <sys/ethernet.h>
        # or if we do but it doesn't declare ether_hostton().
        #
        check_symbol_exists(ether_hostton sys/ethernet.h SYS_ETHERNET_H_DECLARES_ETHER_HOSTTON)
        if(SYS_ETHERNET_H_DECLARES_ETHER_HOSTTON)
            #
            # Yes - we have it declared.
            #
            set(HAVE_DECL_ETHER_HOSTTON TRUE)
        endif()
    endif()
    #
    # Did that succeed?
    #
    if(NOT HAVE_DECL_ETHER_HOSTTON)
        #
        # No, how about <arpa/inet.h>, as on AIX?
        #
        # This test fails if we don't have <arpa/inet.h>
        # or if we do but it doesn't declare ether_hostton().
        #
        check_symbol_exists(ether_hostton arpa/inet.h ARPA_INET_H_DECLARES_ETHER_HOSTTON)
        if(ARPA_INET_H_DECLARES_ETHER_HOSTTON)
            #
            # Yes - we have it declared.
            #
            set(HAVE_DECL_ETHER_HOSTTON TRUE)
        endif()
    endif()
    #
    # Did that succeed?
    #
    if(NOT HAVE_DECL_ETHER_HOSTTON)
        #
        # No, how about <netinet/if_ether.h>?
        # On some platforms, it requires <net/if.h> and
        # <netinet/in.h>, and we always include it with
        # both of them, so test it with both of them.
        #
        # This test fails if we don't have <netinet/if_ether.h>
        # and the headers we include before it, or if we do but
        # <netinet/if_ether.h> doesn't declare ether_hostton().
        #
        check_symbol_exists(ether_hostton "sys/types.h;sys/socket.h;net/if.h;netinet/in.h;netinet/if_ether.h" NETINET_IF_ETHER_H_DECLARES_ETHER_HOSTTON)
        if(NETINET_IF_ETHER_H_DECLARES_ETHER_HOSTTON)
            #
            # Yes - we have it declared.
            #
            set(HAVE_DECL_ETHER_HOSTTON TRUE)
        endif()
    endif()
    #
    # After all that, is ether_hostton() declared?
    #
    if(NOT HAVE_DECL_ETHER_HOSTTON)
        #
        # No, we'll have to declare it ourselves.
        # Do we have "struct ether_addr" if we include<netinet/if_ether.h>?
        #
        check_struct_has_member("struct ether_addr" octet "sys/types.h;sys/socket.h;net/if.h;netinet/in.h;netinet/if_ether.h" HAVE_STRUCT_ETHER_ADDR)
    endif()
endif()

#
# Large file support on UN*X, a/k/a LFS.
#
if(NOT WIN32)
  include(FindLFS)
  if(LFS_FOUND)
    #
    # Add the required #defines.
    #
    add_definitions(${LFS_DEFINITIONS})
  endif()
endif()

if(INET6)
    message(STATUS "Use IPv6")
endif(INET6)

######################################
# External dependencies
######################################

######################################
# Input files
######################################

set(PROJECT_SOURCE_LIST_C
    bpf_dump.c
    bpf_image.c
    etherent.c
    gencode.c
    nametoaddr.c
    optimize.c
    pcap-common.c
    pcap.c
    savefile.c
    sf-pcap-ng.c
    sf-pcap.c
    bpf/net/bpf_filter.c
)

if(WIN32)
    set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} missing/win_snprintf.c)
else()
    if(NOT HAVE_SNPRINTF)
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} missing/snprintf.c)
    endif(NOT HAVE_SNPRINTF)
    if(NOT HAVE_STRTOK_R)
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} missing/strtok_r.c)
    endif(NOT HAVE_STRTOK_R)
endif(WIN32)

if(HAVE_REMOTE)
    set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C}
        pcap-new.c pcap-rpcap.c sockutils.c)
endif(HAVE_REMOTE)

#
# Determine the main pcap-XXX.c file to use, and the libraries with
# which we need to link libpcap, if any.
#
if(WIN32)
    #
    # Windows; we need to link with WinSock2.
    #
    set(PCAP_LINK_LIBRARIES ws2_32)

    #
    # Has the user explicitly specified a capture type?
    #
    if(PCAP_TYPE STREQUAL "")
        #
        # The user didn't explicitly specify a capture mechanism.
        # Check whether we have packet.dll.
        #
        if(HAVE_PACKET32)
            #
            # We have packet.dll.
            # Set the capture type to NPF.
            #
            set(PCAP_TYPE npf)
        else()
            #
            # We don't have any capture type we know about, so just use
            # the null capture type, and only support reading (and writing)
            # capture files.
            #
            set(PCAP_TYPE null)
        endif()
    endif()
else()
    #
    # UN*X.
    #
    # Figure out what type of packet capture mechanism we have, and
    # what libraries we'd need to link libpcap with, if any.
    #
    set(PCAP_LINK_LIBRARIES "")

    #
    # Has the user explicitly specified a capture type?
    #
    if(PCAP_TYPE STREQUAL "")
        #
        # Check for a bunch of headers for various packet capture mechanisms.
        #
        check_include_files("sys/types.h;net/bpf.h" HAVE_NET_BPF_H)
        check_include_file(net/pfilt.h HAVE_NET_PFILT_H)
        check_include_file(net/enet.h HAVE_NET_ENET_H)
        check_include_file(net/nit.h HAVE_NET_NIT_H)
        check_include_file(sys/net/nit.h HAVE_SYS_NET_NIT_H)
        check_include_file(linux/socket.h HAVE_LINUX_SOCKET_H)
        check_include_file(net/raw.h HAVE_NET_RAW_H)
        check_include_file(sys/dlpi.h HAVE_SYS_DLPI_H)

        if(HAVE_NET_BPF_H)
            #
            # BPF.
            # Check this before DLPI, so that we pick BPF on
            # Solaris 11 and later.
            #
            set(PCAP_TYPE bpf)
        elseif(HAVE_NET_PFILT_H)
            #
            # DEC OSF/1, Digital UNIX, Tru64 UNIX
            #
            set(PCAP_TYPE pf)
        elseif(HAVE_NET_ENET_H)
            #
            # Stanford Enetfilter.
            #
            set(PCAP_TYPE enet)
        elseif(HAVE_NET_NIT_H)
            #
            # SunOS 4.x STREAMS NIT.
            #
            set(PCAP_TYPE snit)
        elseif(HAVE_SYS_NET_NIT_H)
            #
            # Pre-SunOS 4.x non-STREAMS NIT.
            #
            set(PCAP_TYPE nit)
        elseif(HAVE_LINUX_SOCKET_H)
            #
            # No prizes for guessing this one.
            #
            set(PCAP_TYPE linux)
        elseif(HAVE_NET_RAW_H)
            #
            # IRIX snoop.
            #
            set(PCAP_TYPE snoop)
        elseif(HAVE_SYS_DLPI_H)
            #
            # DLPI on pre-Solaris 11 SunOS 5, HP-UX, possibly others.
            #
            set(PCAP_TYPE dlpi)
        else()
            #
            # Nothing we support.
            #
            set(PCAP_TYPE null)
        endif()
    endif()
endif(WIN32)
message(STATUS "Packet capture mechanism type: ${PCAP_TYPE}")

#
# Do capture-mechanism-dependent tests.
#
if(WIN32)
    if(PCAP_TYPE STREQUAL "npf")
        #
        # Link with packet.dll before WinSock2.
        #
        set(PCAP_LINK_LIBRARIES ${PACKET_LIBRARY} ${PCAP_LINK_LIBRARIES})
    elseif(PCAP_TYPE STREQUAL "null")
    else()
        message(ERROR "${PCAP_TYPE} is not a valid pcap type")
    endif()
else(WIN32)
    if(PCAP_TYPE STREQUAL "dlpi")
        #
        # Needed for common functions used by pcap-[dlpi,libdlpi].c
        #
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} dlpisubs.c)

        #
        # Checks for some header files.
        #
        check_include_file(sys/bufmod.h HAVE_SYS_BUFMOD_H)
        check_include_file(sys/dlpi_ext.h HAVE_SYS_DLPI_EXT_H)

        #
        # Checks to see if Solaris has the public libdlpi(3LIB) library.
        # Note: The existence of /usr/include/libdlpi.h does not mean it is the
        # public libdlpi(3LIB) version. Before libdlpi was made public, a
        # private version also existed, which did not have the same APIs.
        # Due to a gcc bug, the default search path for 32-bit libraries does
        # not include /lib, we add it explicitly here.
        # [http://bugs.opensolaris.org/view_bug.do?bug_id=6619485].
        # Also, due to the bug above applications that link to libpcap with
        # libdlpi will have to add "-L/lib" option to "configure".
        #
        cmake_push_check_state()
        set(CMAKE_REQUIRED_FLAGS "-L/lib")
        set(CMAKE_REQUIRED_LIBRARIES dlpi)
        check_function_exists(dlpi_walk HAVE_LIBDLPI)
        cmake_pop_check_state()
        if(HAVE_LIBDLPI)
            #
            # XXX - add -L/lib
            #
            set(PCAP_LINK_LIBRARIES ${PCAP_LINK_LIBRARIES} dlpi)
            set(PCAP_TYPE libdlpi)
        endif()

        #
        # This check is for Solaris with DLPI support for passive modes.
        # See dlpi(7P) for more details.
        #
        # XXX - there's no check_struct() macro that's like
        # check_struct_has_member() except that it only checks for the
        # existence of the structure type, so we use
        # check_struct_has_member() and look for dl_primitive.
        #
        check_struct_has_member("dl_passive_req_t" dl_primitive "sys/types.h;sys/dlpi.h" HAVE_DLPI_PASSIVE)
    elseif(PCAP_TYPE STREQUAL "linux")
        #
        # Do we have the wireless extensions?
        # linux/wireless.h requires sys/socket.h.
        #
        check_include_files("sys/socket.h;linux/wireless.h" HAVE_LINUX_WIRELESS_H)

        #
        # Do we have libnl?
        #
        if(BUILD_WITH_LIBNL)
            #
            # Try libnl 3.x first.
            #
            cmake_push_check_state()
            set(CMAKE_REQUIRED_LIBRARIES nl-3)
            check_function_exists(nl_socket_alloc HAVE_LIBNL)
            cmake_pop_check_state()
            if(HAVE_LIBNL)
                #
                # Yes, we have libnl 3.x.
                #
                set(PCAP_LINK_LIBRARIES nl-genl-3 nl-3 ${PCAP_LINK_LIBRARIES})
                set(HAVE_LIBNL_3_x ON)
                set(HAVE_LIBNL_NLE ON)
                set(HAVE_LIBNL_SOCKETS ON)
                include_directories("/usr/include/libnl3")
            else()
                #
                # Try libnl 2.x.
                #
                cmake_push_check_state()
                set(CMAKE_REQUIRED_LIBRARIES nl)
                check_function_exists(nl_socket_alloc HAVE_LIBNL)
                cmake_pop_check_state()
                if(HAVE_LIBNL)
                    #
                    # Yes, we have libnl 2.x.
                    #
                    set(PCAP_LINK_LIBRARIES nl-genl nl ${PCAP_LINK_LIBRARIES})
                    set(HAVE_LIBNL_2_x ON)
                    set(HAVE_LIBNL_NLE ON)
                    set(HAVE_LIBNL_SOCKETS ON)
                else()
                    #
                    # No, we don't; do we have libnl 1.x?
                    #
                    cmake_push_check_state()
                    set(CMAKE_REQUIRED_LIBRARIES nl)
                    check_function_exists(nl_handle_alloc HAVE_LIBNL)
                    cmake_pop_check_state()
                    if(HAVE_LIBNL)
                        set(PCAP_LINK_LIBRARIES nl ${PCAP_LINK_LIBRARIES})
                    endif()
                endif()
            endif()
        endif()

        check_include_file(linux/ethtool.h HAVE_LINUX_ETHTOOL_H)

        #
        # Checks to see if tpacket_stats is defined in linux/if_packet.h
        # If so then pcap-linux.c can use this to report proper statistics.
        #
        check_struct_has_member("struct tpacket_stats" tp_packets linux/if_packet.h HAVE_TPACKET_STATS)

        check_struct_has_member("struct tpacket_auxdata" tp_vlan_tci linux/if_packet.h HAVE_LINUX_TPACKET_AUXDATA_TP_VLAN_TCI)
        if(HAVE_LINUX_TPACKET_AUXDATA_TP_VLAN_TCI)
            set(HAVE_LINUX_TPACKET_AUXDATA tp_vlan_tci)
        endif()
    elseif(PCAP_TYPE STREQUAL "bpf")
        #
        # Check whether we have the *BSD-style ioctls.
        #
        check_include_files("sys/types.h;net/if_media.h" HAVE_NET_IF_MEDIA_H)

        #
        # Check whether we have struct BPF_TIMEVAL.
        #
        if(HAVE_SYS_IOCCOM_H)
            check_struct_has_member("struct BPF_TIMEVAL" tv_sec "sys/types.h;sys/ioccom.h;net/bpf.h" HAVE_STRUCT_BPF_TIMEVAL)
        else()
            check_struct_has_member("struct BPF_TIMEVAL" tv_sec "sys/types.h;net/bpf.h" HAVE_STRUCT_BPF_TIMEVAL)
        endif()
    elseif(PCAP_TYPE STREQUAL "null")
    else()
        message(FATAL_ERROR "${PCAP_TYPE} is not a valid pcap type")
    endif()
endif(WIN32)

set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-${PCAP_TYPE}.c)

#
# Now figure out how we get a list of interfaces and addresses,
# if we support capturing.  Don't bother if we don't support
# capturing.
#
if(NOT WIN32)
    #
    # UN*X - figure out what type of interface list mechanism we
    # have.
    #
    # If the capture type is null, that means we can't capture,
    # so we can't open any capture devices, so we won't return
    # any interfaces.
    #
    if(NOT PCAP_TYPE STREQUAL "null")
        check_function_exists(getifaddrs HAVE_GETIFADDRS)
        if(NOT HAVE_GETIFADDRS)
            #
            # It's in libsocket on Solaris and possibly other OSes;
            # check there.
            #
            # NOTE: if you hand check_library_exists as its last
            # argument a variable that's been set, it skips the test,
            # so we need different variables.
            #
            check_library_exists(socket getifaddrs "" SOCKET_HAS_GETIFADDRS)
            if(SOCKET_HAS_GETIFADDRS)
                set(PCAP_LINK_LIBRARIES socket ${PCAP_LINK_LIBRARIES})
                set(HAVE_GETIFADDRS TRUE)
            endif()
        endif()
        if(HAVE_GETIFADDRS)
            #
            # We have "getifaddrs()"; make sure we have <ifaddrs.h>
            # as well, just in case some platform is really weird.
            # It may require that sys/types.h be included first,
            # so include it first.
            #
            check_include_files("sys/types.h;ifaddrs.h" HAVE_IFADDRS_H)
            if(HAVE_IFADDRS_H)
                #
                # We have the header, so we use "getifaddrs()" to
                # get the list of interfaces.
                #
                set(FINDALLDEVS_TYPE getad)
            else()
                #
                # We don't have the header - give up.
                # XXX - we could also fall back on some other
                # mechanism, but, for now, this'll catch this
                # problem so that we can at least try to figure
                # out something to do on systems with "getifaddrs()"
                # but without "ifaddrs.h", if there is something
                # we can do on those systems.
                #
                message(FATAL_ERROR "Your system has getifaddrs() but doesn't have a usable <ifaddrs.h>.")
            endif()
        else()
            #
            # Well, we don't have "getifaddrs()", so we have to use
            # some other mechanism; determine what that mechanism is.
            #
            # The first thing we use is the type of capture mechanism,
            # which is somewhat of a proxy for the OS we're using.
            #
            if(PCAP_TYPE STREQUAL "dlpi" OR PCAP_TYPE STREQUAL "libdlpi")
                #
                # This might be Solaris 8 or later, with
                # SIOCGLIFCONF, or it might be some other OS
                # or some older version of Solaris, with
                # just SIOCGIFCONF.
                #
                try_compile(HAVE_SIOCGLIFCONF ${CMAKE_CURRENT_BINARY_DIR} "${pcap_SOURCE_DIR}/cmake/have_siocglifconf.c" )
                if(HAVE_SIOCGLIFCONF)
                    set(FINDALLDEVS_TYPE glifc)
                else()
                    set(FINDALLDEVS_TYPE gifc)
                endif()
            else()
                #
                # Assume we just have SIOCGIFCONF.
                # (XXX - on at least later Linux kernels, there's
                # another mechanism, and we should be using that
                # instead.)
                #
                set(FINDALLDEVS_TYPE gifc)
            endif()
        endif()
        message(STATUS "Find-interfaces mechanism type: ${FINDALLDEVS_TYPE}")
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} fad-${FINDALLDEVS_TYPE}.c)
    endif()
endif()

# Check for hardware timestamp support.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    check_include_file(linux/net_tstamp.h HAVE_LINUX_NET_TSTAMP_H)
endif()

# Check for USB sniffing support on Linux.
# On FreeBSD, it uses BPF, so we don't need to do anything special here.
if(NOT DISABLE_USB)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(PCAP_SUPPORT_USB TRUE)
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-usb-linux.c)
        set(LINUX_USB_MON_DEV /dev/usbmon)
        #
        # Do we have a version of <linux/compiler.h> available?
        # If so, we might need it for <linux/usbdevice_fs.h>.
        #
        check_include_files("linux/compiler.h" HAVE_LINUX_COMPILER_H)
        if(HAVE_LINUX_COMPILER_H)
            #
            # Yes - include it when testing for <linux/usbdevice_fs.h>.
            #
            check_include_files("linux/compiler.h;linux/usbdevice_fs.h" HAVE_LINUX_USBDEVICE_FS_H)
        else(HAVE_LINUX_COMPILER_H)
            check_include_files("linux/usbdevice_fs.h" HAVE_LINUX_USBDEVICE_FS_H)
        endif(HAVE_LINUX_COMPILER_H)
        if(HAVE_LINUX_USBDEVICE_FS_H)
            #
            # OK, does it define bRequestType?  Older versions of the kernel
            # define fields with names like "requesttype, "request", and
            # "value", rather than "bRequestType", "bRequest", and
            # "wValue".
            #
            if(HAVE_LINUX_COMPILER_H)
                check_struct_has_member("struct usbdevfs_ctrltransfer" bRequestType "linux/compiler.h;linux/usbdevice_fs.h" HAVE_USBDEVFS_CTRLTRANSFER_BREQUESTTYPE)
            else(HAVE_LINUX_COMPILER_H)
                check_struct_has_member("struct usbdevfs_ctrltransfer" bRequestType "linux/usbdevice_fs.h" HAVE_USBDEVFS_CTRLTRANSFER_BREQUESTTYPE)
            endif(HAVE_LINUX_COMPILER_H)
        endif()
    endif()
endif()

# Check for netfilter sniffing support.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    #
    # Life's too short to deal with trying to get this to compile
    # if you don't get the right types defined with
    # __KERNEL_STRICT_NAMES getting defined by some other include.
    #
    # Check whether the includes Just Work.  If not, don't turn on
    # netfilter support.
    #
    check_c_source_compiles(
"#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/types.h>

#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <linux/netfilter/nfnetlink_queue.h>

int
main(void)
{
    return 0;
}
"
        PCAP_SUPPORT_NETFILTER)
    if(PCAP_SUPPORT_NETFILTER)
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-netfilter-linux.c)
    endif(PCAP_SUPPORT_NETFILTER)
endif()

# Check for netmap sniffing support.
if(NOT DISABLE_NETMAP)
    #
    # Check whether net/netmap_user.h is usable if NETMAP_WITH_LIBS is
    # defined; it's not usable on DragonFly BSD 4.6 if NETMAP_WITH_LIBS
    # is defined, for example, as it includes a non-existent malloc.h
    # header.
    #
    check_c_source_compiles(
"#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
"
        PCAP_SUPPORT_NETMAP)
    if(PCAP_SUPPORT_NETMAP)
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-netmap.c)
    endif(PCAP_SUPPORT_NETMAP)
endif()

# Check for Bluetooth sniffing support
if(NOT DISABLE_BLUETOOTH)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        check_include_file(bluetooth/bluetooth.h HAVE_BLUETOOTH_BLUETOOTH_H)
        if(HAVE_BLUETOOTH_BLUETOOTH_H)
            set(PCAP_SUPPORT_BT TRUE)
            set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-bt-linux.c)
            #
            # OK, does struct sockaddr_hci have an hci_channel
            # member?
            #
            check_struct_has_member("struct sockaddr_hci" hci_channel "bluetooth/bluetooth.h;bluetooth/hci.h" SOCKADDR_HCI_HAS_HCI_CHANNEL)
            if(SOCKADDR_HCI_HAS_HCI_CHANNEL)
                #
                # OK, is HCI_CHANNEL_MONITOR defined?
                #
               check_c_source_compiles(
"#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>

int
main(void)
{
    u_int i = HCI_CHANNEL_MONITOR;
    return 0;
}
"
                   PCAP_SUPPORT_BT_MONITOR)
            endif(SOCKADDR_HCI_HAS_HCI_CHANNEL)
        endif(HAVE_BLUETOOTH_BLUETOOTH_H)
    endif()
endif()

# Check for Bluetooth sniffing support
if(NOT DISABLE_DBUS)
    #
    # We don't support D-Bus sniffing on macOS; see
    #
    # https://bugs.freedesktop.org/show_bug.cgi?id=74029
    #
    if(APPLE)
        message(FATAL_ERROR "Due to freedesktop.org bug 74029, D-Bus capture support is not available on macOS")
    endif(APPLE)
    include(FindPkgConfig)
    pkg_check_modules(DBUS dbus-1)
    if(DBUS_FOUND)
        set(PCAP_SUPPORT_DBUS TRUE)
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-dbus.c)
        include_directories(${DBUS_INCLUDE_DIRS})
        set(PCAP_LINK_LIBRARIES ${PCAP_LINK_LIBRARIES} ${DBUS_LIBRARIES})
    endif(DBUS_FOUND)
endif(NOT DISABLE_DBUS)

# Check for RDMA sniffing support
if(NOT DISABLE_RDMA)
    check_library_exists(ibverbs ibv_get_device_list "" LIBIBVERBS_HAS_IBV_GET_DEVICE_LIST)
    if(LIBIBVERBS_HAS_IBV_GET_DEVICE_LIST)
        check_include_file(infiniband/verbs.h HAVE_INFINIBAND_VERBS_H)
        if(HAVE_INFINIBAND_VERBS_H)
            check_library_exists(ibverbs ibv_create_flow PCAP_SUPPORT_RDMASNIFF)
            if(PCAP_SUPPORT_RDMASNIFF)
                set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-rdmasniff.c)
                set(PCAP_LINK_LIBRARIES ibverbs ${PCAP_LINK_LIBRARIES})
            endif(PCAP_SUPPORT_RDMASNIFF)
        endif(HAVE_INFINIBAND_VERBS_H)
    endif(LIBIBVERBS_HAS_IBV_GET_DEVICE_LIST)
endif(NOT DISABLE_RDMA)

# Check for Endace DAG card support.
if(NOT DISABLE_DAG)
    #
    # Do we have the dagapi.h header?
    #
    set(DAG_INCLUDE_DIR "${DAG_ROOT}/include")
    cmake_push_check_state()
    set(CMAKE_REQUIRED_INCLUDES ${DAG_INCLUDE_DIR})
    check_include_file(dagapi.h HAVE_DAGAPI_H)
    cmake_pop_check_state()
    if(HAVE_DAGAPI_H)
        #
        # Yes.
        #
        include_directories(AFTER ${DAG_INCLUDE_DIR})
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-dag.c)
        set(HAVE_DAG_API TRUE)

        #
        # Check for various DAG API functions.
        #
        set(DAG_LIB_DIR ${DAG_ROOT}/lib)
        check_library_exists(dag dag_attach_stream ${DAG_LIB_DIR} HAVE_DAG_STREAMS_API)
        if(NOT HAVE_DAG_STREAMS_API)
            message(FATAL_ERROR "DAG library lacks streams support")
        endif()
        check_library_exists(dag dag_attach_stream64 ${DAG_LIB_DIR} HAVE_DAG_LARGE_STREAMS_API)
        check_library_exists(dag dag_get_erf_types ${DAG_LIB_DIR} HAVE_DAG_GET_ERF_TYPES)
        check_library_exists(dag dag_get_stream_erf_types ${DAG_LIB_DIR} HAVE_DAG_GET_STREAM_ERF_TYPES)
        set(PCAP_LINK_LIBRARIES ${PCAP_LINK_LIBRARIES} dag)
        link_directories(${DAG_LIB_DIR})

        if(HAVE_DAG_LARGE_STREAMS_API)
            check_library_exists(vdag vdag_set_device_info ${DAG_LIB_DIR} HAVE_DAG_VDAG)
            if(HAVE_DAG_VDAG)
                set(PCAP_LINK_LIBRARIES ${PCAP_LINK_LIBRARIES} pthread)
            endif()
        endif()
    endif()
endif() 

# Check for Septel card support.
set(PROJECT_EXTERNAL_OBJECT_LIST "")
if(NOT DISABLE_SEPTEL)
    #
    # Do we have the msg.h header?
    #
    set(SEPTEL_INCLUDE_DIR "${SEPTEL_ROOT}/INC")
    cmake_push_check_state()
    set(CMAKE_REQUIRED_INCLUDES ${SEPTEL_INCLUDE_DIR})
    check_include_file(msg.h HAVE_INC_MSG_H)
    cmake_pop_check_state()
    if(HAVE_INC_MSG_H)
        #
        # Yes.
        #
        include_directories(AFTER ${SEPTEL_INCLUDE_DIR})
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-septel.c)
        set(PROJECT_EXTERNAL_OBJECT_LIST ${PROJECT_EXTERNAL_OBJECT_LIST} "${SEPTEL_ROOT}/asciibin.o ${SEPTEL_ROOT}/bit2byte.o ${SEPTEL_ROOT}/confirm.o ${SEPTEL_ROOT}/fmtmsg.o ${SEPTEL_ROOT}/gct_unix.o ${SEPTEL_ROOT}/hqueue.o ${SEPTEL_ROOT}/ident.o ${SEPTEL_ROOT}/mem.o ${SEPTEL_ROOT}/pack.o ${SEPTEL_ROOT}/parse.o ${SEPTEL_ROOT}/pool.o ${SEPTEL_ROOT}/sdlsig.o ${SEPTEL_ROOT}/strtonum.o ${SEPTEL_ROOT}/timer.o ${SEPTEL_ROOT}/trace.o")
        set(HAVE_SEPTEL_API TRUE)
    endif()
endif() 

# Check for Myricom SNF support.
if(NOT DISABLE_SNF)
    #
    # Do we have the snf.h header?
    #
    set(SNF_INCLUDE_DIR "${SNF_ROOT}/include")
    cmake_push_check_state()
    set(CMAKE_REQUIRED_INCLUDES ${SNF_INCLUDE_DIR})
    check_include_file(snf.h HAVE_SNF_H)
    cmake_pop_check_state()
    if(HAVE_SNF_H)
        #
        # Yes.  Can we link with the SNF library?
        #
        include_directories(AFTER ${SNF_INCLUDE_DIR})
        set(SNF_LIB_DIR ${SNF_ROOT}/lib)
        check_library_exists(snf snf_init ${SNFLIB_DIR} HAVE_SNF_API)
        if(NOT HAVE_SNF_API)
            message(FATAL_ERROR "SNF API cannot correctly be linked; check CMakeFiles/CMakeError.log")
        endif()

        #
        # Yes.
        #
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-snf.c)
        set(PCAP_LINK_LIBRARIES ${PCAP_LINK_LIBRARIES} snf)
        link_directories(${SNFLIB_DIR})
    endif()
endif() 

# Check for Riverbed TurboCap support.
if(NOT DISABLE_TURBOCAP)
    #
    # Do we have the TcApi.h header?
    #
    set(TURBOCAP_INCLUDE_DIR "${TURBOCAP_ROOT}/include")
    cmake_push_check_state()
    set(CMAKE_REQUIRED_INCLUDES ${TURBOCAP_INCLUDE_DIR})
    check_include_file(TcApi.h HAVE_TCAPI_H)
    cmake_pop_check_state()
    if(HAVE_TCAPI_H)
        #
        # Yes.  Can we link with the TurboCap library?
        #
        include_directories(AFTER ${TURBOCAP_INCLUDE_DIR})
        set(TURBOCAP_LIB_DIR ${TURBOCAP_ROOT}/lib)
        check_library_exists(TcApi TcInstanceCreateByName ${TURBOCAPLIB_DIR} HAVE_TC_API)
        if(NOT HAVE_TC_API)
            message(FATAL_ERROR "TurboCap API cannot correctly be linked; check CMake errors")
        endif()

        #
        # Yes.
        #
        set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-tc.c)
        set(PCAP_LINK_LIBRARIES "${PCAP_LINK_LIBRARIES} TcApi pthread stdc++")
        link_directories(${TURBOCAPLIB_DIR})
    endif()
endif() 

file(GLOB PROJECT_SOURCE_LIST_CORE_H
    *.h
    pcap/*.h
)
set(PROJECT_SOURCE_LIST_H ${PROJECT_SOURCE_LIST_H} ${PROJECT_SOURCE_LIST_CORE_H})

if(WIN32)
    file(GLOB PROJECT_SOURCE_LIST_WIN32_H
        Win32/Include/*.h
    )
    set(PROJECT_SOURCE_LIST_H ${PROJECT_SOURCE_LIST_H} ${PROJECT_SOURCE_LIST_WIN32_H})
endif(WIN32)

#
# {Flex} and YACC/Berkeley YACC/Bison.
# From a mail message to the CMake mailing list by Andy Cedilnik of
# Kitware.
#

#
# Try to find Flex, a Windows version of Flex, or Lex.
#
find_program(LEX_EXECUTABLE NAMES flex win_flex lex)
if(LEX_EXECUTABLE STREQUAL "LEX_EXECUTABLE-NOTFOUND")
    message(FATAL_ERROR "Neither flex nor win_flex nor lex was found.")
endif()
message(STATUS "Lexical analyzer generator: ${LEX_EXECUTABLE}")

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/scanner.c ${CMAKE_CURRENT_BINARY_DIR}/scanner.h
    SOURCE ${pcap_SOURCE_DIR}/scanner.l
    COMMAND ${LEX_EXECUTABLE} -P pcap_ --header-file=scanner.h --nounput -o${CMAKE_CURRENT_BINARY_DIR}/scanner.c ${pcap_SOURCE_DIR}/scanner.l
    DEPENDS ${pcap_SOURCE_DIR}/scanner.l
)

#
# Since scanner.c does not exist yet when cmake is run, mark
# it as generated.
#
# Since scanner.c includes grammar.h, mark that as a dependency.
#
set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/scanner.c PROPERTIES
    GENERATED TRUE
    OBJECT_DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/scanner.h
)

#
# Add scanner.c to the list of sources.
#
#set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} ${CMAKE_CURRENT_BINARY_DIR}/scanner.c)

#
# Try to find YACC or Bison.
#
find_program(YACC_EXECUTABLE NAMES bison win_bison byacc yacc)
if(YACC_EXECUTABLE STREQUAL "YACC_EXECUTABLE-NOTFOUND")
    message(FATAL_ERROR "Neither bison nor win_bison nor byacc nor yacc was found.")
endif()
message(STATUS "Parser generator: ${YACC_EXECUTABLE}")

#
# Create custom command for the scanner.
# Find out whether it's Bison or notby looking at the last component
# of the path (without a .exe extension, if this is Windows).
#
get_filename_component(YACC_NAME ${YACC_EXECUTABLE} NAME_WE)
if("${YACC_NAME}" STREQUAL "bison" OR "${YACC_NAME}" STREQUAL "win_bison")
    set(YACC_COMPATIBILITY_FLAG "-y")
endif()
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/grammar.c ${CMAKE_CURRENT_BINARY_DIR}/grammar.h
    SOURCE ${pcap_SOURCE_DIR}/grammar.y
    COMMAND ${YACC_EXECUTABLE} ${YACC_COMPATIBILITY_FLAG} -p pcap_ -o ${CMAKE_CURRENT_BINARY_DIR}/grammar.c -d ${pcap_SOURCE_DIR}/grammar.y
    DEPENDS ${pcap_SOURCE_DIR}/grammar.y
)

#
# Since grammar.c does not exists yet when cmake is run, mark
# it as generated.
#
set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/grammar.c PROPERTIES
    GENERATED TRUE
)

#
# Add grammar.c to the list of sources.
#
#set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} ${CMAKE_CURRENT_BINARY_DIR}/grammar.c)

#
# Assume, by default, V7/BSD convention for man pages (file formats in
# section 5, miscellaneous info in section 7).
# Individual cases can override this.
#
set(MAN_FILE_FORMATS 5)
set(MAN_MISC_INFO 7)
set(MAN_USERMOD_SECTION 8)
if(CMAKE_SYSTEM_NAME STREQUAL "AIX")
    # Workaround to enable certain features
    set(_SUN TRUE)
    if(PCAP_TYPE STREQUAL "bpf")
        #
        # If we're using BPF, we need libodm and libcfg, as
        # we use them to load the BPF module.
        #
        set(PCAP_LINK_LIBRARIES ${PCAP_LINK_LIBRARIES} odm cfg)
    endif()
elseif(CMAKE_SYSTEM_NAME STREQUAL "HP-UX")
    if(CMAKE_SYSTEM_VERSION MATCHES "[A-Z.]*9\.[0-9]*")
        #
        # HP-UX 9.x.
        #
        set(HAVE_HPUX9 TRUE)
    elseif(CMAKE_SYSTEM_VERSION MATCHES "[A-Z.]*10\.0")
        #
        # HP-UX 10.0.
        #
    elseif(CMAKE_SYSTEM_VERSION MATCHES "[A-Z.]*10\.1")
        #
        # HP-UX 10.1.
        #
    else()
        #
        # HP-UX 10.20 and later.
        #
        set(HAVE_HPUX10_20_OR_LATER TRUE)
    endif()

    #
    # Use System V conventions for man pages.
    #
    set(MAN_FILE_FORMATS 4)
    set(MAN_MISC_INFO 5)
elseif(CMAKE_SYSTEM_NAME STREQUAL "IRIX" OR CMAKE_SYSTEM_NAME STREQUAL "IRIX64")
    #
    # Use System V conventions for man pages.
    #
    set(MAN_FILE_FORMATS 4)
    set(MAN_MISC_INFO 5)
elseif(CMAKE_SYSTEM_NAME STREQUAL "OSF1")
    #
    # DEC OSF/1, a/k/a Digial UNIX, a/k/a Tru64 UNIX.
    # Use System V conventions for man pages.
    #
    set(MAN_FILE_FORMATS 4)
    set(MAN_MISC_INFO 5)
elseif(CMAKE_SYSTEM_NAME STREQUAL "SunOS" AND CMAKE_SYSTEM_VERSION MATCHES "5[.][0-9.]*")
    #
    # SunOS 5.x.
    #
    set(HAVE_SOLARIS TRUE)
    if(CMAKE_SYSTEM_VERSION STREQUAL "5.12")
    else()
        #
        # Use System V conventions for man pages.
        #
        set(MAN_USERMOD_SECTION 1m)
        set(MAN_FILE_FORMATS 4)
        set(MAN_MISC_INFO 5)
    endif()
endif()

if(WIN32 AND NOT MSYS AND NOT ${CMAKE_CROSSCOMPILING})
    #
    # CMake does not love Windows.  Convert its UN*X-style paths to
    # Windows-style paths to hand to Windows programs.
    #
    file(TO_NATIVE_PATH "${pcap_SOURCE_DIR}/GenVersion.bat" GenVersion_path)
    file(TO_NATIVE_PATH "${pcap_SOURCE_DIR}/VERSION" VERSION_path)
    file(TO_NATIVE_PATH "${pcap_SOURCE_DIR}/version.c.in" version_c_in_path)
    file(TO_NATIVE_PATH "${CMAKE_CURRENT_BINARY_DIR}/version.c" version_c_path) 
    file(TO_NATIVE_PATH "${pcap_SOURCE_DIR}/pcap_version.h.in" pcap_version_h_in_path)
    file(TO_NATIVE_PATH "${CMAKE_CURRENT_BINARY_DIR}/pcap_version.h" pcap_version_h_path)
    add_custom_command( 
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/version.c 
        SOURCE ${pcap_SOURCE_DIR}/VERSION 
        COMMAND ${GenVersion_path} ${VERSION_path} ${version_c_in_path} ${version_c_path} 
        DEPENDS ${pcap_SOURCE_DIR}/VERSION ${pcap_SOURCE_DIR}/version.c.in
    ) 
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/pcap_version.h
        SOURCE ${pcap_SOURCE_DIR}/VERSION ${pcap_SOURCE_DIR}/pcap_version.h.in
        COMMAND ${GenVersion_path} ${VERSION_path} ${pcap_version_h_in_path} ${pcap_version_h_path}
        DEPENDS ${pcap_SOURCE_DIR}/VERSION ${pcap_SOURCE_DIR}/pcap_version.h.in
    )
else(WIN32 AND NOT MSYS AND NOT ${CMAKE_CROSSCOMPILING})
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/version.c
        SOURCE ${pcap_SOURCE_DIR}/VERSION
        COMMAND ${pcap_SOURCE_DIR}/gen_version.sh ${pcap_SOURCE_DIR}/VERSION ${pcap_SOURCE_DIR}/version.c.in ${CMAKE_CURRENT_BINARY_DIR}/version.c
        DEPENDS ${pcap_SOURCE_DIR}/VERSION
    )
    add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/pcap_version.h
        SOURCE ${pcap_SOURCE_DIR}/VERSION
        COMMAND ${pcap_SOURCE_DIR}/gen_version.sh ${pcap_SOURCE_DIR}/VERSION ${pcap_SOURCE_DIR}/pcap_version.h.in ${CMAKE_CURRENT_BINARY_DIR}/pcap_version.h
        DEPENDS ${pcap_SOURCE_DIR}/VERSION
    )

    #
    # Since version.c does not exists yet when cmake is run, mark
    # it as generated.
    #
    set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/version.c PROPERTIES
        GENERATED TRUE
    )

    #
    # Add version.c to the list of sources.
    #
    set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} ${CMAKE_CURRENT_BINARY_DIR}/version.c)
endif(WIN32 AND NOT MSYS AND NOT ${CMAKE_CROSSCOMPILING})

#
# Since pcap_version.h does not exists yet when cmake is run, mark
# it as generated.
#
set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/pcap_version.h PROPERTIES
    GENERATED TRUE
)

#
# Add pcap_version.h to the list of headers.
#
set(PROJECT_SOURCE_LIST_H ${PROJECT_SOURCE_LIST_H} ${CMAKE_CURRENT_BINARY_DIR}/pcap_version.h)

source_group("Source Files" FILES ${PROJECT_SOURCE_LIST_C})
source_group("Header Files" FILES ${PROJECT_SOURCE_LIST_H})

if(WIN32)
    #
    # Add pcap-dll.rc to the list of sources.
    #
    set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} ${pcap_SOURCE_DIR}/pcap-dll.rc)
endif(WIN32)

######################################
# Register targets
######################################

#
# Special target to serialize the building of the generated source.
#
# See
#
#  http://public.kitware.com/pipermail/cmake/2013-August/055510.html
#
add_custom_target(SerializeTarget
    DEPENDS
    ${CMAKE_CURRENT_BINARY_DIR}/grammar.c
    ${CMAKE_CURRENT_BINARY_DIR}/scanner.c
    ${CMAKE_CURRENT_BINARY_DIR}/version.c
)

set_source_files_properties(${PROJECT_EXTERNAL_OBJECT_LIST} PROPERTIES
    EXTERNAL_OBJECT TRUE)

if(BUILD_SHARED_LIBS)
    add_library(${LIBRARY_NAME} SHARED
        ${PROJECT_SOURCE_LIST_C}
        ${CMAKE_CURRENT_BINARY_DIR}/grammar.c
        ${CMAKE_CURRENT_BINARY_DIR}/scanner.c
        ${PROJECT_SOURCE_LIST_H}
        ${PROJECT_EXTERNAL_OBJECT_LIST}
    )
    add_dependencies(${LIBRARY_NAME} SerializeTarget)
endif(BUILD_SHARED_LIBS)

add_library(${LIBRARY_NAME}_static STATIC
    ${PROJECT_SOURCE_LIST_C}
    ${CMAKE_CURRENT_BINARY_DIR}/grammar.c
    ${CMAKE_CURRENT_BINARY_DIR}/scanner.c
    ${PROJECT_SOURCE_LIST_H}
    ${PROJECT_EXTERNAL_OBJECT_LIST}
)
add_dependencies(${LIBRARY_NAME}_static SerializeTarget)

if(WIN32)
    set_target_properties(${LIBRARY_NAME} PROPERTIES
        VERSION ${PACKAGE_VERSION_NOSUFFIX} # only MAJOR and MINOR are needed
    )
    if(MSVC)
        # XXX For DLLs, the TARGET_PDB_FILE generator expression can be used to locate
        # its PDB file's output directory for installation.
        # cmake doesn't offer a generator expression for PDB files generated by the
        # compiler (static libraries).
        # So instead of considering any possible output there is (there are many),
        # this will search for the PDB file in the compiler's initial output directory,
        # which is always ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles\wpcap_static.dir
        # regardless of architecture, build generator etc.
        # Quite hackish indeed.
        set(CMAKE_COMPILE_PDB_OUTPUT_DIRECTORY $<TARGET_FILE_DIR:${LIBRARY_NAME}_static>)
        set_target_properties(${LIBRARY_NAME}_static PROPERTIES
            COMPILE_PDB_NAME ${LIBRARY_NAME}_static
            OUTPUT_NAME "${LIBRARY_NAME}_static"
        )
    elseif(MINGW)
        #
        # For compatibility, build the shared library without the "lib" prefix on
        # MinGW as well.
        #
        set_target_properties(${LIBRARY_NAME} PROPERTIES 
            PREFIX ""
            OUTPUT_NAME "${LIBRARY_NAME}"
        )
        set_target_properties(${LIBRARY_NAME}_static PROPERTIES
            OUTPUT_NAME "${LIBRARY_NAME}"
        )
    endif()
else(WIN32) # UN*X
    set_target_properties(${LIBRARY_NAME} PROPERTIES
        VERSION ${PACKAGE_VERSION}
        SOVERSION ${PACKAGE_VERSION_MAJOR}
    )
    set_target_properties(${LIBRARY_NAME}_static PROPERTIES
        OUTPUT_NAME "${LIBRARY_NAME}"
    )
endif(WIN32)

if(BUILD_SHARED_LIBS)
    target_link_libraries(${LIBRARY_NAME} ${PCAP_LINK_LIBRARIES})
endif(BUILD_SHARED_LIBS)

######################################
# Write out the config.h file
######################################

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmakeconfig.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

######################################
# Install pcap library, include files, and man pages
######################################

set(LIBRARY_NAME_STATIC ${LIBRARY_NAME}_static)

function(install_manpage_symlink SOURCE TARGET MANDIR)
    install(CODE
        "message(STATUS \"Symlinking: ${CMAKE_INSTALL_PREFIX}/${MANDIR}/${SOURCE} to ${TARGET}\")
         execute_process(
            COMMAND \"${CMAKE_COMMAND}\" \"-E\" \"remove\" \"${TARGET}\"
            WORKING_DIRECTORY ${CMAKE_INSTALL_PREFIX}/${MANDIR}
          )
         execute_process(
            COMMAND \"${CMAKE_COMMAND}\" \"-E\" \"create_symlink\" \"${SOURCE}\" \"${TARGET}\"
            WORKING_DIRECTORY ${CMAKE_INSTALL_PREFIX}/${MANDIR}
            RESULT_VARIABLE EXIT_STATUS
          )
          if(NOT EXIT_STATUS EQUAL 0)
              message(FATAL_ERROR \"Could not create symbolic link from ${CMAKE_INSTALL_PREFIX}/${MANDIR}/${SOURCE} to ${TARGET}\")
          endif()
          set(CMAKE_INSTALL_MANIFEST_FILES \${CMAKE_INSTALL_MANIFEST_FILES} ${CMAKE_INSTALL_PREFIX}/${MANDIR}/${TARGET})")
endfunction(install_manpage_symlink)

set(MAN1_NOEXPAND pcap-config.1)
set(MAN3PCAP_EXPAND
	pcap.3pcap.in
	pcap_compile.3pcap.in
	pcap_datalink.3pcap.in
	pcap_dump_open.3pcap.in
	pcap_get_tstamp_precision.3pcap.in
	pcap_list_datalinks.3pcap.in
	pcap_list_tstamp_types.3pcap.in
	pcap_open_dead.3pcap.in
	pcap_open_offline.3pcap.in
	pcap_set_tstamp_precision.3pcap.in
	pcap_set_tstamp_type.3pcap.in
)
set(MAN3PCAP_NOEXPAND
	pcap_activate.3pcap
	pcap_breakloop.3pcap
	pcap_can_set_rfmon.3pcap
	pcap_close.3pcap
	pcap_create.3pcap
	pcap_datalink_name_to_val.3pcap
	pcap_datalink_val_to_name.3pcap
	pcap_dump.3pcap
	pcap_dump_close.3pcap
	pcap_dump_file.3pcap
	pcap_dump_flush.3pcap
	pcap_dump_ftell.3pcap
	pcap_file.3pcap
	pcap_fileno.3pcap
	pcap_findalldevs.3pcap
	pcap_freecode.3pcap
	pcap_get_selectable_fd.3pcap
	pcap_geterr.3pcap
	pcap_inject.3pcap
	pcap_is_swapped.3pcap
	pcap_lib_version.3pcap
	pcap_lookupdev.3pcap
	pcap_lookupnet.3pcap
	pcap_loop.3pcap
	pcap_major_version.3pcap
	pcap_next_ex.3pcap
	pcap_offline_filter.3pcap
	pcap_open_live.3pcap
	pcap_set_buffer_size.3pcap
	pcap_set_datalink.3pcap
	pcap_set_immediate_mode.3pcap
	pcap_set_promisc.3pcap
	pcap_set_protocol.3pcap
	pcap_set_rfmon.3pcap
	pcap_set_snaplen.3pcap
	pcap_set_timeout.3pcap
	pcap_setdirection.3pcap
	pcap_setfilter.3pcap
	pcap_setnonblock.3pcap
	pcap_snapshot.3pcap
	pcap_stats.3pcap
	pcap_statustostr.3pcap
	pcap_strerror.3pcap
	pcap_tstamp_type_name_to_val.3pcap
	pcap_tstamp_type_val_to_name.3pcap
)
set(MANFILE_EXPAND pcap-savefile.manfile.in)
set(MANMISC_EXPAND
	pcap-filter.manmisc.in
	pcap-linktype.manmisc.in
	pcap-tstamp.manmisc.in
)

if(NOT BUILD_SHARED_LIBS)
    unset(LIBRARY_NAME)
endif(NOT BUILD_SHARED_LIBS)

if(WIN32)
    if(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8)
        #
        # Install 64-bit code built with MSVC in the amd64 subdirectories,
        # as that's where it expects it to be.
        #
        install(TARGETS ${LIBRARY_NAME} ${LIBRARY_NAME_STATIC}
                RUNTIME DESTINATION bin/amd64
                LIBRARY DESTINATION lib/amd64
                ARCHIVE DESTINATION lib/amd64)
        if(NOT MINGW)
            install(FILES $<TARGET_FILE_DIR:${LIBRARY_NAME_STATIC}>/${LIBRARY_NAME_STATIC}.pdb
                    DESTINATION bin/amd64 OPTIONAL)
            if(BUILD_SHARED_LIBS)
                install(FILES $<TARGET_PDB_FILE:${LIBRARY_NAME}>
                        DESTINATION bin/amd64 OPTIONAL)
            endif(BUILD_SHARED_LIBS)
        endif(NOT MINGW)
    else(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8)
        #
        # Install 32-bit code, and 64-bit code not built with MSVC
        # in the top-level directories, as those are where they
        # expect it to be.
        #
        install(TARGETS ${LIBRARY_NAME} ${LIBRARY_NAME_STATIC}
                RUNTIME DESTINATION bin
                LIBRARY DESTINATION lib
                ARCHIVE DESTINATION lib)
        if(NOT MINGW)
            install(FILES $<TARGET_FILE_DIR:${LIBRARY_NAME_STATIC}>/${LIBRARY_NAME_STATIC}.pdb
                    DESTINATION bin OPTIONAL)
            if(BUILD_SHARED_LIBS)
                install(FILES $<TARGET_PDB_FILE:${LIBRARY_NAME}>
                        DESTINATION bin OPTIONAL)
            endif(BUILD_SHARED_LIBS)
        endif(NOT MINGW)
    endif(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8)
else(WIN32)
    install(TARGETS ${LIBRARY_NAME} ${LIBRARY_NAME_STATIC} DESTINATION lib)

    #
    # Man pages.
    #
    # For each section of the manual for which we have man pages
    # that require macro expansion, do the expansion.
    #
    # XXX - symlinks.
    #
    set(MAN1 "")
    foreach(MANPAGE ${MAN1_NOEXPAND})
        set(MAN1 ${MAN1} ${CMAKE_SOURCE_DIR}/${MANPAGE})
    endforeach(MANPAGE)
    install(FILES ${MAN1} DESTINATION man/man1)

    set(MAN3PCAP "")
    foreach(MANPAGE ${MAN3PCAP_NOEXPAND})
        set(MAN3PCAP ${MAN3PCAP} ${CMAKE_SOURCE_DIR}/${MANPAGE})
    endforeach(MANPAGE)
    foreach(TEMPLATE_MANPAGE ${MAN3PCAP_EXPAND})
        string(REPLACE ".in" "" MANPAGE ${TEMPLATE_MANPAGE})
        configure_file(${CMAKE_SOURCE_DIR}/${TEMPLATE_MANPAGE} ${CMAKE_CURRENT_BINARY_DIR}/${MANPAGE} @ONLY)
        set(MAN3PCAP ${MAN3PCAP} ${CMAKE_CURRENT_BINARY_DIR}/${MANPAGE})
    endforeach(TEMPLATE_MANPAGE)
    install(FILES ${MAN3PCAP} DESTINATION man/man3)
    install_manpage_symlink(pcap_datalink_val_to_name.3pcap pcap_datalink_val_to_description.3pcap man/man3)
    install_manpage_symlink(pcap_dump_open.3pcap pcap_dump_fopen.3pcap man/man3)
    install_manpage_symlink(pcap_findalldevs.3pcap pcap_freealldevs.3pcap man/man3)
    install_manpage_symlink(pcap_geterr.3pcap pcap_perror.3pcap man/man3)
    install_manpage_symlink(pcap_inject.3pcap pcap_sendpacket.3pcap man/man3)
    install_manpage_symlink(pcap_list_datalinks.3pcap pcap_free_datalinks.3pcap man/man3)
    install_manpage_symlink(pcap_list_tstamp_types.3pcap pcap_free_tstamp_types.3pcap man/man3)
    install_manpage_symlink(pcap_loop.3pcap pcap_dispatch.3pcap man/man3)
    install_manpage_symlink(pcap_major_version.3pcap pcap_minor_version.3pcap man/man3)
    install_manpage_symlink(pcap_next_ex.3pcap pcap_next.3pcap man/man3)
    install_manpage_symlink(pcap_open_dead.3pcap pcap_open_dead_with_tstamp_precision.3pcap man/man3)
    install_manpage_symlink(pcap_open_offline.3pcap pcap_open_offline_with_tstamp_precision.3pcap man/man3)
    install_manpage_symlink(pcap_open_offline.3pcap pcap_fopen_offline.3pcap man/man3)
    install_manpage_symlink(pcap_open_offline.3pcap pcap_fopen_offline_with_tstamp_precision.3pcap man/man3)
    install_manpage_symlink(pcap_tstamp_type_val_to_name.3pcap pcap_tstamp_type_val_to_description.3pcap man/man3)
    install_manpage_symlink(pcap_setnonblock.3pcap pcap_getnonblock.3pcap man/man3)

    set(MANFILE "")
    foreach(TEMPLATE_MANPAGE ${MANFILE_EXPAND})
        string(REPLACE ".manfile.in" ".${MAN_FILE_FORMATS}" MANPAGE ${TEMPLATE_MANPAGE})
        configure_file(${CMAKE_SOURCE_DIR}/${TEMPLATE_MANPAGE} ${CMAKE_CURRENT_BINARY_DIR}/${MANPAGE} @ONLY)
        set(MANFILE ${MANFILE} ${CMAKE_CURRENT_BINARY_DIR}/${MANPAGE})
    endforeach(TEMPLATE_MANPAGE)
    install(FILES ${MANFILE} DESTINATION man/man${MAN_FILE_FORMATS})

    set(MANMISC "")
    foreach(TEMPLATE_MANPAGE ${MANMISC_EXPAND})
        string(REPLACE ".manmisc.in" ".${MAN_MISC_INFO}" MANPAGE ${TEMPLATE_MANPAGE})
        configure_file(${CMAKE_SOURCE_DIR}/${TEMPLATE_MANPAGE} ${CMAKE_CURRENT_BINARY_DIR}/${MANPAGE} @ONLY)
        set(MANMISC ${MANMISC} ${CMAKE_CURRENT_BINARY_DIR}/${MANPAGE})
    endforeach(TEMPLATE_MANPAGE)
    install(FILES ${MANMISC} DESTINATION man/man${MAN_MISC_INFO})
endif(WIN32)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/pcap/ DESTINATION include/pcap)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/pcap.h DESTINATION include)

# uninstall target
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
