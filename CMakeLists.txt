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
if(MSVC)
    option(USE_STATIC_RT "Use static Runtime" ON)
endif(MSVC)
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
if(WIN32)
    set(PACKET_DLL_DIR "" CACHE PATH "Path to directory with include and lib subdirectories for packet.dll")
endif(WIN32)

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
    option(BUILD_WITH_LIBNL "Build with libnl" ON)
endif()

######################################
# Project settings
######################################

add_definitions(-DHAVE_CONFIG_H)

include_directories(
    ${CMAKE_CURRENT_BINARY_DIR}
    ${pcap_SOURCE_DIR}
)

include(CheckFunctionExists)

if(WIN32)

    if(IS_DIRECTORY ${CMAKE_HOME_DIRECTORY}/../../Common)
        include_directories(${CMAKE_HOME_DIRECTORY}/../../Common)
    endif(IS_DIRECTORY ${CMAKE_HOME_DIRECTORY}/../../Common)

    find_package(Packet)
    if(PACKET_FOUND)
        set(HAVE_PACKET32 TRUE)
        set(CMAKE_REQUIRED_LIBRARIES ${PACKET_LIBRARY})
        include_directories(${PACKET_INCLUDE_DIR})
        #
        # Check whether we have the NPcap PacketIsLoopbackAdapter()
        # function.
        #
        check_function_exists(PacketIsLoopbackAdapter HAVE_PACKET_IS_LOOPBACK_ADAPTER)
    endif(PACKET_FOUND)

    include_directories(
        ../Common/
        Win32/Include
        Win32/WpdPack/Include
    )
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

if(MSVC)
    if(USE_STATIC_RT)
        message(STATUS "Use STATIC runtime")
        foreach(RT_FLAG
            CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
            CMAKE_C_FLAGS_MINSIZEREL CMAKE_C_FLAGS_RELWITHDEBINFO
            CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELEASE
            CMAKE_CXX_FLAGS_MINSIZEREL CMAKE_CXX_FLAGS_RELWITHDEBINFO)
            string(REGEX REPLACE "/MD" "/MT" ${RT_FLAG} "${${RT_FLAG}}")
        endforeach(RT_FLAG)
    else (USE_STATIC_RT)
        message(STATUS "Use DYNAMIC runtime")
   endif(USE_STATIC_RT)
endif(MSVC)

###################################################################
#   Detect available platform features
###################################################################

include(CheckIncludeFile)
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
    check_include_file(linux/if_bonding.h HAVE_LINUX_IF_BONDING_H)
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

if(WIN32)
    add_definitions(-DHAVE_ADDRINFO)
endif(WIN32)

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
else()
    #
    # UN*X.
    #
    # Figure out what type of packet capture mechanism we have, and
    # what libraries we'd need to link libpcap with, if any.
    #
    set(PCAP_LINK_LIBRARIES "")

    #
    # Check for a bunch of headers for various packet capture mechanisms.
    #
    include(CheckIncludeFiles)
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
endif(WIN32)
message(STATUS "Packet capture mechanism type: ${PCAP_TYPE}")
set(PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} pcap-${PCAP_TYPE}.c)


#
# Do capture-mechanism-dependent tests.
#
if(PCAP_TYPE STREQUAL "npf")
    #
    # Link with packet.dll before WinSock2.
    #
    set(PCAP_LINK_LIBRARIES ${PACKET_LIBRARY} ${PCAP_LINK_LIBRARIES})
elseif(PCAP_TYPE STREQUAL "dlpi")
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
    #
    check_include_file(linux/wireless.h HAVE_LINUX_WIRELESS_H)

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
endif()

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
    #
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
elseif(CMAKE_SYSTEM_NAME STREQUAL "SunOS" AND CMAKE_SYSTEM_VERSION MATCHES "5[.][0-9.]*")
    #
    # SunOS 5.x.
    #
    set(HAVE_SOLARIS TRUE)
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

if(BUILD_SHARED_LIBS)
    add_library(${LIBRARY_NAME} SHARED
        ${PROJECT_SOURCE_LIST_C}
        ${CMAKE_CURRENT_BINARY_DIR}/grammar.c
        ${CMAKE_CURRENT_BINARY_DIR}/scanner.c
        ${PROJECT_SOURCE_LIST_H}
    )
    add_dependencies(${LIBRARY_NAME} SerializeTarget)
endif(BUILD_SHARED_LIBS)

add_library(${LIBRARY_NAME}_static STATIC
    ${PROJECT_SOURCE_LIST_C}
    ${CMAKE_CURRENT_BINARY_DIR}/grammar.c
    ${CMAKE_CURRENT_BINARY_DIR}/scanner.c
    ${PROJECT_SOURCE_LIST_H}
)
add_dependencies(${LIBRARY_NAME}_static SerializeTarget)

if(MSVC)
    foreach(DBG_FLAGS
        CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELWITHDEBINFO
        CMAKE_CXX_FLAGS_DEBUG CMAKE_CXX_FLAGS_RELWITHDEBINFO)
        string(REGEX REPLACE "/Zi" "" ${DBG_FLAGS} "${${DBG_FLAGS}}")
    endforeach(DBG_FLAGS)

    if(BUILD_SHARED_LIBS)
        set_target_properties(${LIBRARY_NAME} PROPERTIES COMPILE_OPTIONS "/Zi")
    endif(BUILD_SHARED_LIBS)
    set_target_properties(${LIBRARY_NAME}_static PROPERTIES COMPILE_OPTIONS "/Z7")
elseif(MINGW)
    #
    # For compatibility, build the shared library without the "lib" prefix on
    # MinGW as well.
    #
    set_target_properties(${LIBRARY_NAME} PROPERTIES PREFIX "" OUTPUT_NAME "${LIBRARY_NAME}")
    set_target_properties(${LIBRARY_NAME}_static PROPERTIES OUTPUT_NAME "${LIBRARY_NAME}")
else()
    set_target_properties(${LIBRARY_NAME}_static PROPERTIES OUTPUT_NAME "${LIBRARY_NAME}")
endif()

if(BUILD_SHARED_LIBS)
    target_link_libraries(${LIBRARY_NAME} ${PCAP_LINK_LIBRARIES})
endif(BUILD_SHARED_LIBS)

######################################
# Write out the config.h file
######################################

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmakeconfig.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

######################################
# Install pcap library and include files
######################################

set(LIBRARY_NAME_STATIC ${LIBRARY_NAME}_static)

if(NOT BUILD_SHARED_LIBS)
    unset(LIBRARY_NAME)
endif(NOT BUILD_SHARED_LIBS)

if(WIN32)
    if(CMAKE_CL_64)
        #
        # Install 64-bit code built with MSVC in the amd64 subdirectories,
        # as that's where it expects it to be.
        #
        install(TARGETS ${LIBRARY_NAME} ${LIBRARY_NAME_STATIC}
                RUNTIME DESTINATION bin/amd64
                LIBRARY DESTINATION lib/amd64
                ARCHIVE DESTINATION lib/amd64)
        if(BUILD_SHARED_LIBS AND NOT MINGW)
            install(FILES $<TARGET_PDB_FILE:${LIBRARY_NAME}>
                    DESTINATION bin/amd64 OPTIONAL)
        endif(BUILD_SHARED_LIBS AND NOT MINGW)
    else(CMAKE_CL_64)
        #
        # Install 32-bit code, and 64-bit code not built with MSVC
        # in the top-level directories, as those are where they
        # expect it to be.
        #
        install(TARGETS ${LIBRARY_NAME} ${LIBRARY_NAME_STATIC}
                RUNTIME DESTINATION bin
                LIBRARY DESTINATION lib
                ARCHIVE DESTINATION lib)
        if(BUILD_SHARED_LIBS AND NOT MINGW)
            install(FILES $<TARGET_PDB_FILE:${LIBRARY_NAME}>
                    DESTINATION bin OPTIONAL)
        endif(BUILD_SHARED_LIBS AND NOT MINGW)
    endif(CMAKE_CL_64)
else(WIN32)
    install(TARGETS ${LIBRARY_NAME} ${LIBRARY_NAME_STATIC} DESTINATION lib)
endif(WIN32)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/pcap/ DESTINATION include/pcap)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/pcap.h DESTINATION include)
