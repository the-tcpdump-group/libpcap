# Try to find dpdk
#
# Once done, this will define
#
# dpdk_FOUND
# dpdk_INCLUDE_DIRS
# dpdk_LIBRARIES

#
# We only try to find DPDK using pkg-config; DPDK is *SO*
# complicated - DPDK 19.02, for example, has about 117(!)
# libraries, and the precise set of libraries required has
# changed over time  - so attempting to guess which libraries
# you need, and hardcoding that in an attempt to find the
# libraries without DPDK, rather than relying on DPDK to
# tell you, with a .pc file, what libraries are needed,
# is *EXTREMELY* fragile and has caused some bug reports,
# so we're just not going to do it.
#
# If that causes a problem, the only thing we will do is
# accept an alternative way of finding the appropriate
# library set for the installed version of DPDK that is
# as robust as pkg-config (i.e., it had better work as well
# as pkg-config with *ALL* versions of DPDK that provide a
# libdpdk.pc file).
#
# If dpdk_ROOT is set, add ${dpdk_ROOT}/pkgconfig
# to PKG_CONFIG_PATH, so we look for the .pc file there,
# first.
#
if(PKG_CONFIG_FOUND)
  set(save_PKG_CONFIG_PATH $ENV{PKG_CONFIG_PATH})
  if(dpdk_ROOT)
    set(ENV{PKG_CONFIG_PATH} "${dpdk_ROOT}/pkgconfig:$ENV{PKG_CONFIG_PATH}")
  endif()
  pkg_check_modules(dpdk QUIET libdpdk)
  set(ENV{PKG_CONFIG_PATH} "${save_PKG_CONFIG_PATH}")
endif()

mark_as_advanced(dpdk_INCLUDE_DIRS ${dpdk_LIBRARIES})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(dpdk DEFAULT_MSG
  dpdk_INCLUDE_DIRS
  dpdk_LIBRARIES)

if(dpdk_FOUND)
  if(NOT TARGET dpdk::cflags)
     if(CMAKE_SYSTEM_PROCESSOR MATCHES "amd64|x86_64|AMD64")
      set(rte_cflags "-march=core2")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm|ARM")
      set(rte_cflags "-march=armv7-a")
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|AARCH64")
      set(rte_cflags "-march=armv8-a+crc")
    endif()
    add_library(dpdk::cflags INTERFACE IMPORTED)
    if (rte_cflags)
      set_target_properties(dpdk::cflags PROPERTIES
        INTERFACE_COMPILE_OPTIONS "${rte_cflags}")
    endif()
  endif()

  if(NOT TARGET dpdk::dpdk)
    add_library(dpdk::dpdk INTERFACE IMPORTED)
    find_package(Threads QUIET)
    list(APPEND dpdk_LIBRARIES
      Threads::Threads
      dpdk::cflags)
    set_target_properties(dpdk::dpdk PROPERTIES
      INTERFACE_LINK_LIBRARIES "${dpdk_LIBRARIES}"
      INTERFACE_INCLUDE_DIRECTORIES "${dpdk_INCLUDE_DIRS}")
  endif()
endif()
