set(CMAKE_THREAD_PREFER_PTHREAD 1)
if(NOT MSVC)
  find_package(Threads REQUIRED)
  if(CMAKE_USE_PTHREADS_INIT)
    set(RPCAPD_LINK_LIBRARIES ${RPCAPD_LINK_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
  else(CMAKE_USE_PTHREADS_INIT)
    message(WARNING "Pthreads not found. Won't be able to build rpcapd.")
  endif(CMAKE_USE_PTHREADS_INIT)
else(NOT MSVC)
# tell cmake to look for pthreads-w32 so that it uses
# our custom module in [pcap root]/cmake/FindPthreads-w32.cmake
# instead of the standard FindThreads.cmake
  find_package(Pthreads-w32 REQUIRED) 
  if(PTHREADS_FOUND)
    set(RPCAPD_LINK_LIBRARIES ${RPCAPD_LINK_LIBRARIES} ${PTHREADS_LIBRARY})
    include_directories(${PTHREADS_INCLUDE_DIR})
  else(PTHREADS_FOUND)
    message(WARNING "Pthreads not found. Won't be able to build rpcapd.")
  endif(PTHREADS_FOUND)
endif(NOT MSVC)

if(UNIX)
  check_function_exists(crypt HAVE_CRYPT_IN_SYSTEM_LIBRARIES)
  if(HAVE_CRYPT_IN_SYSTEM_LIBRARIES)
    set(HAVE_CRYPT TRUE)
  else(HAVE_CRYPT_IN_SYSTEM_LIBRARIES)
    check_library_exists(crypt crypt "" HAVE_CRYPT_IN_LIBCRYPT)
    if(HAVE_CRYPT_IN_LIBCRYPT)
      set(RPCAPD_LINK_LIBRARIES ${RPCAPD_LINK_LIBRARIES} crypt)
      set(HAVE_CRYPT TRUE)
    else(HAVE_CRYPT_IN_LIBCRYPT)
      message(WARNING "crypt() not found. Won't be able to build rpcapd.")
    endif(HAVE_CRYPT_IN_LIBCRYPT)
  endif(HAVE_CRYPT_IN_SYSTEM_LIBRARIES)
endif(UNIX)

#
# We need pthreads and, on UN*X, we need crypt().
#
if((CMAKE_USE_PTHREADS_INIT OR PTHREADS_FOUND) AND (WIN32 OR HAVE_CRYPT))

  if(UNIX)
    #
    # Do we have getspnam()?
    #
    check_function_exists(getspnam HAVE_GETSPNAM)
  endif(UNIX)

  if(WIN32)
    set(RPCAPD_EXTRA_SOURCES win32-svc.c rpcapd.rc)
    include_directories(${pcap_SOURCE_DIR}/rpcapd)
  endif(WIN32)

  add_executable(rpcapd
    daemon.c
    fileconf.c
    log-stderr.c
    rpcapd.c
    utils.c
    ${RPCAPD_EXTRA_SOURCES}
  )

  target_link_libraries(rpcapd ${LIBRARY_NAME}_static
    ${RPCAPD_LINK_LIBRARIES} ${PCAP_LINK_LIBRARIES})

  if(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    install(TARGETS rpcapd DESTINATION bin/amd64)
  else(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    install(TARGETS rpcapd DESTINATION bin)
  endif(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8)

endif((CMAKE_USE_PTHREADS_INIT OR PTHREADS_FOUND) AND (WIN32 OR HAVE_CRYPT))
