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
# On UN*X, we need pthreads and crypt().
#
if(WIN32 OR ((CMAKE_USE_PTHREADS_INIT OR PTHREADS_FOUND) AND HAVE_CRYPT))
  if(UNIX)
    #
    # Do we have getspnam()?
    #
    check_function_exists(getspnam HAVE_GETSPNAM)
  endif(UNIX)

  if(WIN32)
    set(RPCAPD_EXTRA_SOURCES win32-svc.c ${pcap_SOURCE_DIR}/missing/getopt.c rpcapd.rc)
    include_directories(${pcap_SOURCE_DIR}/rpcapd ${pcap_SOURCE_DIR}/missing)
  endif(WIN32)

  add_executable(rpcapd
    daemon.c
    fileconf.c
    log-stderr.c
    rpcapd.c
    ${RPCAPD_EXTRA_SOURCES}
  )

  set_target_properties(rpcapd PROPERTIES
    COMPILE_OPTIONS "${C_ADDITIONAL_FLAGS}")

  target_link_libraries(rpcapd ${LIBRARY_NAME}_static
    ${RPCAPD_LINK_LIBRARIES} ${PCAP_LINK_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

  if(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    install(TARGETS rpcapd DESTINATION bin/amd64)
  else(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    install(TARGETS rpcapd DESTINATION bin)
  endif(MSVC AND CMAKE_SIZEOF_VOID_P EQUAL 8)
endif(WIN32 OR ((CMAKE_USE_PTHREADS_INIT OR PTHREADS_FOUND) AND HAVE_CRYPT))
