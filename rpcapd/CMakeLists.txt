set(CMAKE_THREAD_PREFER_PTHREAD 1)
find_package(Threads REQUIRED)
if(NOT MSVC)
  find_package(Threads REQUIRED)
  if(CMAKE_USE_PTHREADS_INIT)
    set(PCAP_LINK_LIBRARIES ${PCAP_LINK_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
  else(CMAKE_USE_PTHREADS_INIT)
    message(WARNING "Pthreads not found. Won't be able to build rpcapd.")
  endif(CMAKE_USE_PTHREADS_INIT)
else(NOT MSVC)
# tell cmake to look for pthreads-w32 so that it uses
# our custom module in [pcap root]/cmake/FindPthreads-w32.cmake
# instead of the standard FindThreads.cmake
  find_package(Pthreads-w32 REQUIRED) 
  if(PTHREADS_FOUND)
    set(PCAP_LINK_LIBRARIES ${PCAP_LINK_LIBRARIES} ${PTHREADS_LIBRARY})
    include_directories(${PTHREADS_INCLUDE_DIR})
  else(PTHREADS_FOUND)
    message(WARNING "Pthreads not found. Won't be able to build rpcapd.")
  endif(PTHREADS_FOUND)
endif(NOT MSVC)

if(CMAKE_USE_PTHREADS_INIT OR PTHREADS_FOUND)

set(BUILDING_RPCAPD 1)

if(WIN32)
set(RPCAPD_EXTRA_SOURCES win32-svc.c ${PCAP_DLL_RC})
add_definitions(-DWIN32_LEAN_AND_MEAN -DBUILDING_RPCAPD)
include_directories(${pcap_SOURCE_DIR}/rpcapd)
endif(WIN32)

add_executable(rpcapd
  daemon.c
  fileconf.c
  rpcapd.c
  utils.c
  ${RPCAPD_EXTRA_SOURCES}
)

if(UNIX)
  set(PCAP_LINK_LIBRARIES ${PCAP_LINK_LIBRARIES} crypt)
endif(UNIX)

target_link_libraries(rpcapd ${LIBRARY_NAME}_static ${PCAP_LINK_LIBRARIES})

endif(CMAKE_USE_PTHREADS_INIT OR PTHREADS_FOUND)
