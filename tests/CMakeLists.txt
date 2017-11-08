if(MSVC)
    file(GLOB PROJECT_SOURCE_LIST_WIN32_C
        ${pcap_SOURCE_DIR}/missing/getopt.c
   )
endif(MSVC)

add_custom_target(tests)

add_executable(can_set_rfmon_test EXCLUDE_FROM_ALL
  can_set_rfmon_test.c ${PROJECT_SOURCE_LIST_WIN32_C})
target_link_libraries(can_set_rfmon_test pcap)
add_dependencies(tests can_set_rfmon_test)

add_executable(capturetest EXCLUDE_FROM_ALL
  capturetest.c ${PROJECT_SOURCE_LIST_WIN32_C})
target_link_libraries(capturetest pcap)
add_dependencies(tests capturetest)

add_executable(filtertest EXCLUDE_FROM_ALL
  filtertest.c ${PROJECT_SOURCE_LIST_WIN32_C})
target_link_libraries(filtertest pcap)
add_dependencies(tests filtertest)

add_executable(findalldevstest EXCLUDE_FROM_ALL
  findalldevstest.c ${PROJECT_SOURCE_LIST_WIN32_C})
target_link_libraries(findalldevstest pcap)
add_dependencies(tests findalldevstest)

add_executable(opentest EXCLUDE_FROM_ALL
  opentest.c ${PROJECT_SOURCE_LIST_WIN32_C})
target_link_libraries(opentest pcap)
add_dependencies(tests opentest)

add_executable(reactivatetest EXCLUDE_FROM_ALL
  reactivatetest.c ${PROJECT_SOURCE_LIST_WIN32_C})
target_link_libraries(reactivatetest pcap)
add_dependencies(tests reactivatetest)

if(NOT WIN32)
  add_executable(selpolltest EXCLUDE_FROM_ALL
    selpolltest.c ${PROJECT_SOURCE_LIST_WIN32_C})
  target_link_libraries(selpolltest pcap)
  add_dependencies(tests selpolltest)
endif()

if(NOT WIN32)
  add_executable(threadsignaltest EXCLUDE_FROM_ALL
    threadsignaltest.c ${PROJECT_SOURCE_LIST_WIN32_C})
  target_link_libraries(threadsignaltest pcap ${CMAKE_THREAD_LIBS_INIT})
  add_dependencies(tests threadsignaltest)
endif()

if(NOT WIN32)
  add_executable(valgrindtest EXCLUDE_FROM_ALL
    valgrindtest.c ${PROJECT_SOURCE_LIST_WIN32_C})
  target_link_libraries(valgrindtest pcap)  
  add_dependencies(tests valgrindtest)
endif()
