add_executable(fuzz_pcap onefile.c fuzz_pcap.c)
target_link_libraries(fuzz_pcap ${ARGN} ${LIBRARY_NAME}_static ${PCAP_LINK_LIBRARIES})

add_executable(fuzz_filter onefile.c fuzz_filter.c)
target_link_libraries(fuzz_filter ${ARGN} ${LIBRARY_NAME}_static ${PCAP_LINK_LIBRARIES})

add_executable(fuzz_both onefile.c fuzz_both.c)
target_link_libraries(fuzz_both ${ARGN} ${LIBRARY_NAME}_static ${PCAP_LINK_LIBRARIES})
