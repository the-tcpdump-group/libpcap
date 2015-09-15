cmake_minimum_required( VERSION 2.8.8 )

project( pcap_tests )

######################################
# Register targets
######################################

ADD_EXECUTABLE (can_set_rfmon_test can_set_rfmon_test.c )
target_link_libraries ( can_set_rfmon_test pcap )

ADD_EXECUTABLE (capturetest capturetest.c )
target_link_libraries ( capturetest pcap )

ADD_EXECUTABLE (filtertest filtertest.c )
target_link_libraries ( filtertest pcap )

ADD_EXECUTABLE (indalldevstest findalldevstest.c )
target_link_libraries ( indalldevstest pcap )

ADD_EXECUTABLE (opentest opentest.c )
target_link_libraries ( opentest pcap )

#ADD_EXECUTABLE (pcap_compile_test pcap_compile_test.c )
#target_link_libraries ( pcap_compile_test pcap )

ADD_EXECUTABLE (reactivatetest reactivatetest.c )
target_link_libraries ( reactivatetest pcap )

if( NOT WIN32 )
    ADD_EXECUTABLE (selpolltest selpolltest.c )
    target_link_libraries ( selpolltest pcap )
endif()

ADD_EXECUTABLE (valgrindtest valgrindtest.c )
target_link_libraries ( valgrindtest pcap )
