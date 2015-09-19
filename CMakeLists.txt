cmake_minimum_required( VERSION 2.8.8 )

set( PROJECT_NAME pcap )
project( ${PROJECT_NAME} )

include( cmake/preconfigure.cmake )
file( WRITE "${CMAKE_BINARY_DIR}/config.h" "${CONFIG_H_CONTENT}" )

######################################
# Project setings
######################################

include_directories(
    ${CMAKE_BINARY_DIR}
    ${pcap_SOURCE_DIR}
    ${AirPcap_INCLUDE_DIRS}
)

if( WIN32 ) 
    include_directories(
        ../Common/
        Win32/Include
    )
endif( WIN32)

######################################
# Input files
######################################

file(GLOB PROJECT_SOURCE_LIST_CORE_C
    bpf_dump.c
    bpf_image.c
    etherent.c
    gencode.c
    grammar.c
    inet.c
    nametoaddr.c
    optimize.c
    pcap-common.c
    pcap-new.c
    pcap.c
    savefile.c
    scanner.c
    sf-pcap-ng.c
    sf-pcap.c
    sockutils.c
    missing/snprintf.c
    bpf/net/bpf_filter.c
)

set( PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} ${PROJECT_SOURCE_LIST_CORE_C} )

if( WIN32 )
    file(GLOB PROJECT_SOURCE_LIST_WIN32_C
        fad-win32.c
        pcap-win32.c
        Win32/Src/ffs.c
        Win32/Src/getservent.c
    )

    set( PROJECT_SOURCE_LIST_C ${PROJECT_SOURCE_LIST_C} ${PROJECT_SOURCE_LIST_WIN32_C} )
endif( WIN32 )

file(GLOB PROJECT_SOURCE_LIST_CORE_H
    *.h
    pcap/*.h
)
set( PROJECT_SOURCE_LIST_H ${PROJECT_SOURCE_LIST_H} ${PROJECT_SOURCE_LIST_CORE_H} )

if( WIN32 )
    file(GLOB PROJECT_SOURCE_LIST_WIN32_H
        Win32/Include/*.h
    )
    set( PROJECT_SOURCE_LIST_H ${PROJECT_SOURCE_LIST_H} ${PROJECT_SOURCE_LIST_WIN32_H} )
endif( WIN32 )

source_group("Source Files" FILES ${PROJECT_SOURCE_LIST_C})
source_group("Header Files" FILES ${PROJECT_SOURCE_LIST_H})

######################################
# Register targets
######################################

add_library (${PROJECT_NAME} ${PROJECT_SOURCE_LIST_C} ${PROJECT_SOURCE_LIST_H})

if( WIN32 )
    target_link_libraries ( ${PROJECT_NAME} 
        packet
        ws2_32
    )
endif( WIN32 )

add_subdirectory( tests )
