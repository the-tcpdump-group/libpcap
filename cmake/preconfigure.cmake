###################################################################
#   Parameters
###################################################################

option (USE_STATIC_RT "Use static Runtime" ON)
option (USE_IPV6 "Enable IPv6" ON)

if( NOT LIBPCAP_PRECONFIGURED )
    set( LIBPCAP_PRECONFIGURED TRUE )

    ######################################
    # Project setings
    ######################################

    add_definitions( -DLIBPCAP_EXPORTS )

    if( MSVC )
        add_definitions( -D__STDC__ )
        add_definitions( -D_CRT_SECURE_NO_WARNINGS )
        add_definitions( "-D_U_=" )
    elseif( CMAKE_COMPILER_IS_GNUCXX )
        add_definitions( "-D_U_=__attribute__((unused))" )
    else(MSVC)
        add_definitions( "-D_U_=" )
    endif( MSVC )

    if (USE_STATIC_RT)
        MESSAGE( STATUS "Use STATIC runtime" )

        if( MSVC )
            set (CMAKE_CXX_FLAGS_MINSIZEREL     "${CMAKE_CXX_FLAGS_MINSIZEREL} /MT")
            set (CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /MT")
            set (CMAKE_CXX_FLAGS_RELEASE        "${CMAKE_CXX_FLAGS_RELEASE} /MT")
            set (CMAKE_CXX_FLAGS_DEBUG          "${CMAKE_CXX_FLAGS_DEBUG} /MTd")

            set (CMAKE_C_FLAGS_MINSIZEREL       "${CMAKE_C_FLAGS_MINSIZEREL} /MT")
            set (CMAKE_C_FLAGS_RELWITHDEBINFO   "${CMAKE_C_FLAGS_RELWITHDEBINFO} /MT")
            set (CMAKE_C_FLAGS_RELEASE          "${CMAKE_C_FLAGS_RELEASE} /MT")
            set (CMAKE_C_FLAGS_DEBUG            "${CMAKE_C_FLAGS_DEBUG} /MTd")
        endif( MSVC )
    else (USE_STATIC_RT)
        MESSAGE( STATUS "Use DYNAMIC runtime" )

        if( MSVC )
            set (CMAKE_CXX_FLAGS_MINSIZEREL     "${CMAKE_CXX_FLAGS_MINSIZEREL} /MD")
            set (CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /MD")
            set (CMAKE_CXX_FLAGS_RELEASE        "${CMAKE_CXX_FLAGS_RELEASE} /MD")
            set (CMAKE_CXX_FLAGS_DEBUG          "${CMAKE_CXX_FLAGS_DEBUG} /MDd")

            set (CMAKE_C_FLAGS_MINSIZEREL       "${CMAKE_C_FLAGS_MINSIZEREL} /MD")
            set (CMAKE_C_FLAGS_RELWITHDEBINFO   "${CMAKE_C_FLAGS_RELWITHDEBINFO} /MD")
            set (CMAKE_C_FLAGS_RELEASE          "${CMAKE_C_FLAGS_RELEASE} /MD")
            set (CMAKE_C_FLAGS_DEBUG            "${CMAKE_C_FLAGS_DEBUG} /MDd")
        endif( MSVC )
    endif (USE_STATIC_RT)

    try_compile( HAVE_STRINGS_H ${CMAKE_BINARY_DIR} "${pcap_SOURCE_DIR}/config/have_strings.c"  )
    message( STATUS "HAVE_STRINGS_H = ${HAVE_STRINGS_H}" )
    if( HAVE_STRINGS_H )
        set( CONFIG_H_CONTENT "${CONFIG_H_CONTENT}#define HAVE_STRINGS_H\n" )
        add_definitions( -DHAVE_STRINGS_H )
    endif( HAVE_STRINGS_H )

    try_compile( HAVE_INTTYPES_H ${CMAKE_BINARY_DIR} "${pcap_SOURCE_DIR}/config/have_inttypes.c"  )
    message( STATUS "HAVE_INTTYPES_H = ${HAVE_INTTYPES_H}" )
    if( HAVE_INTTYPES_H )
        set( CONFIG_H_CONTENT "${CONFIG_H_CONTENT}#define HAVE_INTTYPES_H\n" )
        add_definitions( -DHAVE_INTTYPES_H )
    endif( HAVE_INTTYPES_H )

    try_compile( HAVE_STDINT_H ${CMAKE_BINARY_DIR} "${pcap_SOURCE_DIR}/config/have_stdint.c"  )
    message( STATUS "HAVE_STDINT_H = ${HAVE_STDINT_H}" )
    if( HAVE_STDINT_H )
        set( CONFIG_H_CONTENT "${CONFIG_H_CONTENT}#define HAVE_STDINT_H\n" )
        add_definitions( -DHAVE_STDINT_H )
    endif( HAVE_STDINT_H )

    try_compile( HAVE_UNISTD_H ${CMAKE_BINARY_DIR} "${pcap_SOURCE_DIR}/config/have_unistd.c"  )
    message( STATUS "HAVE_UNISTD_H = ${HAVE_UNISTD_H}" )
    if( HAVE_UNISTD_H )
        set( CONFIG_H_CONTENT "${CONFIG_H_CONTENT}#define HAVE_UNISTD_H\n" )
        add_definitions( -DHAVE_UNISTD_H )
    else( HAVE_UNISTD_H )
        add_definitions( -DYY_NO_UNISTD_H )
    endif( HAVE_UNISTD_H )

    try_compile( HAVE_STRERROR ${CMAKE_BINARY_DIR} "${pcap_SOURCE_DIR}/config/have_strerror.c"  )
    message( STATUS "HAVE_STRERROR = ${HAVE_STRERROR}" )
    if( HAVE_STRERROR )
        set( CONFIG_H_CONTENT "${CONFIG_H_CONTENT}#define HAVE_STRERROR\n" )
        add_definitions( -DHAVE_STRERROR )
    endif( HAVE_STRERROR )

    try_compile( HAVE_SNPRINTF ${CMAKE_BINARY_DIR} "${pcap_SOURCE_DIR}/config/have_snprintf.c"  )
    message( STATUS "HAVE_SNPRINTF = ${HAVE_SNPRINTF}" )
    if( HAVE_SNPRINTF )
        set( CONFIG_H_CONTENT "${CONFIG_H_CONTENT}#define HAVE_SNPRINTF\n" )
        add_definitions( -DHAVE_SNPRINTF )
    endif( HAVE_SNPRINTF )

    try_compile( HAVE_VSNPRINTF ${CMAKE_BINARY_DIR} "${pcap_SOURCE_DIR}/config/have_vsnprintf.c"  )
    message( STATUS "HAVE_VSNPRINTF = ${HAVE_VSNPRINTF}" )
    if( HAVE_VSNPRINTF )
        set( CONFIG_H_CONTENT "${CONFIG_H_CONTENT}#define HAVE_VSNPRINTF\n" )
        add_definitions( -DHAVE_VSNPRINTF )
    endif( HAVE_VSNPRINTF )

    try_compile( HAVE_LIMITS_H ${CMAKE_BINARY_DIR} "${pcap_SOURCE_DIR}/config/have_limits.c"  )
    message( STATUS "HAVE_LIMITS_H = ${HAVE_LIMITS_H}" )
    if( HAVE_LIMITS_H )
        set( CONFIG_H_CONTENT "${CONFIG_H_CONTENT}#define HAVE_LIMITS_H\n" )
        add_definitions( -DHAVE_LIMITS_H )
    endif( HAVE_LIMITS_H )

    try_compile( HAVE_SOCKADDR_SA_LEN ${CMAKE_BINARY_DIR} "${pcap_SOURCE_DIR}/config/have_sockaddr_sa_len.c"  )
    message( STATUS "HAVE_SOCKADDR_SA_LEN = ${HAVE_SOCKADDR_SA_LEN}" )
    if( HAVE_SOCKADDR_SA_LEN )
        set( CONFIG_H_CONTENT "${CONFIG_H_CONTENT}#define HAVE_SOCKADDR_SA_LEN\n" )
        add_definitions( -DHAVE_SOCKADDR_SA_LEN )
    endif( HAVE_SOCKADDR_SA_LEN )

    try_compile( HAVE_SOCKADDR_STORAGE ${CMAKE_BINARY_DIR} "${pcap_SOURCE_DIR}/config/have_sockaddr_storage.c"  )
    message( STATUS "HAVE_SOCKADDR_STORAGE = ${HAVE_SOCKADDR_STORAGE}" )
    if( HAVE_SOCKADDR_STORAGE )
        set( CONFIG_H_CONTENT "${CONFIG_H_CONTENT}#define HAVE_SOCKADDR_STORAGE\n" )
        add_definitions( -DHAVE_SOCKADDR_STORAGE )
    endif( HAVE_SOCKADDR_STORAGE )

    try_compile( HAVE_SYS_BITYPES_H ${CMAKE_BINARY_DIR} "${pcap_SOURCE_DIR}/config/have_bitypes.c"  )
    message( STATUS "HAVE_SYS_BITYPES_H = ${HAVE_SYS_BITYPES_H}" )
    if( HAVE_SYS_BITYPES_H )
        set( CONFIG_H_CONTENT "${CONFIG_H_CONTENT}#define HAVE_SYS_BITYPES_H\n" )
        add_definitions( -DHAVE_SYS_BITYPES_H )
    endif( HAVE_SYS_BITYPES_H )

    try_compile( HAVE_STRLCPY ${CMAKE_BINARY_DIR} "${pcap_SOURCE_DIR}/config/have_strlcpy.c"  )
    message( STATUS "HAVE_STRLCPY = ${HAVE_STRLCPY}" )
    if( HAVE_STRLCPY )
        set( CONFIG_H_CONTENT "${CONFIG_H_CONTENT}#define HAVE_STRLCPY\n" )
        add_definitions( -DHAVE_STRLCPY )
    endif( HAVE_STRLCPY )

    if( USE_IPV6 )
        MESSAGE( STATUS "Use IPv6" )
        set( CONFIG_H_CONTENT "${CONFIG_H_CONTENT}#define USE_IPV6\n" )
        add_definitions( -DUSE_IPV6 )
    endif( USE_IPV6 )

    if( WIN32 )
        set( CONFIG_H_CONTENT "${CONFIG_H_CONTENT}#define HAVE_ADDRINFO\n" )
        add_definitions( -DHAVE_ADDRINFO )
    endif( WIN32 )

endif( NOT LIBPCAP_PRECONFIGURED )