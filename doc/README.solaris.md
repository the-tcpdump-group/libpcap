# Compiling libpcap on Solaris

* Autoconf works everywhere.
* Neither Solaris lex nor Solaris yacc are suitable.

## Solaris 11/SPARC

* flex 2.6.4 and GNU Bison 3.7.1 work.
* CMake 3.14.3 works.
* Sun C 5.13, Sun C 5.14 and Sun C 5.15 work; GCC 5.5.0 and GCC 7.3.0 work.

## Solaris 10/SPARC

* libpcap build fails with rpcapd enabled.
* flex 2.6.4 and GNU Bison 3.7.1 work.
* CMake 3.14.3 works.
* Sun C 5.13 works, GCC 5.5.0 works.

## Solaris 9/SPARC

* flex 2.5.35 and GNU Bison 3.0.2 work.
* CMake 2.8.9 does not work.
* Neither Sun C 5.8 nor Sun C 5.9 work, GCC 4.6.4 works.
