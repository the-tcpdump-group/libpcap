# Compiling libpcap on Solaris and related OSes

* Autoconf works everywhere.
* Neither Solaris lex nor Solaris yacc are suitable.
* Neither illumos lex nor illumos yacc are suitable.
* Solaris m4 and illumos m4 are suitable.

## OmniOS r151054/AMD64

* flex 2.6.4 and GNU Bison 3.8.2 work.
* CMake 4.0.1 works.
* GCC 14.2.0 and Clang 20.1.2 work.

## OmniOS r151052/AMD64

* flex 2.6.4 and GNU Bison 3.8.2 work.
* CMake 3.30.5 works.
* GCC 14.2.0 and Clang 19.1.2 work.

## OmniOS r151046/AMD64

* flex 2.6.4 and GNU Bison 3.8.2 work.
* CMake 3.26.4 works.
* GCC 12.2.0 and Clang 16.0.4 work.

## OpenIndiana 2024.04/AMD64

* flex 2.6.4 and GNU Bison 3.7.6 work.
* CMake 3.30.2 works.
* GCC 10.5.0, GCC 13.3.0 and Clang 18.1.8 work.

For reference, the tests were done using a system installed from
`OI-hipster-minimal-20240426.iso` plus the `build-essential` package.

## Solaris CBE 11.4.81.193.1/AMD64

* flex 2.6.4 and GNU Bison 3.8.2 work.
* CMake 3.24.0 works.
* Clang 19.1.7 and GCC 14.2.0 work.

## Solaris 11.4.72.176.1/SPARC
* flex 2.6.4 and GNU Bison 3.8.2 work.
* CMake 3.24.0 works.
* Sun C 5.15 works.
* GCC 13.2.0 and Clang 13.0.1 work, but require setting
  `PKG_CONFIG_PATH=/usr/lib/64/pkgconfig`

## Solaris 11.4.57.144.3/SPARC

* flex 2.6.4 and GNU Bison 3.8.2 work.
* CMake does not work.
* GCC 12.2.0 and Clang 13.0.1 work.

## Solaris CBE 11.4.42.111.0/AMD64

* flex 2.6.4 and GNU Bison 3.7.3 work.
* CMake 3.21.0 works.
* Clang 11.0, GCC 11.2 and Sun C 5.15 work.

## Solaris 11.3/SPARC

* flex 2.6.4 and GNU Bison 3.7.5 work.
* CMake 3.14.3 works.
* Sun C 5.13, Sun C 5.14 and Sun C 5.15 work; GCC 5.5.0 and GCC 7.3.0 work.

## Solaris 10/SPARC

* libpcap build fails with rpcapd enabled.
* flex 2.6.4 and GNU Bison 3.7.5 work.
* CMake 3.14.3 works.
* Sun C 5.13 works, GCC 5.5.0 works.

## Solaris 9

This version of this OS is not supported because the snprintf(3) implementation
in its libc is not suitable.
