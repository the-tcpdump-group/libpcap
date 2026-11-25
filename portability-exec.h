/*
 * Copyright (c) 2025
 *	The Tcpdump Group and contributors.  All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef PORTABILITY_EXEC_H
#define PORTABILITY_EXEC_H

#include <config.h> // HAVE_xxx

#ifdef _WIN32
  #include "getopt.h"
#else
  #include <unistd.h>
#endif

#ifdef HAVE_SYSEXITS_H
  // most OSes
  #include <sysexits.h>
#else
  // Windows and QNX
  #define EX_OK           0
  #define EX_USAGE       64
  #define EX_DATAERR     65
  #define EX_NOINPUT     66
  #define EX_NOUSER      67
  #define EX_NOHOST      68
  #define EX_UNAVAILABLE 69
  #define EX_SOFTWARE    70
  #define EX_OSERR       71
  #define EX_OSFILE      72
  #define EX_CANTCREAT   73
  #define EX_IOERR       74
  #define EX_TEMPFAIL    75
  #define EX_PROTOCOL    76
  #define EX_NOPERM      77
  #define EX_CONFIG      78
#endif // HAVE_SYSEXITS_H

#ifdef _WIN32
  #define DEV_NULL "NUL"
#else
  #define DEV_NULL "/dev/null"
#endif

#endif // PORTABILITY_EXEC_H
