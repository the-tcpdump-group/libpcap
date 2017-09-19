#undef PCAP_TRACE

#if !defined(_WIN32)
  #define PCAP_TRACE(level, fmt, ...)  (void)0

#else  /* Rest of file */

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wincon.h>

/* \todo: Use 'g_cfg.color.file' and 'g_cfg.color.text'
 *        set from %HOME%/wpcap.cfg.
 */

#ifndef TRACE_COLOR_START
#define TRACE_COLOR_START  (FOREGROUND_INTENSITY | 2)  /* bright green */
#endif

#ifndef TRACE_COLOR_ARGS
#define TRACE_COLOR_ARGS   (FOREGROUND_INTENSITY | 7)  /* bright white */
#endif

#ifndef __FILE
#define __FILE()  _pcap_trace_basename (__FILE__)
#endif

#if !defined(TRACE_PREFIX)
  #if defined(USE_WIN10PCAP)
    #define TRACE_PREFIX  "[Win10Pcap] "

  #elif defined(USE_NPCAP)
    #define TRACE_PREFIX  "[NPcap] "

  #else
    #define TRACE_PREFIX  ""
  #endif
#endif


/*
 * Use this macro as e.g.:
 *   PCAP_TRACE (1, "%s() -> %s\n", __FUNCTION__, file);
 *
 * The stuff in '_pcap_trace_level()' should initialise itself once and
 * return the value of 'g_dbg_level'.
 */
#if defined(USE_PCAP_TRACE)
  #define PCAP_TRACE(level, fmt, ...)  do {                                       \
                                         if (_pcap_trace_level() >= level) {      \
                                           EnterCriticalSection (&g_trace_crit);  \
                                           _pcap_trace_color (TRACE_COLOR_START); \
                                           printf ("%s%s(%u): ", TRACE_PREFIX,    \
                                                   __FILE(), __LINE__);           \
                                           _pcap_trace_color (TRACE_COLOR_ARGS);  \
                                           printf (fmt, ## __VA_ARGS__);          \
                                           _pcap_trace_color (0);                 \
                                           LeaveCriticalSection (&g_trace_crit);  \
                                         }                                        \
                                       } while (0)

  static const char *last_fmt _U_;

  /* The generated grammar.c has this:
   *   ifndef YYFPRINTF
   *    include <stdio.h> // INFRINGES ON USER NAME SPACE
   *    define YYFPRINTF fprintf
   *   endif
   *
   * Thus, if 'YYDEBUG' is defined and 'yydebug > 0', the above
   * macro is used to trace the inner workings of grammar.c.
   * All in shining colours.
   */
  #undef  YYFPRINTF
  #define YYFPRINTF(s, fmt, ...)                               \
          do {                                                 \
            if (_pcap_trace_level() >= 1) {                    \
              int add_prefix = !last_fmt ||                    \
                   (last_fmt[strlen(last_fmt)-1] == '\n');     \
                                                               \
              last_fmt = fmt;                                  \
              if (add_prefix) {                                \
                _pcap_trace_color (8 | 2);  /* bright green */ \
                printf ("%s%s(%u): ", TRACE_PREFIX,            \
                  _pcap_trace_basename(__FILE()), __LINE__);   \
                _pcap_trace_color (8 | 7);  /* bright white */ \
                printf (fmt, ## __VA_ARGS__);                  \
              }                                                \
              else                                             \
                printf (fmt, ## __VA_ARGS__);                  \
              fflush (stdout);                                 \
              _pcap_trace_color (0);                           \
            }                                                  \
          } while (0)

#else
  #define PCAP_TRACE(level, fmt, ...)   (void)0
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern CRITICAL_SECTION g_trace_crit;

extern int         _pcap_trace_level (void);
extern void        _pcap_trace_color (unsigned short col);
extern const char *_pcap_trace_basename (const char *fname);

#ifdef __cplusplus
}
#endif
#endif  /* _WIN32 */

