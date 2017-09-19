
#include "./Win32/config.h"
#include "pcap-trace.h"

#include <assert.h>
#include <pcap/pcap.h>
#include <pcap-int.h>

#if defined(USE_PCAP_TRACE)  /* Rest of file */

static CONSOLE_SCREEN_BUFFER_INFO console_info;
static HANDLE                     stdout_hnd;

CRITICAL_SECTION  g_trace_crit;
int               g_dbg_level;

int _pcap_trace_level (void)
{
  const char *env;

  if (g_trace_crit.OwningThread)   /* Already done this, get out */
     return (g_dbg_level);

  env = getenv ("PCAP_TRACE");
  g_dbg_level = env ? (*env-'0') : 0;
  stdout_hnd = GetStdHandle (STD_OUTPUT_HANDLE);
  GetConsoleScreenBufferInfo (stdout_hnd, &console_info);
  InitializeCriticalSection (&g_trace_crit);
  return (g_dbg_level);
}

void _pcap_trace_color (unsigned short col)
{
#if 0
  /*
   * Ensure '_pcap_trace_level()' was called
   */
  assert (g_trace_crit.OwningThread);
#endif

  fflush (stdout);
  if (col == 0)
       SetConsoleTextAttribute (stdout_hnd, console_info.wAttributes);
  else SetConsoleTextAttribute (stdout_hnd, (console_info.wAttributes & ~7) | col);
}

/*
 * Strip drive-letter, directory and suffix from a filename.
 */
#define IS_SLASH(c)  ((c) == '\\' || (c) == '/')

const char *_pcap_trace_basename (const char *fname)
{
  const char *base = fname;

  if (fname && *fname)
  {
    if (fname[0] && fname[1] == ':')
    {
      fname += 2;
      base = fname;
    }
    while (*fname)
    {
      if (IS_SLASH(*fname))
         base = fname + 1;
      fname++;
    }
  }
  return (base);
}
#endif /* USE_PCAP_TRACE */
