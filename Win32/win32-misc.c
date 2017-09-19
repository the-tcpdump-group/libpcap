/*
 * This stuff must be included from pcap-npf.c only.
 * And not compiled on it's own.
 */
#ifdef BDEBUG
int dflag;
#endif

#if defined(USE_WIN10PCAP)
  struct bpf_stat {
         UINT bs_recv;
         UINT bs_drop;
         UINT ps_ifdrop;
         UINT bs_capt;
       };

  struct bpf_hdr {
         struct timeval bh_tstamp;
         UINT           bh_caplen;
         UINT           bh_datalen;
         USHORT         bh_hdrlen;
       };
#endif

PCAP_API ADAPTER *pcap_get_adapter (pcap_t *p);

ADAPTER *pcap_get_adapter (pcap_t *p)
{
  struct pcap_win *pw;

  if (!p)
    return (NULL);
  pw = p->priv;

 /* \todo: if this is a plugin, make sure 'pw->adapter' is NULL
  *        since it makes sense only to NPF/NPcap/Win10Pcap adapters.
  *        But how to do that best?
  */
#if 1
  return (pw ? pw->adapter : NULL);
#else
  return ((pw && p->handle && p->handle != INVALID_HANDLE_VALUE) ? pw->adapter : NULL);
#endif
}

#if defined(_MSC_VER) && defined(_DEBUG)
static _CrtMemState last_state;

void crtdbug_init (void)
{
  _HFILE file  = _CRTDBG_FILE_STDERR;
  int    mode  = _CRTDBG_MODE_FILE;
  int    flags = _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CRTDBG_DELAY_FREE_MEM_DF;

  _CrtSetReportFile (_CRT_ASSERT, file);
  _CrtSetReportMode (_CRT_ASSERT, mode);
  _CrtSetReportFile (_CRT_ERROR, file);
  _CrtSetReportMode (_CRT_ERROR, mode);
  _CrtSetReportFile (_CRT_WARN, file);
  _CrtSetReportMode (_CRT_WARN, mode);
  _CrtSetDbgFlag (flags | _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG));
  _CrtMemCheckpoint (&last_state);
}

void crtdbug_exit (void)
{
  _CrtCheckMemory();
  if (_pcap_trace_level() >= 1)
       _CrtMemDumpStatistics (&last_state);
  else _CrtMemDumpAllObjectsSince (&last_state);
  _CrtDumpMemoryLeaks();
}

#else
void crtdbug_init (void)
{
}
void crtdbug_exit (void)
{
}
#endif

#ifdef HAVE_AIRPCAP_API  /* Rest of file */

#include <airpcap.h>

#if defined(USE_WIN10PCAP)
  #error Win10Pcap with AirPcap is not supported at the moment.
#endif

#if defined(USE_NPCAP) && 0
  #error NPcap with AirPcap is not supported at the moment.
#endif

/* Copied from Packet32-int.h:
 */
typedef PCHAR (*AirpcapGetLastErrorHandler) (PAirpcapHandle Handle);
typedef BOOL (*AirpcapSetLinkTypeHandler) (PAirpcapHandle Handle,
                                           AirpcapLinkType LinkLayer);
/* Set in Packet32.c
 */
/* PCAP_API_DEF */ AirpcapGetLastErrorHandler g_PAirpcapGetLastError;
/* PCAP_API_DEF */ AirpcapSetLinkTypeHandler  g_PAirpcapSetLinkType;

static int pcap_set_datalink_airpcap (pcap_t *p, int dlt)
{
  struct pcap_win *pw = p->priv;
  PAirpcapHandle  hnd = PacketGetAirPcapHandle (pw->adapter);
  AirpcapLinkType type;

  PCAP_TRACE (2, "hnd: %p, g_PAirpcapSetLinkType: %p\n", hnd, g_PAirpcapSetLinkType);

  if (!hnd || !g_PAirpcapSetLinkType)
     return (-1);

  switch (dlt) {
    case DLT_IEEE802_11:
         type = AIRPCAP_LT_802_11;
         PCAP_TRACE (2, "DLT_IEEE802_11\n");
         break;
    case DLT_IEEE802_11_RADIO:
         type = AIRPCAP_LT_802_11_PLUS_RADIO;
         PCAP_TRACE (2, "DLT_IEEE802_11_RADIO\n");
         break;
    case DLT_PPI:
         type = AIRPCAP_LT_802_11_PLUS_PPI;
         PCAP_TRACE (2, "DLT_PPI\n");
         break;
     default:
         PCAP_TRACE (2, "Unsupported dlt: %d\n", dlt);
         return (-1);
  }

  p->linktype = dlt;

  if ((*g_PAirpcapSetLinkType)(hnd, type))
     return (0);

  PCAP_TRACE (2, "Failed: %s\n", (*g_PAirpcapGetLastError)(hnd));
  return (-1);
}

static void init_airpcap_dlts (pcap_t *p)
{
  p->dlt_list = (u_int *) malloc(sizeof(u_int) * 4);
  if (!p->dlt_list)
     return;

  p->dlt_list[0] = DLT_DOCSIS;
  p->dlt_list[1] = DLT_IEEE802_11;
  p->dlt_list[2] = DLT_IEEE802_11_RADIO;
  p->dlt_list[3] = DLT_PPI;
  p->dlt_count = 4;

  PCAP_TRACE (2, "p->dlt_list: %p, p->dlt_count: %d\n", p->dlt_list, p->dlt_count);
}
#endif  /* HAVE_AIRPCAP_API */

