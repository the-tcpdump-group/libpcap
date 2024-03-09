#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>

  // Different OSes define ETHER_ADDR_LEN in different headers, if at all, so
  // it would take an amount of conditionals similar to that in nametoaddr.c
  // just to get the well-known constant from an OS (or not).  Keep it simple.
  #ifndef ETHER_ADDR_LEN
    #define ETHER_ADDR_LEN 6
  #endif // ETHER_ADDR_LEN

  // Linux defines and uses AF_PACKET.
  // AIX, FreeBSD, Haiku, macOS, NetBSD and OpenBSD define and use AF_LINK.
  // illumos defines both AF_PACKET and AF_LINK, and uses AF_LINK.
  // Solaris 11 defines both AF_PACKET and AF_LINK, but uses neither.
  // GNU/Hurd defines neither AF_PACKET nor AF_LINK.
  #include <net/if.h>
  #ifdef AF_PACKET
    #include <netpacket/packet.h> // struct sockaddr_ll
    #include <net/if_arp.h> // ARPHRD_ETHER
  #endif // AF_PACKET
  #ifdef AF_LINK
    #include <net/if_dl.h> // struct sockaddr_dl and LLADDR()
    #include <net/if_types.h> // IFT_ETHER
  #endif // AF_LINK
#endif

#include <pcap.h>

#include "varattrs.h"
#include "pcap/funcattrs.h"

static int ifprint(pcap_if_t *d);
static char *iptos(bpf_u_int32 in);

#ifdef _WIN32
#include "portability.h"

/*
 * Generate a string for a Win32-specific error (i.e. an error generated when
 * calling a Win32 API).
 * For errors occurred during standard C calls, we still use pcap_strerror()
 */
#define ERRBUF_SIZE	1024
static const char *
win32_strerror(DWORD error)
{
  static char errbuf[ERRBUF_SIZE+1];
  size_t errlen;

  FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, 0, errbuf,
                ERRBUF_SIZE, NULL);

  /*
   * "FormatMessage()" "helpfully" sticks CR/LF at the end of the
   * message.  Get rid of it.
   */
  errlen = strlen(errbuf);
  if (errlen >= 2) {
    errbuf[errlen - 1] = '\0';
    errbuf[errlen - 2] = '\0';
    errlen -= 2;
  }
  return errbuf;
}

static char *
getpass(const char *prompt)
{
  HANDLE console_handle = GetStdHandle(STD_INPUT_HANDLE);
  DWORD console_mode, save_console_mode;
  static char password[128+1];
  char *p;

  fprintf(stderr, "%s", prompt);

  /*
   * Turn off echoing.
   */
  if (!GetConsoleMode(console_handle, &console_mode)) {
    fprintf(stderr, "Can't get console mode: %s\n",
            win32_strerror(GetLastError()));
    exit(1);
  }
  save_console_mode = console_mode;
  console_mode &= ~ENABLE_ECHO_INPUT;
  if (!SetConsoleMode(console_handle, console_mode)) {
    fprintf(stderr, "Can't set console mode: %s\n",
            win32_strerror(GetLastError()));
    exit(1);
  }
  if (fgets(password, sizeof password, stdin) == NULL) {
    fprintf(stderr, "\n");
    SetConsoleMode(console_handle, save_console_mode);
    exit(1);
  }
  fprintf(stderr, "\n");
  SetConsoleMode(console_handle, save_console_mode);
  p = strchr(password, '\n');
  if (p != NULL)
    *p = '\0';
 return password;
}
#endif

int main(int argc, char **argv)
{
  pcap_if_t *alldevs;
  pcap_if_t *d;
  bpf_u_int32 net, mask;
  int exit_status = 0;
  char errbuf[PCAP_ERRBUF_SIZE+1];
  struct pcap_rmtauth auth;
  char username[128+1];
  char *p;
  char *password;

  if (argc >= 2)
  {
    if (pcap_findalldevs_ex(argv[1], NULL, &alldevs, errbuf) == -1)
    {
      /*
       * OK, try it with a user name and password.
       */
      fprintf(stderr, "User name: ");
      if (fgets(username, sizeof username, stdin) == NULL)
        exit(1);
      p = strchr(username, '\n');
      if (p != NULL)
        *p = '\0';
      password = getpass("Password: ");
      auth.type = RPCAP_RMTAUTH_PWD;
      auth.username = username;
      auth.password = password;
      if (pcap_findalldevs_ex(argv[1], &auth, &alldevs, errbuf) == -1)
      {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n",errbuf);
        exit(1);
      }
    }
  }
  else
  {
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
      fprintf(stderr,"Error in pcap_findalldevs: %s\n",errbuf);
      exit(1);
    }
  }
  for(d=alldevs;d;d=d->next)
  {
    if (!ifprint(d))
      exit_status = 2;
  }

  if (alldevs != NULL)
  {
    if (pcap_lookupnet(alldevs->name, &net, &mask, errbuf) < 0)
    {
      /*
       * XXX - this doesn't distinguish between "a real error
       * occurred" and "this interface doesn't *have* an IPv4
       * address".  The latter shouldn't be treated as an error.
       *
       * We look for the interface name, followed by a colon and
       * a space, and, if we find it,w e see if what follows it
       * is "no IPv4 address assigned".
       */
      size_t devnamelen = strlen(alldevs->name);
      if (strncmp(errbuf, alldevs->name, devnamelen) == 0 &&
          strncmp(errbuf + devnamelen, ": ", 2) == 0 &&
          strcmp(errbuf + devnamelen + 2, "no IPv4 address assigned") == 0)
        printf("Preferred device is not on an IPv4 network\n");
      else {
        fprintf(stderr,"Error in pcap_lookupnet: %s\n",errbuf);
        exit_status = 2;
      }
    }
    else
    {
      printf("Preferred device is on network: %s/%s\n",iptos(net), iptos(mask));
    }
  }

  pcap_freealldevs(alldevs);
  exit(exit_status);
}

#if ! defined(_WIN32) && (defined(AF_PACKET) || defined(AF_LINK))
static char *
ether_ntop(const u_char addr[], char *buffer, size_t size, u_char mask)
{
  if (mask)
    snprintf(buffer, size, "%02x:%02x:%02x:xx:xx:xx",
             addr[0], addr[1], addr[2]);
  else
    snprintf(buffer, size, "%02x:%02x:%02x:%02x:%02x:%02x",
             addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
  return buffer;
}
#endif // ! defined(_WIN32) && (defined(AF_PACKET) || defined(AF_LINK))

static int ifprint(pcap_if_t *d)
{
  const char *sep;
  int status = 1; /* success */

  printf("%s\n",d->name);
  if (d->description)
    printf("\tDescription: %s\n",d->description);
  printf("\tFlags: ");
  sep = "";
  if (d->flags & PCAP_IF_UP) {
    printf("%sUP", sep);
    sep = ", ";
  }
  if (d->flags & PCAP_IF_RUNNING) {
    printf("%sRUNNING", sep);
    sep = ", ";
  }
  if (d->flags & PCAP_IF_LOOPBACK) {
    printf("%sLOOPBACK", sep);
    sep = ", ";
  }
  if (d->flags & PCAP_IF_WIRELESS) {
    printf("%sWIRELESS", sep);
    switch (d->flags & PCAP_IF_CONNECTION_STATUS) {

    case PCAP_IF_CONNECTION_STATUS_UNKNOWN:
      printf(" (association status unknown)");
      break;

    case PCAP_IF_CONNECTION_STATUS_CONNECTED:
      printf(" (associated)");
      break;

    case PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
      printf(" (not associated)");
      break;

    case PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE:
      break;
    }
  } else {
    switch (d->flags & PCAP_IF_CONNECTION_STATUS) {

    case PCAP_IF_CONNECTION_STATUS_UNKNOWN:
      printf(" (connection status unknown)");
      break;

    case PCAP_IF_CONNECTION_STATUS_CONNECTED:
      printf(" (connected)");
      break;

    case PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
      printf(" (disconnected)");
      break;

    case PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE:
      break;
    }
  }
  printf("\n");

  const char *unmask = getenv("UNMASK_MAC_ADDRESSES");
  if (unmask && strcmp("yes", unmask))
    unmask = NULL;

  for (pcap_addr_t *a = d->addresses; a; a=a->next) {
    if (a->addr == NULL) {
      fprintf(stderr, "\tWarning: a->addr is NULL, skipping this address.\n");
      status = 0;
    } else {
#if ! defined(_WIN32) && (defined(AF_PACKET) || defined(AF_LINK))
      char ether_buf[] = "00:00:00:00:00:00";
#endif // ! defined(_WIN32) && (defined(AF_PACKET) || defined(AF_LINK))
      switch(a->addr->sa_family) {
      case AF_INET:
        printf("\tAddress Family: AF_INET (%d)\n", a->addr->sa_family);
        char ipv4_buf[INET_ADDRSTRLEN];
        printf("\t\tAddress: %s\n",
          inet_ntop(AF_INET,
             &((struct sockaddr_in *)(a->addr))->sin_addr,
             ipv4_buf, sizeof ipv4_buf));
        if (a->netmask)
          printf("\t\tNetmask: %s\n",
            inet_ntop(AF_INET,
               &((struct sockaddr_in *)(a->netmask))->sin_addr,
               ipv4_buf, sizeof ipv4_buf));
        if (a->broadaddr)
          printf("\t\tBroadcast Address: %s\n",
            inet_ntop(AF_INET,
               &((struct sockaddr_in *)(a->broadaddr))->sin_addr,
               ipv4_buf, sizeof ipv4_buf));
        if (a->dstaddr)
          printf("\t\tDestination Address: %s\n",
            inet_ntop(AF_INET,
               &((struct sockaddr_in *)(a->dstaddr))->sin_addr,
               ipv4_buf, sizeof ipv4_buf));
        break;

#if ! defined(_WIN32)
#ifdef AF_PACKET
      case AF_PACKET:
        printf("\tAddress Family: AF_PACKET (%d)\n", a->addr->sa_family);
        struct sockaddr_ll *sll = (struct sockaddr_ll *)a->addr;
        printf("\t\tInterface Index: %u\n", sll->sll_ifindex);
        printf("\t\tType: %d%s\n", sll->sll_hatype,
               sll->sll_hatype == ARPHRD_ETHER ? " (ARPHRD_ETHER)" : "");
        printf("\t\tLength: %u\n", sll->sll_halen);
        if (sll->sll_hatype == ARPHRD_ETHER && sll->sll_halen == ETHER_ADDR_LEN)
          printf("\t\tAddress: %s\n",
                 ether_ntop((const u_char *)sll->sll_addr,
                            ether_buf, sizeof(ether_buf), ! unmask));
      break;
#endif // AF_PACKET

#ifdef AF_LINK
      case AF_LINK:
        printf("\tAddress Family: AF_LINK (%d)\n", a->addr->sa_family);
        struct sockaddr_dl *sdl = (struct sockaddr_dl *)a->addr;
        printf("\t\tInterface Index: %u\n", sdl->sdl_index);
        printf("\t\tType: %u%s\n", sdl->sdl_type,
               sdl->sdl_type == IFT_ETHER ? " (IFT_ETHER)" : "");
        printf("\t\tLength: %u\n", sdl->sdl_alen);
        // On illumos sdl_type can be 0, see https://www.illumos.org/issues/16383
        if ((sdl->sdl_type == IFT_ETHER
#ifdef __illumos__
             || sdl->sdl_type == 0
#endif // __illumos__
            ) && sdl->sdl_alen == ETHER_ADDR_LEN)
          printf("\t\tAddress: %s\n",
                 ether_ntop((const u_char *)LLADDR(sdl),
                            ether_buf, sizeof(ether_buf), ! unmask));
      break;
#endif // AF_LINK
#endif // ! defined(_WIN32)

#ifdef AF_INET6
      case AF_INET6:
        printf("\tAddress Family: AF_INET6 (%d)\n", a->addr->sa_family);
        char ipv6_buf[INET6_ADDRSTRLEN];
        printf("\t\tAddress: %s\n",
          inet_ntop(AF_INET6,
             ((struct sockaddr_in6 *)(a->addr))->sin6_addr.s6_addr,
             ipv6_buf, sizeof ipv6_buf));
        if (a->netmask)
          printf("\t\tNetmask: %s\n",
            inet_ntop(AF_INET6,
              ((struct sockaddr_in6 *)(a->netmask))->sin6_addr.s6_addr,
               ipv6_buf, sizeof ipv6_buf));
        if (a->broadaddr)
          printf("\t\tBroadcast Address: %s\n",
            inet_ntop(AF_INET6,
              ((struct sockaddr_in6 *)(a->broadaddr))->sin6_addr.s6_addr,
               ipv6_buf, sizeof ipv6_buf));
        if (a->dstaddr)
          printf("\t\tDestination Address: %s\n",
            inet_ntop(AF_INET6,
              ((struct sockaddr_in6 *)(a->dstaddr))->sin6_addr.s6_addr,
               ipv6_buf, sizeof ipv6_buf));
        break;
#endif // AF_INET6
      default:
        printf("\tAddress Family: Unknown (%d)\n", a->addr->sa_family);
        break;
      } // switch
    } // if
  } // for
  printf("\n");
  return status;
}

/* From tcptraceroute */
#define IPTOSBUFFERS	12
static char *iptos(bpf_u_int32 in)
{
	static char output[IPTOSBUFFERS][sizeof("255.255.255.255")];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	snprintf(output[which], sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}
