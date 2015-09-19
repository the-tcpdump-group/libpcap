#ifdef _WIN32
#   include <Winsock2.h>
#else
#   include <sys/types.h>
#   include <sys/socket.h>
#endif

int main ()
{
  u_int i = sizeof(((struct sockaddr *)0)->sa_len);
  return 0;
}
