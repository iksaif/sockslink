#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <sys/fcntl.h>

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "config.h"
#include "utils.h"

int sock_set_v6only(int s, int on)
{
#ifdef IPV6_V6ONLY
  return setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof (on));
#else
  return 0;
#endif
}

int sock_set_tcpnodelay(int s, int on)
{
  return setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &on, sizeof (on));
}

int sock_set_reuseaddr(int s, int on)
{
  return setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on));
}

int sock_set_nonblock(int s)
{
  int flags;

  flags = fcntl(s, F_GETFL);
  if (flags < 0)
    return flags;
  flags |= O_NONBLOCK;
  if (fcntl(s, F_SETFL, flags) < 0)
    return -1;

  return 0;
}


const char *addr_ntop(const struct sockaddr_storage *addr,
		      char *dst, socklen_t size)
{
  const char *ret;

  switch(addr->ss_family) {
  case AF_INET:
    ret = inet_ntop(AF_INET, &(((struct sockaddr_in *)addr)->sin_addr),
		    dst, size);
    break;
#ifdef HAVE_IPV6
  case AF_INET6:
    ret = inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)addr)->sin6_addr),
		    dst, size);
    break;
#endif
  default:
    ret = NULL;
  }

  return ret;
}

/**
 * strlcat - Append a length-limited, %NUL-terminated string to another
 * @dest: The string to be appended to
 * @src: The string to append to it
 * @count: The size of the destination buffer.
 */
size_t strlcat(char *dest, const char *src, size_t count)
{
  size_t dsize = strlen(dest);
  size_t len = strlen(src);
  size_t res = dsize + len;

  assert(dsize >= count);

  dest += dsize;
  count -= dsize;
  if (len >= count)
    len = count-1;
  memcpy(dest, src, len);
  dest[len] = 0;
  return res;
}

/**
 * strlcpy - Copy a %NUL terminated string into a sized buffer
 * @dest: Where to copy the string to
 * @src: Where to copy the string from
 * @size: size of destination buffer
 *
 * Compatible with *BSD: the result is always a valid
 * NUL-terminated string that fits in the buffer (unless,
 * of course, the buffer size is zero). It does not pad
 * out the result like strncpy() does.
 */
size_t strlcpy(char *dest, const char *src, size_t size)
{
  size_t ret = strlen(src);

  if (size) {
    size_t len = (ret >= size) ? size - 1 : ret;
    memcpy(dest, src, len);
    dest[len] = '\0';
  }
  return ret;
}
