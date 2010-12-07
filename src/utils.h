#ifndef UTILS_H
# define UTILS_H

#include <arpa/inet.h>
#include "config.h"

int sock_set_v6only(int s, int on);
int sock_set_tcpnodelay(int s, int on);
int sock_set_nonblock(int s);
int sock_set_reuseaddr(int s, int on);

size_t strlcpy(char *dst, const char *src, size_t size);
size_t strlcat(char *dst, const char *src, size_t size);
char *strnchr(const char *s, size_t count, int c);

int urldecode(const char *src, size_t srclen, char *dst, size_t dstlen);
int urlencode(const char *src, size_t srclen, char *dst, size_t dstlen);

#ifdef HAVE_IPV6
# define ADDR_NTOP_BUFSIZ INET6_ADDRSTRLEN
#else
# define ADDR_NTOP_BUFSIZ INET_ADDRSTRLEN
#endif

const char *addr_ntop(const struct sockaddr_storage *addr,
		      char *dst, socklen_t size);

int parse_ip_port(const char *address, const char *fallback_service,
		  struct sockaddr_storage *addr,
		  socklen_t *addrlen);

#endif /* !UTILS_H */
