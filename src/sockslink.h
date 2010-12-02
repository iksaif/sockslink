#ifndef SOCKSLINK_H
# define SOCKSLINK_H

#include <sys/socket.h>
#include <arpa/inet.h>

#include <stdbool.h>
#include <event.h>

#include "list.h"

#define SOCKS5_VER		0x05

#define AUTH_METHOD_NONE	0x00
#define AUTH_METHOD_GSSAPI	0x01
#define AUTH_METHOD_USERNAME	0x02
#define AUTH_METHOD_INVALID	0xFF

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif
#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

struct sockslink;

struct helper {
  struct sockslink *parent;
  int pid;
  int fd;
  int died;
  struct timeval tod;
  const char *cmd;
  struct bufferevent *bufev;
};

typedef struct helper Helper;

#define SOCKSLINK_LISTEN_FD_MAX		256

struct sockslink {
  struct event_base *base;
  struct list_head clients;
  struct list_head addrs;
  struct helper helper;
  int verbose;
  bool pipe;
  bool fg;
  bool syslog;
  uint8_t methods[2];
  int fd[SOCKSLINK_LISTEN_FD_MAX];
  struct event ev_accept[SOCKSLINK_LISTEN_FD_MAX];
  const char *addresses[SOCKSLINK_LISTEN_FD_MAX];
  const char *iface;
  const char *port;
  const char *username;
  const char *groupname;
  struct sockaddr_storage nexthop_addr;
  socklen_t nexthop_addrlen;
  const char *nexthop_port;
  struct list_head next;
};

typedef struct sockslink SocksLink;

int sockslink_init(SocksLink *sl);
int sockslink_loop(SocksLink *sl);
int sockslink_start(SocksLink *sl);
int sockslink_stop(SocksLink *sl);
void sockslink_clear(SocksLink *sl);

#endif /* !SOCKSLINK_H */
