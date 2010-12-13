#ifndef SOCKSLINK_H
# define SOCKSLINK_H

#include <sys/socket.h>
#include <arpa/inet.h>

#include <stdbool.h>
#include <event.h>
#include "event-compat.h"

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
  struct list_head clients;
  pid_t pid;
  bool running; /* helper is up and running */
  bool dying;   /* helper is dying */
  int stdin;
  int stdout;
  int stderr;
  struct bufferevent *bufev_in;
  struct bufferevent *bufev_out;
  struct bufferevent *bufev_err;
  struct list_head next;
};

typedef struct helper Helper;

#define SOCKSLINK_LISTEN_FD_MAX		256

struct sockslink {
  /* Config */
  int verbose;
  bool pipe;
  bool fg;
  bool syslog;
  const char *username;
  const char *groupname;
  bool exiting;
  bool cores;
  const char *conf;
  const char *pid;
  int pidfd;

  /* Network config */
  const char *iface;
  const char *port;
  const char *addresses[SOCKSLINK_LISTEN_FD_MAX];
  struct sockaddr_storage nexthop_addr;
  socklen_t nexthop_addrlen;
  const char *nexthop_port;

  /* Auth config */
  uint8_t methods[2];

  /* network and libevent */
  struct event_base *base;
  int fd[SOCKSLINK_LISTEN_FD_MAX];
  struct event ev_accept[SOCKSLINK_LISTEN_FD_MAX];

  /* Clients */
  struct list_head clients;
  int fds_max;

  /* Helpers */
  const char *helper_command;
  int helpers_max;
  int helpers_running;
  struct list_head helpers;
  struct event helper_refill_event;

  /* To chain SocksLinks */
  struct list_head next;
};

typedef struct sockslink SocksLink;

int sockslink_init(SocksLink *sl);
int sockslink_loop(SocksLink *sl);
int sockslink_start(SocksLink *sl);
int sockslink_stop(SocksLink *sl);
void sockslink_clear(SocksLink *sl);

#endif /* !SOCKSLINK_H */
