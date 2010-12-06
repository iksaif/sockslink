#ifndef CLIENT_H
# define CLIENT_H

#include <sys/socket.h>

#include "sockslink.h"

struct peer {
  int fd;
  struct sockaddr_storage addr;
  socklen_t addrlen;
  struct bufferevent *bufev;
};

typedef struct peer Peer;

struct client {
  struct sockslink *parent;
  Peer client;
  Peer server;
  bool close;
  struct list_head next_auth;
  struct list_head next;
  uint8_t method;
  union {
    struct {
      char uname[256];
      char passwd[256];
    } username;
  } auth;
};

typedef struct client Client;

Client *client_new(SocksLink *sl, int fd, struct sockaddr_storage *addr,
		   socklen_t addrlen);
void client_disconnect(Client *cl);
void client_drop(Client *cl);
void client_start_stream(Client *cl);
void client_auth_username_successful(Client *cl);
void client_auth_username_fail(Client *cl);

#endif /* !CLIENT_H */
