#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "sockslink.h"
#include "client.h"
#include "server.h"
#include "list.h"
#include "log.h"
#include "config.h"

static void client_connect_server(Client *cl)
{
  SocksLink *sl = cl->parent;

  if (!sl->helper.cmd) {
    server_connect(cl, &sl->nexthop_addr, sl->nexthop_addrlen);
  } else {
    /* FIXME ask helper: timeout, helper died, ...*/
  }
}

static void client_invalid_version(Client *cl)
{
  static const uint8_t response[] = {SOCKS5_VER, AUTH_METHOD_INVALID};

  bufferevent_write(cl->client.bufev, response, 2);
  client_disconnect(cl);
}

static void on_client_event(struct bufferevent *bev, short why, void *ctx)
{
  Client *cl = ctx;
  SocksLink *sl = cl->parent;

  if (why & EVBUFFER_EOF) {
    /* Client disconnected, remove the read event and the
     * free the client structure. */
    pr_debug(sl, "client disconnected");
  } else if (why & EVBUFFER_TIMEOUT) {
    pr_debug(sl, "client timeout");
  } else if (cl->client.fd != -1) {
    pr_debug(sl, "client socket error, disconnecting");
  }

  client_drop(cl);
}

static void on_client_write(struct bufferevent *bev, void *ctx)
{
  Client *cl = ctx;

  prcl_trace(cl, "client write buffer sent");

  if (cl->close)
    client_drop(cl);
}

static void on_client_read_auth_username(struct bufferevent *bev, void *ctx)
{
  Client *cl = ctx;
  uint8_t ver, ulen, plen;
  uint8_t *buffer = EVBUFFER_DATA(EVBUFFER_INPUT(bev));
  size_t bytes = EVBUFFER_LENGTH(EVBUFFER_INPUT(bev));

  prcl_trace(cl, "received %d bytes from client", bytes);

  if (bytes < 2)
    return ;

  ver = buffer[0];
  ulen = buffer[1];

  if (ver != 0x01) {
    client_invalid_version(cl);
    return ;
  }

  if (bytes < 2 + ulen + 1)
    return ;

  plen = buffer[2 + ulen];

  prcl_trace(cl, "ulen: %d, plen: %d", ulen, plen);

  if (bytes < 2 + ulen + 1 + plen)
    return ;

  memcpy(cl->auth.username.uname, buffer + 2, ulen);
  memcpy(cl->auth.username.passwd, buffer + 2 + ulen + 1, plen);

  prcl_trace(cl, "user: %s, passwd: %s", cl->auth.username.uname,
	     cl->auth.username.passwd);

  evbuffer_drain(bev->input, 2 + ulen + 1 + plen);

  client_connect_server(cl);
}

static void on_client_read_stream(struct bufferevent *bev, void *ctx)
{
  Client *cl = ctx;
  char buf[SOCKS_STREAM_BUFSIZ];
  size_t bytes = EVBUFFER_LENGTH(EVBUFFER_INPUT(bev));

  prcl_trace(cl, "received %d bytes from client", bytes);

  bytes = bufferevent_read(bev, buf, sizeof (buf));
  bufferevent_write(cl->server.bufev, buf, bytes);
}

static void on_client_read_init(struct bufferevent *bev, void *ctx)
{
  Client *cl = ctx;
  SocksLink *sl = cl->parent;
  uint8_t ver, nmeth, method;
  uint8_t *buffer = EVBUFFER_DATA(EVBUFFER_INPUT(bev));
  size_t bytes = EVBUFFER_LENGTH(EVBUFFER_INPUT(bev));

  prcl_trace(cl, "received %d bytes from client", bytes);

  if (bytes < 2)
    return ;

  ver = buffer[0];
  nmeth = buffer[1];

  if (ver != SOCKS5_VER) {
    client_invalid_version(cl);
    return ;
  }

  if (bytes < 2 + nmeth)
    return ;

  method = AUTH_METHOD_INVALID;
  /* Choose prefered method */
  for (int i = 0; i < ARRAY_SIZE(sl->methods); ++i) {
    if (sl->methods[i] == AUTH_METHOD_INVALID)
      break ;
    for (int j = 0; j < nmeth; ++j) {
      if (sl->methods[i] == buffer[2 + j]) {
	method = sl->methods[i];
	break ;
      }
    }
    if (method != AUTH_METHOD_INVALID)
      break ;
  }

  if (method == AUTH_METHOD_INVALID) {
    prcl_debug(cl, "no matching authentication method found");
  } else {
    prcl_debug(cl, "using 0x%.2x authentication method", method);
  }

  if (method == AUTH_METHOD_INVALID)
    cl->close = true;
  else if (method == AUTH_METHOD_NONE)
    client_connect_server(cl);
  else if (method == AUTH_METHOD_USERNAME)
    bufferevent_setcb(cl->client.bufev, on_client_read_auth_username,
		      on_client_write, on_client_event, cl);

  bufferevent_write(cl->client.bufev, (uint8_t []){SOCKS5_VER, method}, 2);

  evbuffer_drain(bev->input, 2 + nmeth);
}

void client_start_stream(Client *cl)
{
  bufferevent_disable(cl->client.bufev, EV_READ | EV_WRITE);
  bufferevent_settimeout(cl->client.bufev, SOCKS_IO_TIMEOUT, SOCKS_IO_TIMEOUT);
  bufferevent_setwatermark(cl->server.bufev, EV_READ, 0, SOCKS_STREAM_BUFSIZ);
  bufferevent_setcb(cl->client.bufev, on_client_read_stream,
		    on_client_write, on_client_event, cl);
  bufferevent_enable(cl->client.bufev, EV_READ | EV_WRITE);
}

Client *client_new(SocksLink *sl, int fd, struct sockaddr_storage *addr,
		   socklen_t addrlen)
{
  Client *cl = calloc(sizeof (*cl), 1);
  struct bufferevent *bev;

  INIT_LIST_HEAD(&cl->next);
  INIT_LIST_HEAD(&cl->next_auth);

  if (!cl)
    return NULL;

  bev = bufferevent_new(fd, NULL, NULL, NULL, NULL);
  if (!bev) {
    free(cl);
    return NULL;
  }

  cl->parent = sl;
  cl->client.bufev = bev;
  cl->client.fd = fd;
  cl->client.addr = *addr;
  cl->client.addrlen = addrlen;
  cl->server.fd = -1;

  list_add(&cl->next, &sl->clients);

  bufferevent_base_set(sl->base, bev);
  if (sl->pipe) {
    client_connect_server(cl);
  } else {
    bufferevent_setcb(bev, on_client_read_init, on_client_write, on_client_event, cl);
    bufferevent_settimeout(bev, SOCKS5_AUTH_TIMEOUT, SOCKS5_AUTH_TIMEOUT);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
  }

  return cl;
}

/* Disconnect client as soon as buffer are empty */
void client_disconnect(Client *cl)
{
  size_t bytes = EVBUFFER_LENGTH(EVBUFFER_OUTPUT(cl->client.bufev));

  if (bytes)
    cl->close = true;
  else
    client_drop(cl);
}

void client_drop(Client *cl)
{
  if (!cl)
    return ;

  if (cl->client.bufev) {
    bufferevent_disable(cl->client.bufev,  EV_READ | EV_WRITE);
    bufferevent_free(cl->client.bufev);
  }

  if (cl->server.bufev) {
    bufferevent_disable(cl->server.bufev,  EV_READ | EV_WRITE);
    bufferevent_free(cl->server.bufev);
  }

  if (cl->client.fd >= 0)
    close(cl->client.fd);
  if (cl->server.fd >= 0)
    close(cl->server.fd);

  cl->client.fd = -1;
  cl->server.fd = -1;

  list_del_init(&cl->next_auth);
  list_del_init(&cl->next);

  free(cl);
}
