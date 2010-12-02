#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "config.h"
#include "sockslink.h"
#include "client.h"
#include "server.h"
#include "log.h"
#include "utils.h"

static void on_server_write(struct bufferevent *bev, void *ctx)
{
  Client *cl = ctx;

  if (cl->close)
    client_drop(cl);
}

static void on_server_connect(struct bufferevent *bev, void *ctx)
{
  Client *cl = ctx;
  int ret;
  int status = 0;
  socklen_t len = 0;

  ret = getsockopt(cl->server.fd, SOL_SOCKET, SO_ERROR, &status, &len);
  if (ret) {
    prcl_debug(cl, "connection error: %s", strerror(status));
    client_drop(cl);
    return ;
  }

  prcl_debug(cl, "remote server connected");
  server_start_stream(cl);
  client_start_stream(cl);
}

static void on_server_read_stream(struct bufferevent *bev, void *ctx)
{
  Client *cl = ctx;
  char buf[SOCKS_STREAM_BUFSIZ];
  size_t bytes = EVBUFFER_LENGTH(EVBUFFER_INPUT(bev));

  prcl_trace(cl, "received %d bytes from server", bytes);

  bytes = bufferevent_read(bev, buf, sizeof (buf));
  bufferevent_write(cl->client.bufev, buf, bytes);
}

static void on_server_event(struct bufferevent *bev, short why, void *ctx)
{
  Client *cl = ctx;

  if (why & EVBUFFER_EOF) {
    /* Client disconnected, remove the read event and the
     * free the client structure. */
    prcl_debug(cl, "remote server disconnected");
    client_disconnect(cl);
  } else if (why & EVBUFFER_TIMEOUT) {
    prcl_debug(cl, "remote server timeout, disconnecting");
    client_drop(cl);
  } else {
    prcl_debug(cl, "remote server socket error (%#x), disconnecting", why);
    client_disconnect(cl);
  }
}

void server_start_stream(Client *cl)
{
  bufferevent_disable(cl->server.bufev, EV_READ | EV_WRITE);
  bufferevent_settimeout(cl->server.bufev, SOCKS_IO_TIMEOUT, SOCKS_IO_TIMEOUT);
  bufferevent_setwatermark(cl->server.bufev, EV_READ, 0, SOCKS_STREAM_BUFSIZ);
  bufferevent_setcb(cl->server.bufev, on_server_read_stream,
		    on_server_write, on_server_event, cl);
  bufferevent_enable(cl->server.bufev, EV_READ | EV_WRITE);
}

void server_connect(Client *cl, const struct sockaddr_storage *addr,
		    socklen_t addrlen)
{
  SocksLink *sl = cl->parent;
  struct bufferevent *bev;
  int fd;
  int ret;

  memcpy(&cl->server.addr, addr, addrlen);
  cl->server.addrlen = addrlen;

  ret = socket(addr->ss_family, SOCK_STREAM, IPPROTO_TCP);

  if (ret == -1) {
    prcl_err(cl, "can't create remote server socket: %s", strerror(errno));
    goto error;
  }

  fd = ret;

  ret = sock_set_nonblock(fd);

  if (ret < 0) {
    prcl_err(cl, "failed to set remote server socket to non-blocking");
    goto error;
  }

  ret = connect(fd, (const struct sockaddr *)addr, addrlen);

  if (ret == -1 && errno != EINPROGRESS) {
    prcl_err(cl, "can't connect to remote server: %s", strerror(errno));
    goto error;
  }

  bev = bufferevent_new(fd, NULL, NULL, NULL, NULL);
  if (!bev) {
    prcl_err(cl, "can't create bufferevent");
    goto error;
  }

  cl->server.fd = fd;
  cl->server.bufev = bev;

  bufferevent_setcb(bev, NULL, on_server_connect, on_server_event, cl);
  bufferevent_settimeout(bev, 0, SOCKS5_AUTH_TIMEOUT);
  bufferevent_base_set(sl->base, bev);
  bufferevent_enable(bev, EV_READ|EV_WRITE);

  return ;
 error:
  client_drop(cl);
  return ;
}
