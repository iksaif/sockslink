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

static void on_server_write(struct bufferevent *bev, void *ctx)
{
  Client *cl = ctx;

  if (cl->close)
    client_drop(cl);
}

static void on_server_auth_username(struct bufferevent *bev, void *ctx)
{
  Client *cl = ctx;
  uint8_t *buffer = EVBUFFER_DATA(EVBUFFER_INPUT(bev));
  size_t bytes = EVBUFFER_LENGTH(EVBUFFER_INPUT(bev));
  uint8_t ver, result;

  prcl_trace(cl, "received %d bytes from remote server", bytes);

  if (bytes < 2)
    return ;

  ver = buffer[0];
  result = buffer[1];

  prcl_trace(cl, "username authentication result: %#x %#x", ver, result);

  if (ver != 0x01 || result != 0x00) {
    client_drop(cl);
    return ;
  }

  evbuffer_drain(EVBUFFER_INPUT(bev), 2);

  client_auth_username_successful(cl);

  server_start_stream(cl);
  client_start_stream(cl);
}

static void server_auth_username(Client *cl)
{
  struct bufferevent *bev = cl->server.bufev;
  uint8_t ver = 0x01;
  uint8_t ulen = strlen(cl->auth.username.uname);
  uint8_t plen = strlen(cl->auth.username.passwd);

  prcl_trace(cl, "sending username authentication data");

  bufferevent_setcb(bev, on_server_auth_username, on_server_write,
		    on_server_event, cl);

  bufferevent_write(bev, &ver, 1);
  bufferevent_write(bev, &ulen, 1);
  bufferevent_write(bev, cl->auth.username.uname, ulen);
  bufferevent_write(bev, &plen, 1);
  bufferevent_write(bev, cl->auth.username.passwd, plen);

  /* there is still data available in the buffer, call next callback */
  if (EVBUFFER_LENGTH(EVBUFFER_INPUT(bev)))
    on_server_auth_username(bev, cl);
}

static void on_server_negociate(struct bufferevent *bev, void *ctx)
{
  Client *cl = ctx;
  uint8_t *buffer = EVBUFFER_DATA(EVBUFFER_INPUT(bev));
  size_t bytes = EVBUFFER_LENGTH(EVBUFFER_INPUT(bev));
  uint8_t ver, method;

  prcl_trace(cl, "received %d bytes from remote server", bytes);

  if (bytes < 2)
    return ;

  ver = buffer[0];
  method = buffer[1];

  if (ver != SOCKS5_VER || method != cl->method) {
    client_drop(cl);
    return ;
  }

  evbuffer_drain(EVBUFFER_INPUT(bev), 2);

  if (method == AUTH_METHOD_USERNAME) {
    server_auth_username(cl);
  } else {
    server_start_stream(cl);
    client_start_stream(cl);
  }
}

static void server_negociate(Client *cl)
{
  struct bufferevent *bev = cl->server.bufev;
  uint8_t message[] = {SOCKS5_VER, 1, cl->method};

  prcl_debug(cl, "sending negociation request to remote server (method: %#x)",
	     cl->method);

  bufferevent_disable(bev, EV_READ | EV_WRITE);
  bufferevent_settimeout(bev, SOCKS5_AUTH_TIMEOUT, SOCKS5_AUTH_TIMEOUT);
  bufferevent_setcb(bev, on_server_negociate, on_server_write, on_server_event, cl);
  bufferevent_enable(bev, EV_READ | EV_WRITE);

  bufferevent_write(bev, message, sizeof (message));

  /* there is still data available in the buffer, call next callback */
  if (EVBUFFER_LENGTH(EVBUFFER_INPUT(bev)))
    on_server_negociate(bev, cl);
}

static void on_server_connect(struct bufferevent *bev, void *ctx)
{
  Client *cl = ctx;
  SocksLink *sl = cl->parent;
  int ret;
  int status = 0;
  socklen_t len = 0;

  /* Check for connect() error */
  ret = getsockopt(cl->server.fd, SOL_SOCKET, SO_ERROR, &status, &len);
  if (ret) {
    prcl_debug(cl, "connection error: %s", strerror(status));
    client_drop(cl);
    return ;
  }

  prcl_debug(cl, "remote server connected");

  if (sl->pipe) {
    /* If server is in pipe mode, relay data now */
    server_start_stream(cl);
    client_start_stream(cl);
  } else {
    /* Else, try to authenticate with the remote server */
    server_negociate(cl);
  }
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

void server_start_stream(Client *cl)
{
  struct bufferevent *bev = cl->server.bufev;

  bufferevent_disable(bev, EV_READ | EV_WRITE);
  bufferevent_settimeout(bev, SOCKS_IO_TIMEOUT, SOCKS_IO_TIMEOUT);
  bufferevent_setwatermark(bev, EV_READ, 0, SOCKS_STREAM_BUFSIZ);
  bufferevent_setcb(bev, on_server_read_stream, on_server_write, on_server_event, cl);
  bufferevent_enable(bev, EV_READ | EV_WRITE);

  /* there is still data available in the buffer, call next callback */
  if (EVBUFFER_LENGTH(EVBUFFER_INPUT(bev)))
    on_server_read_stream(bev, cl);
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

  bufferevent_base_set(sl->base, bev);
  bufferevent_setcb(bev, NULL, on_server_connect, on_server_event, cl);
  bufferevent_settimeout(bev, 0, SOCKS5_AUTH_TIMEOUT);
  bufferevent_enable(bev, EV_WRITE);

  return ;
 error:
  client_drop(cl);
  return ;
}
