#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>

#include "log.h"
#include "config.h"
#include "utils.h"
#include "sockslink.h"
#include "helper.h"
#include "server.h"

static int helper_kill(Helper *helper)
{
  int status;
  pid_t pid;
  int retry = 2;
  int ret;

  ret = kill(helper->pid, SIGTERM);

  if (ret == -1 && errno == ESRCH)
    return 0;

  while (retry--) {
    pid = waitpid(helper->pid, &status, WNOHANG);

    if (pid == helper->pid)
      return 0;

    /* try to let the helper finish its stuff */
    usleep(100);
  }

  /*
   * failed to stop the helper gracefully, kill it
   * wait with WNOHANG, if it doesn't work, sockslink
   * SIGCHLD handler will take care of freeing memory
   */
  ret = kill(helper->pid, SIGKILL);

  if (ret == -1 && errno == ESRCH)
    return 0;

  pid = waitpid(helper->pid, &status, WNOHANG);
  if (pid == helper->pid)
    return 0;
  return -1;
}

static int helper_stop(Helper *helper)
{
  Client *client, *ctmp;
  SocksLink *sl = helper->parent;

  pr_debug(sl, "helper[%d] stopping", helper->pid);

  if (helper->running) {
    helper->running = false;
    sl->helpers_running--;
  }

  list_del_init(&helper->next);

  /* Drop clients waiting for auth on this helper */
  list_for_each_entry_safe(client, ctmp, &helper->clients, next_auth, Client)
    client_disconnect(client);

  if (!helper->dying && helper->pid > 0) {
    if (helper_kill(helper)) {
      /* re-add helper to helper list so SIGCHLD handler can remove it later */
      list_add(&helper->next, &helper->parent->helpers);
      return -1;
    }
  }

  if (helper->bufev_in) {
    bufferevent_disable(helper->bufev_in,  EV_READ | EV_WRITE);
    bufferevent_free(helper->bufev_in);
  }

  if (helper->bufev_out) {
    bufferevent_disable(helper->bufev_out,  EV_READ | EV_WRITE);
    bufferevent_free(helper->bufev_out);
  }

  if (helper->bufev_err) {
    bufferevent_disable(helper->bufev_err,  EV_READ | EV_WRITE);
    bufferevent_free(helper->bufev_err);
  }

  close(helper->stdin);
  close(helper->stdout);
  close(helper->stderr);

  free(helper);
  return 0;
}

/**
 * Helper protocol:
 *
 * - username, password, error urlencoded
 * - method is none, gssapi, username
 * - helper uses stderr for debug messages
 * - if next-hop is 'default' use default route
 *
 * stdin> source-ip method [username [password]]
 * stdout< OK next-hop method [username [password]]
 * stdout< ERR [error]
 */

static void helper_parse_authentication(Helper *hl, Client *cl, int argc,
					char *argv[])
{
  cl->method = AUTH_METHOD_INVALID;

  if (!strcmp(argv[0], "none") && argc == 1) {
    cl->method = AUTH_METHOD_NONE;
  } else if (!strcmp(argv[0], "username") && argc == 3) {

    if (urldecode(argv[1], cl->auth.username.uname, 255) < 0)
      return ;

    if (urldecode(argv[2], cl->auth.username.passwd, 255) < 0)
      return ;

    cl->method = AUTH_METHOD_USERNAME;
  }
}

static int helper_parse_nexthop(Helper *hl, Client *cl, const char *address,
				const char *service,
				struct sockaddr_storage *nexthop_addr,
				socklen_t *nexthop_addrlen)
{
  struct addrinfo hints;
  struct addrinfo *result;
  int ret;

  memset(&hints, 0, sizeof (hints));
  ret = getaddrinfo(address, service, &hints, &result);

  if (ret != 0) {
    prcl_err(cl, "helper[%d]: can't resolve address: getaddrinfo(%s): %s",
	     address, gai_strerror(ret));
    return -1;
  }

  memcpy(nexthop_addr, result->ai_addr, result->ai_addrlen);
  *nexthop_addrlen = result->ai_addrlen;

  freeaddrinfo(result);
  return 0;
}

static void on_helper_read_ok(Helper *hl, Client *cl, char *buffer)
{
  SocksLink *sl = cl->parent;
  struct sockaddr_storage nexthop_addr;
  socklen_t nexthop_addrlen;
  int ret;
  int argc;
  char *argv[6];

  /* Default nexthop (if available) */
  if (sl->nexthop_addrlen) {
    memcpy(&nexthop_addr, &sl->nexthop_addr, sl->nexthop_addrlen);
    nexthop_addrlen = sl->nexthop_addrlen;
  }

  for (argc = 0; argc < ARRAY_SIZE(argv); ++argc) {
    argv[argc] = buffer;

    for (; *buffer && !isblank(*buffer); buffer++)
      ;
    for (; *buffer && isblank(*buffer); buffer++)
      *buffer = '\0';
  }

  if (argc >= 3) {
    ret = helper_parse_nexthop(hl, cl, argv[1], argv[2],
			       &nexthop_addr, &nexthop_addrlen);
    if (ret < 0) {
      nexthop_addrlen = 0;
      goto connect;
    }
  }

  if (argc >= 4) {
    helper_parse_authentication(hl, cl, argc - 3, argv + 3);
  }

 connect:
  if (!nexthop_addrlen) {
    prcl_err(cl, "helper[%d] did not send a valid next-hop, "
	     "and no default route set with --next-hop, dropping client",
	     hl->pid);
    client_drop(cl);
    return ;
  }
  if (cl->method == AUTH_METHOD_INVALID) {
    prcl_err(cl, "helper[%d] did no provide a valid authentication method",
	     hl->pid);
    client_drop(cl);
    return ;
  }

  server_connect(cl, &nexthop_addr, nexthop_addrlen);
}

static void on_helper_read_err(Helper *hl, Client *cl, const char *error)
{
  SocksLink *sl = cl->parent;

  pr_debug(sl, "helper[%d]: authentication error: %s", hl->pid, error);

  if (cl->method == AUTH_METHOD_USERNAME)
    client_auth_username_fail(cl);

  client_disconnect(cl);
}

static void on_helper_read_stdout(struct bufferevent *bev, void *ctx)
{
  Helper *helper = ctx;
  SocksLink *sl = helper->parent;
  char *buffer = EVBUFFER_DATA(EVBUFFER_INPUT(bev));
  size_t bytes = EVBUFFER_LENGTH(EVBUFFER_INPUT(bev));
  Client *client;
  char *endofline;

  pr_trace(sl, "helper[%d] ready to read data (%d bytes)", helper->pid, bytes);

  while (bytes > 0 && (endofline = strnchr(buffer, bytes, '\n')) != NULL) {
    size_t consumed = 0;

    if (list_empty(&helper->clients)) {
      pr_err(sl, "helper[%d] sent data, but no clients in auth queue,"
	     "ignoring data", helper->pid);
      evbuffer_drain(EVBUFFER_INPUT(bev), bytes);
      break ;
    }

    *endofline = '\0';

    client = list_first_entry(&helper->clients, Client, next_auth);
    list_del_init(&client->next_auth);

    if (strcmp(buffer, "OK"))
      on_helper_read_ok(helper, client, buffer);
    else if (strcmp(buffer, "ERR"))
      on_helper_read_err(helper, client, buffer + 3);
    else
      pr_err(sl, "helper[%d] send an invalid answer (not starting "
	     "with OK or ERR)", helper->pid);

    consumed = endofline - buffer + 1;
    evbuffer_drain(EVBUFFER_INPUT(bev), consumed);
    bytes -= consumed;
    buffer += consumed;
  }

  /* no more client waiting, remove timeout */
  if (list_empty(&helper->clients)) {
    struct bufferevent *bev;

    bev = helper->bufev_in;
    bufferevent_disable(bev, EV_WRITE);
    bufferevent_settimeout(bev, 0, 0);
    bufferevent_enable(bev, EV_WRITE);

    bev = helper->bufev_out;
    bufferevent_disable(bev, EV_READ);
    bufferevent_settimeout(bev, 0, 0);
    bufferevent_enable(bev, EV_READ);
  }
}

static void on_helper_read_stderr(struct bufferevent *bev, void *ctx)
{
  Helper *helper = ctx;
  SocksLink *sl = helper->parent;
  char buf[1024];
  size_t bytes;

  while ((bytes = bufferevent_read(bev, buf, sizeof (buf) - 1)) > 0) {
    buf[bytes] = '\0';

    pr_err(sl, "helper[%d]: %s", helper->pid, buf);
  }
}

static void on_helper_write_stdin(struct bufferevent *bev, void *ctx)
{
  Helper *helper = ctx;
  SocksLink *sl = helper->parent;

  if (!helper->running) {
    bufferevent_settimeout(bev, 0, 0);
    helper->running = true;
    helper->parent->helpers_running++;
    pr_debug(sl, "helper[%d] started", helper->pid);
  } else {
    pr_trace(sl, "helper[%d] finished to write data", helper->pid);
  }

}

static void on_helper_event(struct bufferevent *bev, short why, void *ctx)
{
  Helper *helper = ctx;
  SocksLink *sl = helper->parent;

  if (why & EVBUFFER_EOF) {
    /* Helper died... */
    pr_debug(sl, "helper[%d] died", helper->pid);
  } else if (why & EVBUFFER_TIMEOUT) {
    pr_debug(sl, "helper[%d] authentication timeout", helper->pid);
  } else {
    pr_debug(sl, "helper[%d] unknown error", helper->pid);
  }
  helper_stop(helper);
}

static int helper_start(SocksLink *sl)
{
  int in[2], out[2], err[2];
  pid_t pid;

  in[0] = in[1] = -1;
  out[0] = out[1] = -1;
  err[0] = err[1] = -1;

  if (pipe(out) == -1)
    goto error;

  if (pipe(err) == -1)
    goto error;

  if (pipe(in) == -1)
    goto error;

  pid = fork();
  if (pid == -1)
    goto error;

  if (pid) {
    Helper *helper = calloc(sizeof (*helper), 1);
    struct bufferevent *bev;

    close(in[0]);
    close(out[1]);
    close(err[1]);

    if (!helper)
      goto error_parent;

    INIT_LIST_HEAD(&helper->clients);

    helper->parent = sl;
    helper->pid = pid;
    helper->stdin = in[1];
    helper->stdout = out[0];
    helper->stderr = err[0];

    helper->bufev_in = bufferevent_new(helper->stdin, NULL, NULL, NULL, NULL);
    helper->bufev_out = bufferevent_new(helper->stdout, NULL, NULL, NULL, NULL);
    helper->bufev_err = bufferevent_new(helper->stderr, NULL, NULL, NULL, NULL);

    if (!helper->bufev_in || !helper->bufev_out || !helper->bufev_err)
      goto error_parent;

    bev = helper->bufev_in;
    bufferevent_setcb(bev, NULL, on_helper_write_stdin, on_helper_event, helper);
    bufferevent_base_set(sl->base, bev);
    bufferevent_enable(bev, EV_WRITE);
    bufferevent_settimeout(bev, 0, HELPER_STARTUP_TIMEOUT);

    bev = helper->bufev_out;
    bufferevent_setcb(bev, on_helper_read_stdout, NULL, on_helper_event, helper);
    bufferevent_base_set(sl->base, bev);
    bufferevent_enable(bev, EV_READ);

    bev = helper->bufev_err;
    bufferevent_setcb(bev, on_helper_read_stderr, NULL, on_helper_event, helper);
    bufferevent_base_set(sl->base, bev);
    bufferevent_enable(bev, EV_READ);

    list_add(&helper->next, &sl->helpers);

    pr_infos(sl, "helper[%d] started (%s)", helper->pid, sl->helper_command);

    return 0;
  error_parent:
    pr_err(sl, "error while finishing helper initialization");
    if (helper)
      helper_stop(helper);
    else {
      close(in[1]);
      close(out[0]);
      close(err[0]);
    }

    return -1;
  } else {
    char *argv[] = { (char *)sl->helper_command, 0 };
    Client *client;
    Helper *helper;

    dup2(in[0], STDIN_FILENO);
    dup2(out[1], STDOUT_FILENO);
    dup2(err[1], STDERR_FILENO);

    close(in[0]);
    close(in[1]);
    close(out[0]);
    close(out[1]);
    close(err[0]);
    close(err[1]);

    list_for_each_entry(client, &sl->clients, next, Client) {
      if (client->client.fd != -1)
	close(client->client.fd);
      if (client->server.fd != -1)
	close(client->server.fd);
    }

    list_for_each_entry(helper, &sl->helpers, next, Helper) {
      close(helper->stdin);
      close(helper->stdout);
      close(helper->stderr);
    }

    for (int i = 0; i < SOCKSLINK_LISTEN_FD_MAX; ++i) {
      if (sl->fd[i] != -1)
	close(sl->fd[i]);
    }

    execv(argv[0], argv);
    exit(1);
  }
  return 0;


 error:
  pr_err(sl, "error while initializating helper");

  if (in[0] != -1)
    close(in[0]);
  if (in[1] != -1)
    close(in[1]);

  if (out[0] != -1)
    close(out[0]);
  if (out[1] != -1)
    close(out[1]);

  if (err[0] != -1)
    close(err[0]);
  if (err[1] != -1)
    close(err[1]);

  return -1;
}

static void on_helpers_refill(int fd, short event, void *ctx)
{
  SocksLink *sl = ctx;
  int ret = 0;

  for (int i = sl->helpers_running; i < sl->helpers_max; ++i)
    ret |= helper_start(sl);

  if (ret)
    helpers_refill_pool(sl);
  else if (timeout_pending(&sl->helper_refill_event, NULL))
    timeout_del(&sl->helper_refill_event);
}

void helpers_start_pool(SocksLink *sl)
{
  pr_debug(sl, "starting %d helpers", sl->helpers_max);

  for (int i = sl->helpers_running; i < sl->helpers_max; ++i)
    helper_start(sl);

  helpers_refill_pool(sl); /* launch timer */
}

void helpers_stop_pool(SocksLink *sl)
{
  Helper *helper, *tmp;

  if (timeout_pending(&sl->helper_refill_event, NULL))
      timeout_del(&sl->helper_refill_event);

  list_for_each_entry_safe(helper, tmp, &sl->helpers, next, Helper)
    helper_stop(helper);
}

void helpers_refill_pool(SocksLink *sl)
{
  struct event *ev = &sl->helper_refill_event;
  static const struct timeval tv = HELPERS_REFILL_POOL_TIMEOUT;

  if (!timeout_initialized(ev)) {
    timeout_set(ev, on_helpers_refill, sl);
    event_base_set(sl->base, ev);
  }
  if (!timeout_pending(ev, NULL))
    timeout_add(ev, &tv);
}

bool helper_available(SocksLink *sl)
{
  return !!sl->helpers_running;
}

int helper_stop_pid(SocksLink *sl, pid_t pid, bool dying)
{
  Helper *helper, *tmp;

  list_for_each_entry_safe(helper, tmp, &sl->helpers, next, Helper) {
    if (helper->pid == pid) {
      helper->dying = dying;
      return helper_stop(helper);
    }
  }
  return -1;
}

static Helper *helper_round_robin(SocksLink *sl)
{
  Helper *helper;

  if (!sl->helpers_running)
    return NULL;

  helper = list_first_entry(&sl->helpers, Helper, next);

  if (list_is_singular(&sl->helpers))
    return helper;

  list_del_init(&helper->next);
  list_add_tail(&helper->next, &sl->helpers);
  return helper;
}

int helper_call(Client *client)
{
  Helper *helper = helper_round_robin(client->parent);
  struct bufferevent *bev;
  char buf[ADDR_NTOP_BUFSIZ];

  if (!helper || helper->dying) {
    helpers_refill_pool(client->parent);
    return -1;
  }

  bev = helper->bufev_in;

  if (addr_ntop(&client->client.addr, buf, sizeof (buf))) {
    bufferevent_write(bev, buf, strlen(buf));
    bufferevent_write(bev, " ", 1);
  }

  if (client->method == AUTH_METHOD_NONE)
    bufferevent_write(bev, "none", 4);
  if (client->method == AUTH_METHOD_USERNAME) {
    char buf[255 * 3 + 1]; /* worst case */
    size_t bytes;

    bufferevent_write(bev, "username ", 9);

    bytes = urlencode(client->auth.username.uname, buf, sizeof (buf));
    bufferevent_write(bev, buf, bytes);
    bufferevent_write(bev, " ", 1);

    bytes = urlencode(client->auth.username.passwd, buf, sizeof (buf));
    bufferevent_write(bev, buf, bytes);
  }
  bufferevent_write(bev, "\n", 1);

  /* setup auth timeout */
  bufferevent_settimeout(helper->bufev_in, 0, HELPER_AUTH_TIMEOUT);
  bufferevent_settimeout(helper->bufev_out, HELPER_AUTH_TIMEOUT, 0);
  list_add(&client->next_auth, &helper->clients);
  return 0;
}

