#include <sys/types.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#include "sockslink.h"
#include "client.h"
#include "helper.h"
#include "log.h"
#include "config.h"
#include "utils.h"
#include "daemonize.h"

static bool signals_initialized = 0;
static LIST_HEAD(servers);

static void sig_sigaction(int sig, siginfo_t *infos, void *ctx)
{
  SocksLink *sl = NULL;

  switch (sig) {
  case SIGINT:
    list_for_each_entry(sl, &servers, next, SocksLink) {
      if (sl->base)
	event_base_loopbreak(sl->base);
      sl->exiting = true;
    }
    break ;
  case SIGCHLD:
    {
      int status;

      if (infos->si_pid != waitpid(infos->si_pid, &status, WNOHANG))
	break ;

      list_for_each_entry(sl, &servers, next, SocksLink) {
	if (sl->exiting)
	  continue ;

	helper_stop_pid(sl, infos->si_pid, true);
	helpers_refill_pool(sl);
      }
    }
    break ;
  default: /* Ignore */
    break ;
  }
}

static int setup_sigactions(void)
{
  struct sigaction sa;
  int ret;

  if (likely(signals_initialized))
    return 0;

  signals_initialized = 1;

  memset(&sa, 0, sizeof (sa));
  sigemptyset(&sa.sa_mask);
  sigaddset(&sa.sa_mask, SIGPIPE);
  sigaddset(&sa.sa_mask, SIGCHLD);
  sigaddset(&sa.sa_mask, SIGINT);

  sa.sa_flags = SA_NOCLDSTOP|SA_SIGINFO;
  sa.sa_sigaction = sig_sigaction;
  ret = sigaction(SIGCHLD, &sa, NULL);
  if (ret)
    goto error;

  ret = sigaction(SIGPIPE, &sa, NULL);
  if (ret)
    goto error;

  ret = sigaction(SIGINT, &sa, NULL);
  if (ret)
    goto error;

  return 0;
 error:
  pr_err(NULL, "error while setting up signal handlers: %s", strerror(errno));
  return ret;
}

int sockslink_init(SocksLink *sl)
{
  int ret = 0;

  memset(sl, 0, sizeof (*sl));
  memset(sl->fd, -1, sizeof (sl->fd));
  memset(sl->methods, AUTH_METHOD_INVALID, sizeof (sl->methods));

  INIT_LIST_HEAD(&sl->clients);
  INIT_LIST_HEAD(&sl->next);
  INIT_LIST_HEAD(&sl->helpers);

  sl->base = event_base_new();
  if (!sl->base) {
    pr_err(sl, "can't initialize libevent");
    ret = -1;
    goto error;
  }

  if ((ret = setup_sigactions()) < 0) {
    pr_err(sl, "can't setup signals: %s", strerror(errno));
    goto error;
  }

  list_add(&sl->next, &servers);
  return 0;
error:
  if (sl->base)
    event_base_free(sl->base);
  return ret;
}

void sockslink_clear(SocksLink *sl)
{
  pr_debug(NULL, "clearing sockslink");
  event_base_free(sl->base);
  list_del_init(&sl->next);
}

static void on_accept(int afd, short ev, void *arg)
{
  SocksLink *sl = arg;
  Client *client;
  int fd;
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);

  fd = accept(afd, (struct sockaddr *)&addr, &addrlen);
  if (fd == -1) {
    pr_warn(sl, "accept failed: %s", strerror(errno));
    return;
  }

  if (sock_set_nonblock(fd) < 0)
    pr_warn(sl, "failed to set client socket non-blocking: %s", strerror(errno));

  //if (sock_set_tcpnodelay(fd, 1) < 0)
  //  pr_warn(sl, "failed to set client socket tcp nodelay: %s", strerror(errno));

  client = client_new(sl, fd, &addr, addrlen);
  if (!client) {
    close(fd);
    return ;
  }

  prcl_debug(client, "client connected");
}

int sockslink_start(SocksLink *sl)
{
  int ret;
  int n = 0;

  pr_debug(sl, "starting sockslink");

  for (int i = 0; sl->addresses[i]; ++i) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Stream socket */
    hints.ai_flags = AI_PASSIVE;     /* For wildcard IP address */
    hints.ai_protocol = IPPROTO_TCP;

    pr_debug(sl, "trying to listen on iface: %s port: %s",
	     sl->addresses[i], sl->port);
    ret = getaddrinfo(sl->addresses[i], sl->port, &hints, &result);

    if (ret != 0) {
      pr_err(sl, "getaddrinfo(\"%s\", \"%s\"): %s", sl->addresses[i],
	     sl->port, gai_strerror(ret));
      continue ;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
      int fd = -1;

      switch (rp->ai_family) {
      case AF_INET:
	{
	  char buf[INET_ADDRSTRLEN];
	  struct sockaddr_in *sin;

	  sin = ((struct sockaddr_in *)rp->ai_addr);
	  inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof (buf));
	  pr_infos(sl, "listenning on %s:%d", buf, ntohs(sin->sin_port));
	}
	break ;
#ifdef HAVE_IPV6
      case AF_INET6:
	{
	  char buf[INET6_ADDRSTRLEN];
	  struct sockaddr_in6 *sin6;

	  sin6 = ((struct sockaddr_in6 *)rp->ai_addr);
	  inet_ntop(rp->ai_family, &sin6->sin6_addr, buf, sizeof (buf));
	  pr_infos(sl, "listenning on [%s]:%d", buf, ntohs(sin6->sin6_port));
	}
	break ;
#endif
      default:
	continue ;
      }

      if (n >= SOCKSLINK_LISTEN_FD_MAX -1) {
	pr_err(sl, "skipping address, can't listen on more than %d fds",
	       SOCKSLINK_LISTEN_FD_MAX);
	break ;
      }

      ret = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

      if (ret < 0) {
	pr_err(sl, "can't create socket: %s", strerror(errno));
	goto error_continue;
      }

      fd = ret;

      ret = sock_set_reuseaddr(fd, 1);

      if (ret < 0)
	pr_err(sl, "setsockopt failed, can't reuse address: %s", strerror(errno));

      sock_set_v6only(fd, 1);

      if (ret < 0)
	pr_err(sl, "setsockopt failed, can't set v6only flag: %s", strerror(errno));

      ret = sock_set_nonblock(fd);

      if (ret < 0) {
	pr_err(sl, "failed to set server socket to non-blocking");
	goto error_continue;
      }

      ret = bind(fd, rp->ai_addr, rp->ai_addrlen);

      if (ret < 0) {
	pr_err(sl, "bind failed: %s", strerror(errno));
	goto error_continue;
      }

#if defined(SO_BINDTODEVICE)
      if (sl->iface)
	ret = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, sl->iface, IF_NAMESIZE);
      if (ret < 0) {
	pr_err(sl, "can't bind to device %s: %s", sl->iface, strerror(errno));
	goto error_continue;
      }
#endif

      ret = listen(fd, 5);

      if (ret < 0) {
	pr_err(sl, "listen failed: %s", strerror(errno));
	goto error_continue;
      }

      sl->fd[n++] = fd;
      continue ;
    error_continue:
      if (fd >= 0)
	close(fd);
    }
    freeaddrinfo(result);
  }

  if (n == 0) {
    pr_err(sl, "can't listen on any specified interface, exiting");
    return -1;
  }

  if (!sl->fg) {
    ret = daemonize();
    if (ret) {
      pr_err(sl, "failed to detach: %s", strerror(errno));
      return -1;
    }
  }

  ret = drop_privileges(sl->username, sl->groupname);
  if (ret) {
    pr_err(sl, "failed to drop privileges (%s:%s): %s",
	   sl->username ? sl->username : "<none>",
	   sl->groupname ? sl->groupname : "<none>",
	   strerror(errno));
    return -1;
  }

  for (int i = 0; i < n; ++i) {
    if (sl->fd[i] == -1)
      continue ;
    n++;
    event_set(&sl->ev_accept[i], sl->fd[i], EV_READ|EV_PERSIST, on_accept, sl);
    event_base_set(sl->base, &sl->ev_accept[i]);
    event_add(&sl->ev_accept[i], NULL);
  }

  helpers_start_pool(sl);

  return 0;
}

int sockslink_stop(SocksLink *sl)
{
  int ret = 0;
  Client *client, *ctmp;

  pr_infos(sl, "stopping sockslink");

  list_for_each_entry_safe(client, ctmp, &sl->clients, next, Client)
    client_drop(client);

  for (int i = 0; i < SOCKSLINK_LISTEN_FD_MAX; ++i) {
    if (sl->fd[i] == -1)
      continue ;
    event_del(&sl->ev_accept[i]);
    close(sl->fd[i]);
    sl->fd[i] = -1;
  }

  helpers_stop_pool(sl);
  return ret;
}


int sockslink_loop(SocksLink *sl)
{
  int ret;

  pr_debug(sl, "entering loop");
  ret = event_base_dispatch(sl->base);
  pr_debug(sl, "loop exited");
  return ret;
}
