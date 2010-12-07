#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>

#include "log.h"
#include "utils.h"

static void pr_stderr(const char *prefix, const char *fmt, va_list ap)
{
  if (prefix)
    fprintf(stderr, "%s: %s", program_invocation_short_name, prefix);
  else
    fprintf(stderr, "%s: ", program_invocation_short_name);

  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
}

static void pr_syslog(int level, const char *prefix, const char *fmt, va_list ap)
{
  char buf[BUFSIZ];
  int facility = LOG_USER | level;
  int ret;
  size_t bytes;

  if (prefix) {
    strlcpy(buf, prefix, sizeof (buf));
    bytes = strlen(buf);
  } else
    bytes = 0;

  ret = vsnprintf(buf + bytes, sizeof (buf) - bytes, fmt, ap);
  if (ret < 0)
    return ;

  syslog(facility, "%s", buf);
}

static void prcl_common(Client *client, int level, const char *fmt, va_list ap)
{
  char buf[256] = {0, };
  size_t bytes = sizeof (buf);
  char *prefix = NULL;

  switch (client->client.addr.ss_family) {
  case AF_INET:
    {
      char addr[INET_ADDRSTRLEN];
      struct sockaddr_in *sin;

      sin = ((struct sockaddr_in *)&client->client.addr);
      if (inet_ntop(AF_INET, &sin->sin_addr, addr, sizeof (addr)))
	snprintf(buf, bytes, "%s:%d: ", addr, ntohs(sin->sin_port));
    }
    break ;
#ifdef HAVE_IPV6
  case AF_INET6:
    {
      char addr[INET6_ADDRSTRLEN];
      struct sockaddr_in6 *sin6;

      sin6 = ((struct sockaddr_in6 *)&client->client.addr);
      if (inet_ntop(AF_INET6, &sin6->sin6_addr, addr, sizeof (addr)))
	snprintf(buf, bytes, "[%s]:%d: ", addr, ntohs(sin6->sin6_port));
    }
    break ;
#endif
  default:
    break ;
  }

  if (buf[0])
    prefix = buf;
  else
    prefix = NULL;

  if (client && client->parent->syslog)
    pr_syslog(level, prefix, fmt, ap);
  else
    pr_stderr(prefix, fmt, ap);
}

static void pr_common(SocksLink *sl, int level, const char *fmt, va_list ap)
{
  if (sl && sl->syslog)
    pr_syslog(level, NULL, fmt, ap);
  else
    pr_stderr(NULL, fmt, ap);
}

#define PR_FUNC(__name, __level, __syslog_level)	\
  void __name(SocksLink *sl, const char *fmt, ...)	\
  {							\
    va_list ap;						\
							\
    if (sl && sl->verbose < __level)			\
      return ;						\
    va_start(ap, fmt);					\
    pr_common(sl, __syslog_level, fmt, ap);		\
    va_end(ap);						\
  }

PR_FUNC(pr_err,   -1, LOG_ERR)
PR_FUNC(pr_infos, 0, LOG_INFO)
PR_FUNC(pr_warn,  1, LOG_WARNING)
PR_FUNC(pr_debug, 2, LOG_DEBUG)
#if defined(DEBUG)
PR_FUNC(pr_trace, 3, LOG_DEBUG)
#endif

#define PRCL_FUNC(__name, __level, __syslog_level)	\
  void __name(Client *cl, const char *fmt, ...)		\
  {							\
    va_list ap;						\
							\
    if (cl && cl->parent->verbose < __level)		\
      return ;						\
    va_start(ap, fmt);					\
    prcl_common(cl, __syslog_level, fmt, ap);		\
    va_end(ap);						\
  }

PRCL_FUNC(prcl_err,   -1, LOG_ERR)
PRCL_FUNC(prcl_infos, 0, LOG_INFO)
PRCL_FUNC(prcl_warn,  1, LOG_WARNING)
PRCL_FUNC(prcl_debug, 2, LOG_DEBUG)
#if defined(DEBUG)
PRCL_FUNC(prcl_trace, 3, LOG_DEBUG)
#endif
