#ifndef SOCKSLINK_EVENT_COMPAT_H
# define SOCKSLINK_EVENT_COMPAT_H

#include <sys/types.h>
#include <event.h>

#include "config.h"

#if defined(HAVE_BUFFEREVENT_SETWATERMARK) && !defined(HAVE_BUFFEREVENT_SETWATERMARK_PROTO)
void bufferevent_setwatermark(struct bufferevent *, short, size_t, size_t);
#endif

#ifndef HAVE_BUFFEREVENT_SETCB
void bufferevent_setcb(struct bufferevent *bufev,
		       evbuffercb readcb, evbuffercb writecb, everrorcb errorcb, void *cbarg);
#endif

#ifndef HAVE_EVENT_BASE_NEW
struct event_base *event_base_new(void);
#endif

#ifndef HAVE_EVENT_BASE_LOOPBREAK
void event_base_loopbreak(struct event_base *base);
#endif

#endif

