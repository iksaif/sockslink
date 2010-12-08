#include "event-compat.h"

#ifndef HAVE_BUFFEREVENT_SETCB
void
bufferevent_setcb(struct bufferevent *bufev,
		  evbuffercb readcb, evbuffercb writecb, everrorcb errorcb, void *cbarg)
{
  bufev->readcb = readcb;
  bufev->writecb = writecb;
  bufev->errorcb = errorcb;

  bufev->cbarg = cbarg;
}
#endif

#ifndef HAVE_EVENT_BASE_NEW
struct event_base *event_base_new(void)
{
  return event_init();
}
#endif

#ifndef HAVE_EVENT_BASE_LOOPBREAK
void event_base_loopbreak(struct event_base *base)
{
  struct timeval tv = {0, 1};

  event_base_loopexit(base, &tv);
}
#endif
