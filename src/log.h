#ifndef LOG_H
# define LOG_H

#include "sockslink.h"
#include "client.h"

void prcl_infos(Client *client, const char *fmt, ...);
void prcl_err(Client *client, const char *fmt, ...);
void prcl_warn(Client *client, const char *fmt, ...);
void prcl_debug(Client *client, const char *fmt, ...);


void pr_infos(SocksLink *sl, const char *fmt, ...);
void pr_err(SocksLink *sl, const char *fmt, ...);
void pr_warn(SocksLink *sl, const char *fmt, ...);
void pr_debug(SocksLink *sl, const char *fmt, ...);

#if !defined(DEBUG)

# define prcl_trace(...)
# define pr_trace(...)

#else
void prcl_trace(Client *client, const char *fmt, ...);
void pr_trace(SocksLink *sl, const char *fmt, ...);
#endif

#endif /* !LOG_H */
