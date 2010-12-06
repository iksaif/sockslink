#ifndef HELPER_H
# define HELPER_H

#include <sys/types.h>

#include "sockslink.h"

void helpers_start_pool(SocksLink *sl);
void helpers_stop_pool(SocksLink *sl);
void helpers_refill_pool(SocksLink *sl);

bool helper_available(SocksLink *sl);
int helper_stop_pid(SocksLink *sl, pid_t pid, bool dying);
int helper_call(Client *client);

#endif /* !HELPER_H */
