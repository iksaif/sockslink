#ifndef ARGS_H
# define ARGS_H

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include "sockslink.h"
#include "list.h"

int parse_args(int argc, char *argv[], SocksLink * sl);

#endif /* !ARGS_H */
