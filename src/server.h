#ifndef SERVER_H
# define SERVER_H

#include <sys/socket.h>

void server_connect(Client *cl, const struct sockaddr_storage *addr,
		    socklen_t addrlen);

void server_start_stream(Client *cl);

#endif
