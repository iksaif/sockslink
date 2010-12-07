#ifndef DAEMONIZE_H
# define DAEMONIZE_H

int daemonize(void);
int drop_privileges(const char *username, const char *groupname);
int enable_cores(int enable);
int set_maxfds(int fd);

#endif /* !DAEMONIZE_H */

