#ifndef DAEMONIZE_H
# define DAEMONIZE_H

int daemonize(void);
int drop_privileges(const char *username, const char *groupname);

#endif /* !DAEMONIZE_H */

