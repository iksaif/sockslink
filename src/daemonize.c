#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

int daemonize(void)
{
  pid_t pid, sid;
  int ret;

  pid = fork();
  if (pid < 0)
    return pid;

  if (pid > 0)
    exit(EXIT_SUCCESS);

  umask(0);

  sid = setsid();
  if (sid < 0)
    return sid;

  if ((ret = chdir("/")) < 0)
    return ret;

  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
  return 0;
}

int drop_privileges(const char *username, const char *groupname)
{
  struct group *gp = NULL;
  struct passwd *pw = NULL;

  if (username) {
    pw = getpwnam(username);
    if (!pw)
      return -1;
  }

  if (groupname) {
    gp = getgrnam(groupname);
    if (!gp)
      return -1;
  }

  if (gp) {
    gid_t dummy;

    if (setgroups(0, &dummy) == -1)
      return -1;
    if (setgid(gp->gr_gid) == -1)
      return -1;
  }

  if (pw) {
    if (setuid(pw->pw_uid) == -1)
      return -1;
  }
  return 0;
}
