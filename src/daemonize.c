#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
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
  int fd;

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

  if ((fd = open("/dev/null", O_RDWR)) == -1)
    return fd;

  dup2(fd, STDIN_FILENO);
  dup2(fd, STDOUT_FILENO);
  dup2(fd, STDERR_FILENO);

  close(fd);
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

int set_maxfds(int fds)
{
  struct rlimit rlim;

  if (getrlimit(RLIMIT_NOFILE, &rlim) != 0) {
    return -1;
  }

  if (fds) {
    rlim.rlim_cur = fds;
    rlim.rlim_max = fds;

    if (setrlimit(RLIMIT_NOFILE, &rlim) != 0) {
      return -1;
    }
  }

  return rlim.rlim_cur;
}

int enable_cores(int cores)
{
  struct rlimit rlim;

  if (cores && getrlimit(RLIMIT_CORE, &rlim) == 0) {
    rlim.rlim_cur = rlim.rlim_max;
    setrlimit(RLIMIT_CORE, &rlim);
  }
  return 0;
}
