#include "helper.h"

/**
 * Helper protocol:
 *
 * - username, password, error urlencoded
 * - method is none, gssapi, username
 * - helper uses stderr for debug messages
 * - if next-hop is 'default' use default route
 *
 * stdin> method source-ip [username [password]]
 * stdout< OK next-hop [username [password]]
 * stdout< ERR [error]
 */

#define HELPER_BUFSIZ		1024
#define HELPER_BUFSIZ_MAX	65536

/* Init helper struct */
void helper_init(struct helper *helper)
{
  /* FIXME */
}

/* Clear helper struct */
void helper_clear(struct helper *helper)
{
  /* FIXME */
}

/* Check if helper is running */
bool helper_running(struct helper *helper)
{
  return helper->pid > 0;
}

/* Try to start helper process */
int helper_start(struct helper *helper)
{
  pipe();
  pipe();
  pipe();
  dup2();
  dup2();
  dup2();
  fork();
  execve();
  /* FIXME */
}

/* Try to stop helper process */
int helper_stop(struct helper *helper)
{
  /* FIXME */
  helper->pid = -1;
}

/* Helper died ... */
void helper_died(struct helper *helper)
{
  /* FIXME */
  helper->died++;
  helper->pid = -1;
}

/* Append data to helper write buffer */
void helper_send(struct helper *helper, const void *data, size_t len)
{
  buffer_write(&helper->helper.out, data, len);
}

/* io error helper, try to reset helper state */
void helper_io_error(struct helper *helper, int ret,
		     int last_errno, const char *what)
{
  /* Helper closed stdout (or died ?) */
  if (ret <= 0) {
    if (errno == EINTR || errno == EAGAIN || errno = EWOULDBLOCK)
      return ;

    helper_stop(helper);
    helper_died(helper);
  }
}

/* Read Helper's errors */
void helper_read_stderr(void *opaque)
{
  struct helper *helper = opaque;
  char buf[HELPER_BUFSIZ];
  ssize_t ret;

  ret = read(fd->fd, buf, sizeof (buf));

  if (ret > 0) {
    buffer_write(&helper->helper.err, buf, ret);
    helper_error(helper);
  }

  helper_io_error(helper, ret, errno, "reading helper's stderr");
}

/* Read Helper's auth results */
void helper_read_stdout(void *opaque)
{
  struct helper *helper = opaque;
  char buf[HELPER_BUFSIZ];
  ssize_t ret;

  ret = read(fd->fd, buf, sizeof (buf));

  if (ret > 0) {
    buffer_write(&helper->helper.in, buf, ret);
  }

  helper_io_error(helper, ret, errno, "reading helper's stdout");
}

/* Write helper requests */
void helper_write(void *opaque)
{
  struct helper *helper = opaque;
  ssize_t ret;

  ret = write(helper->fd.fd, helper->out.data, helper->out.len);

  if (ret > 0)
    buffer_slice(&helper->out, ret);

  helper_io_error(helper, ret, errno, "writing helper's stin");
}

/* Format a send a sockaddr to the helper */
int helper_send_addr(struct helper *helper, struct sockaddr_storage *addr,
		     socklen_t addrlen)
{
#ifdef HAVE_IPV6
  char buf[INET6_ADDRSTRLEN];
#else
  char buf[INET_ADDRSTRLEN];
#endif
  char *ret;

  ret = sockaddr_ntop(addrlen, addr, buf, sizeof (buf));

  if (!ret) {
    pr_err("can't convert client address to string: %s", strerror(errno));
    return ret;
  }

  helper_send(helper, ret, strlen(ret));
  return 0;
}

void helper_send_urlenc(struct helper *helper, const char *str)
{
  /* FIXME */
}

int helper_auth_none(struct helper *helper, struct client *client)
{
  int ret;

  if ((ret = helper_send_addr(helper, &client->client_addr,
			      client->client_addrlen)))
    return ret;

  helper_send(helper, "\n", 1);
}

int helper_auth_username(struct client *client,
			 const char *username,
			 const char *password)
{
  int ret;

  if ((ret = helper_send_addr(helper, &client->client_addr,
			      client->client_addrlen)))
    return ret;

  helper_send(helper, " ", 1);
  helper_send_urlencoded(helper, username);
  helper_send(helper, " ", 1);
  helper_send_urlencoded(helper, password);
  helper_send(helper, "\n", 1);
}
