#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <netdb.h>
#include <unistd.h>

#include "config.h"
#include "sockslink.h"
#include "args.h"
#include "log.h"
#include "utils.h"

static void version(void)
{
  fprintf(stderr, "%s %s\n", program_invocation_short_name, SOCKSLINK_VERSION);
  fprintf(stderr, "Copyright (C) 2010 commonIT.\n\n");
  fprintf(stderr, "Written by Corentin Chary <corentincj@iksaif.net>\n");
}

static void usage(void)
{
  fprintf(stderr, "Usage: %s [options]\n",  program_invocation_short_name);
  fprintf(stderr, "Relay socks connections\n"
	  "\n"
	  "Mandatory arguments to long options are mandatory for short options too.\n"
#if defined(SO_BINDTODEVICE)
	  "  -i, --interface=<iface>   listen on this interface (none)\n"
#endif
	  "  -l, --listen=<addr>       listen on this address  (default: 0.0.0.0 and ::)\n"
	  "  -p, --port=<port>         TCP port (default: 1080)\n"
	  "  -d, --max-fds=<num>       maximum number of file descriptor open\n"
	  "                            = (clients * 2) + (helpers * 3) + 1\n"
	  "\n"
	  "  -P, --pipe                do nothing, just relay connections to next hop\n"
	  "  -n, --next-hop=<next>     default route when not specified by helper\n"
	  "                            to specify a non-standard port, use ':'\n"
	  "                            between address and port (example: '[::1]:1081' or \n"
	  "                            '192.168.0.1:1081')\n"
	  "  -H, --helper=<helper>     path to authentication and routing helper\n"
	  "  -j, --helpers-max=<num>   number of helper instances sockslink should start (default is 1)\n"
	  "  -m, --method=<method>     enable this method, arguments order defines method priority,\n"
	  "                            \"none\" and \"username\" methods are available\n"
	  "\n"
	  "  -D, --foreground          don't go to background (default: go to background)\n"
	  "      --pidfile=<file>      write the pid in this file (default: /var/run/sockslinkd.pid)",
	  "  -u, --user=<username>     change to this user after startup\n"
	  "  -g, --group=<group>       change to this group after startup\n"
	  "  -v, --verbose             be more verbose\n"
	  "  -q, --quiet               be more quiet\n"
	  "\n"
	  "  -c, --conf                config file path\n"
	  "\n"
	  "  -h, --help                display this help and exit\n"
	  "  -V, --version             output version information and exit\n"
	  );
}

static int parse_helper(SocksLink *sl, const char *optarg)
{
  struct stat st;

  if (sl->helper_command) {
    pr_err(sl, "helper already set");
    return -1;
  }
  if (stat(optarg, &st)) {
    pr_err(sl, "can't get helper's informations: %s\n",
	   strerror(errno));
    return -1;
  }
  if (!S_ISREG(st.st_mode)) {
    pr_err(sl, "helper is not a regular file");
    return -1;
  }
  sl->helper_command = strdup(optarg);
  return 0;
}

static int parse_helpers_max(SocksLink *sl, const char *optarg)
{
  if (sl->helpers_max) {
    pr_err(sl, "helper num already set\n");
    return -1;
  }
  sl->helpers_max = strtol(optarg, NULL, 0);
  if (sl->helpers_max < 1) {
    pr_err(sl, "invalid argument for --helpers-max: '%s'\n",
	   optarg);
    return -1;
  }
  return 0;
}

static int parse_fd_max(SocksLink *sl, const char *optarg)
{
  if (getuid() != 0) {
    pr_err(sl, "can only set maximum number of fd when root\n");
    return -1;
  }
  if (sl->fds_max) {
    pr_err(sl, "maximum number of fd already set\n");
    return -1;
  }
  sl->fds_max = strtol(optarg, NULL, 0);
  if (sl->fds_max < 1) {
    pr_err(sl, "invalid argument for --max-fds '%s'\n",
	   optarg);
    return -1;
  }
  return 0;
}

#if defined(SO_BINDTODEVICE)
static int parse_interface(SocksLink *sl, const char *optarg)
{
  if (sl->iface) {
    fprintf(stderr,  "error: listenning interface already set\n");
    return -1;
  }
  sl->iface = strdup(optarg);
  return 0;
}
#endif

static int parse_addresses(SocksLink *sl, const char *optarg)
{
  for (int i = 0; i < SOCKSLINK_LISTEN_FD_MAX; ++i)
    if (!sl->addresses[i]) {
      sl->addresses[i] = strdup(optarg);
      return 0;
    }

  pr_err(sl, "can't listen on more than %d addresses", SOCKSLINK_LISTEN_FD_MAX);
  return -1;
}

static int parse_method(SocksLink *sl, const char *optarg)
{
  uint8_t method = AUTH_METHOD_INVALID;

  if (!strcmp(optarg, "none"))
    method = AUTH_METHOD_NONE;
  if (!strcmp(optarg, "username"))
    method = AUTH_METHOD_USERNAME;

  if (method == AUTH_METHOD_INVALID) {
    pr_err(sl, "unknown method '%s' (available methods are 'none' and 'username')", optarg);
    return -1;
  }

  for (int i = 0; i < sizeof (sl->methods); ++i) {
    if (sl->methods[i] == AUTH_METHOD_INVALID) {
      sl->methods[i] = method;
      return 0;
    }
  }

  pr_err(sl, "you already specified more than %d methods, skipping '%s'",
	 ARRAY_SIZE(sl->methods), optarg);
  return 0;
}

static int parse_port(SocksLink *sl, const char *optarg)
{
  if (sl->port) {
    pr_err(sl, "port already specified");
    return -1;
  }
  sl->port = strdup(optarg);
  return 0;
}

static int parse_nexthop(SocksLink *sl, const char *optarg)
{
  int ret;

  ret = parse_ip_port(optarg, "socks", &sl->nexthop_addr, &sl->nexthop_addrlen);

  if (ret != 0) {
    pr_err(sl, "getaddrinfo(%s): %s", optarg, gai_strerror(ret));
    return ret;
  }

  return 0;
}

static int parse_arg(SocksLink *sl, int c, char *optarg)
{
  switch (c) {
  case 'c':
    if (sl->conf) {
      pr_err(sl, "configuration file already set");
      goto error;
    }
    sl->conf = strdup(optarg);
    break;

  case 't':
    if (sl->pid) {
      pr_err(sl, "pid file already set");
      goto error;
    }
    sl->pid = strdup(optarg);
    break;

  case 'D':
    sl->fg = true;
    break;

  case 'v':
    sl->verbose++;
    break;

  case 'q':
    sl->verbose--;
    break;

  case 'u':
    if (getuid() != 0) {
      pr_err(sl, "--user can only be used when running as root");
      goto error;
    }
    if (sl->username) {
      pr_err(sl, "user already specified");
      goto error;
    }
    sl->username = strdup(optarg);
    break;

  case 'g':
    if (getuid() != 0) {
      pr_err(sl, "--group can only be used when running as root");
      goto error;
    }
    if (sl->groupname) {
      pr_err(sl, "group already specified");
      goto error;
    }
    sl->groupname = strdup(optarg);
    break;

  case 'l':
    if (parse_addresses(sl, optarg))
      goto error;
    break;

#if defined(SO_BINDTODEVICE)
  case 'i':
    if (parse_interface(sl, optarg))
      goto error;
    break;
#endif

  case 'H':
    if (parse_helper(sl, optarg))
      goto error;
    break;

  case 'j':
    if (parse_helpers_max(sl, optarg))
      goto error;
    break;

  case 'd':
    if (parse_fd_max(sl, optarg))
      goto error;
    break;

  case 'm':
    if (parse_method(sl, optarg))
      goto error;
    break;

  case 'n':
    if (parse_nexthop(sl, optarg))
      goto error;
    break;

  case 'P':
    sl->pipe = true;
    break;

  case 'p':
    if (parse_port(sl, optarg))
      goto error;
    break;

  case 'h':
    usage();
    exit(0);

  case 'V':
    version();
    exit(0);

  case '?':
  default:
    usage();
    return -1;
  }
  return 0;
 error:
  return -1;
}

static struct option long_options[] =
  {
    {"conf",          no_argument,       0, 'c'},
    {"foreground",    no_argument,       0, 'D'},
    {"pidfile",       required_argument, 0, 't'},
    {"verbose",       no_argument,       0, 'v'},
    {"quiet",         no_argument,       0, 'q'},
    {"user",          required_argument, 0, 'u'},
    {"group",         required_argument, 0, 'g'},
    {"listen",        required_argument, 0, 'l'},
    {"interface",     required_argument, 0, 'i'},
    {"port",          required_argument, 0, 'p'},
    {"max-fds",       required_argument, 0, 'd'},
    {"pipe",          no_argument,       0, 'P'},
    {"helper",        required_argument, 0, 'H'},
    {"helpers-max",   required_argument, 0, 'j'},
    {"method",        required_argument, 0, 'm'},
    {"next-hop",      required_argument, 0, 'n'},
    {"help",          no_argument,       0, 'h'},
    {"version",       no_argument,       0, 'V'},
    {NULL, 0, 0, '\0'}
  };

/* Basic dummy file parser */
static int parse_conf(SocksLink *sl, const char *filename)
{
  FILE *fp = fopen(filename, "r");
  char buffer[1024];
  char *val;

  if (!fp) {
    pr_warn(sl, "can't open configuration file '%s': %s", filename,
	    strerror(errno));
    return -1;
  }

  while (fgets(buffer, sizeof (buffer), fp)) {
    if (*buffer == '#')
      continue ;

    val = strrchr(buffer, '\n');

    if (val)
      *val = '\0';

    val = strchr(buffer, '=');

    if (val) {
      *val = '\0';
      val++;
    }
    if (val)
      pr_trace(sl, "configuration: %s = '%s'", buffer, val);
    else
      pr_trace(sl, "configuration: %s", buffer, val);

    for (struct option *opt = long_options; opt->name; opt++) {
      if (!strcmp(buffer, opt->name)) {
	if (opt->has_arg == no_argument && val)
	  pr_err(sl, "%s doesn't take any argument", buffer);
	else if (opt->has_arg == required_argument && !val)
	  pr_err(sl, "%s needs an argument", buffer);
	else
	  parse_arg(sl, opt->val, val);
      }
    }
  }

  fclose(fp);
  return 0;
}

int parse_args(int argc, char *argv[], SocksLink * sl)
{
  while (1) {
    int option_index = 0;
    int c;

    c = getopt_long(argc, argv, "t:c:Dvqu:g:i:l:p:H:j:Pd:m:n:b:hV",
		    long_options, &option_index);

    if (c == -1)
      break;

    if (parse_arg(sl, c, optarg))
      goto error;
  }

  if (!sl->conf)
    sl->conf = strdup(SOCKSLINKD_CONF_FILE);

  parse_conf(sl, sl->conf);

  if (!sl->pid && !sl->fg)
    sl->pid = strdup(SOCKSLINKD_PID_FILE);

  if (sl->pipe && sl->helper_command) {
    pr_err(sl, "You can't use --pipe with --helper");
    return -1;
  }

  if (sl->pipe && sl->methods[0] != AUTH_METHOD_INVALID) {
    pr_err(sl, "You can't use --pipe with --method");
    return -1;
  }

  if (sl->pipe && !sl->nexthop_addrlen) {
    pr_err(sl, "You can't use --pipe without --next-hop");
    return -1;
  }

  if (!sl->helper_command && !sl->nexthop_addrlen) {
    pr_err(sl, "You must specify --helper-command or --next-hop");
    return -1;
  }

  if (!sl->fg) {
    pr_debug(sl, "switching to syslog");
    sl->syslog = true;
  }

  if (!sl->port)
    sl->port = strdup("1080");

  if (!sl->addresses[0]) {
    sl->addresses[0] = strdup("0.0.0.0");
#if defined(HAVE_IPV6)
    sl->addresses[1] = strdup("::");
#endif
  }

  if (sl->methods[0] == AUTH_METHOD_INVALID) {
    sl->methods[0] = AUTH_METHOD_NONE;
    if (sl->helper_command)
      sl->methods[1] = AUTH_METHOD_USERNAME;
  }

  if (sl->helper_command && !sl->helpers_max)
    sl->helpers_max = 1;

#if defined(DEBUG)
  sl->cores = 1;
#endif

  return 0;
 error:
  return -1;
}
