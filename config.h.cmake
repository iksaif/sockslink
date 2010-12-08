#cmakedefine SOCKSLINK_VERSION	"@SOCKSLINK_VERSION@"
#cmakedefine HAVE_IPV6
#cmakedefine HAVE_EVENT_BASE_LOOPBREAK
#cmakedefine HAVE_EVENT_BASE_NEW
#cmakedefine HAVE_BUFFEREVENT_SETCB
#cmakedefine HAVE_BUFFEREVENT_SETWATERMARK
#cmakedefine HAVE_BUFFEREVENT_SETWATERMARK_PROTO

/*
 * number of second the client have to finish the authentication
 * process
 */
#define SOCKS5_AUTH_TIMEOUT	120

/*
 * number of second the client can stay connected without
 * doing any io
 */
#define SOCKS_IO_TIMEOUT	86400

/*
 * Stream buffer size
 */
#define SOCKS_STREAM_BUFSIZ	(1024 * 64 * 2)

/*
 * Timeout before re-trying to launch helper
 */
#define HELPERS_REFILL_POOL_TIMEOUT	{ 5, 0 }

/*
 * Maximum startup time for an helper
 */
#define HELPER_STARTUP_TIMEOUT	30

/*
 * Maximum auth time for an helper
 */
#define HELPER_AUTH_TIMEOUT	10

/*
 * Path of default config file
 */
#define SOCKSLINK_CONF_FILE	"/etc/socks/sockslinkd.conf"
