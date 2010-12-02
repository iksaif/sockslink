#cmakedefine SOCKSLINK_VERSION	"@SOCKSLINK_VERSION@"
#cmakedefine HAVE_IPV6

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
#define SOCKS_STREAM_BUFSIZ	(1024 * 4)
