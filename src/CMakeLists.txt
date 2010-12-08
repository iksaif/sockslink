find_package(Event REQUIRED)

include(CheckStructHasMember)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckLibraryExists)

check_struct_has_member("struct sockaddr_in6" sin6_addr netinet/in.h HAVE_IPV6)
check_library_exists(event event_base_loopbreak "" HAVE_EVENT_BASE_LOOPBREAK)
check_library_exists(event event_base_new "" HAVE_EVENT_BASE_NEW)
check_library_exists(event bufferevent_setcb "" HAVE_BUFFEREVENT_SETCB)
check_library_exists(event bufferevent_setwatermark "" HAVE_BUFFEREVENT_SETWATERMARK)
check_symbol_exists(bufferevent_setwatermark "sys/types.h;unistd.h;event.h" HAVE_BUFFEREVENT_SETWATERMARK_PROTO)

set(sockslink_SRCS
  main.c
  args.c
  sockslink.c
  client.c
  server.c
  helper.c
  log.c
  utils.c
  daemonize.c
  event-compat.c
)

add_executable(sockslinkd ${sockslink_SRCS})
target_link_libraries(sockslinkd event)