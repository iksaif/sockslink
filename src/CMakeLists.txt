find_package(Event REQUIRED)

include(CheckStructHasMember)

check_struct_has_member("struct sockaddr_in6" sin6_addr netinet/in.h HAVE_IPV6)

set(sockslink_SRCS
  main.c
  args.c
  sockslink.c
  client.c
  server.c
  log.c
  utils.c
  daemonize.c
)

add_executable(sockslinkd ${sockslink_SRCS})
target_link_libraries(sockslinkd event)