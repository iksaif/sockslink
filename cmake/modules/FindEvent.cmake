# Find Libevent
# http://monkey.org/~provos/libevent/
#
# Once done, this will define:
#
# Event_FOUND - system has Event
# Event_INCLUDE_DIRS - the Event include directories
# Event_LIBRARIES - link these to use Event
#

if (EVENT_INCLUDE_DIR AND EVENT_LIBRARY)
  # Already in cache, be silent
  set(EVENT_FIND_QUIETLY TRUE)
endif (EVENT_INCLUDE_DIR AND EVENT_LIBRARY)

find_path(EVENT_INCLUDE_DIR event.h
  PATH_SUFFIXES event
)

find_library(EVENT_LIBRARY
  NAMES event
)

set(EVENT_LIBRARIES ${EVENT_LIBRARY} )

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(EVENT
  DEFAULT_MSG
  EVENT_INCLUDE_DIR
  EVENT_LIBRARIES
)

mark_as_advanced(EVENT_INCLUDE_DIR EVENT_LIBRARY)

