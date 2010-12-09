cmake_minimum_required(VERSION 2.6)

project(sockslink)

include(CMakeDependentOption)

set(VERSION_MAJOR "1")
set(VERSION_MINOR "0")
set(VERSION_PATCH "0")

if(CMAKE_SYSTEM_NAME MATCHES Linux)
  set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} /usr/share/apps/cmake/modules/)
endif()
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules/)

## GCC  ##
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE}")
set(CMAKE_C_FLAGS_DEBUG "-ggdb3 -DDEBUG=1 ${CMAKE_C_FLAGS_DEBUG}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall -Wstrict-prototypes -Werror-implicit-function-declaration -Wno-pointer-sign -pedantic -D_GNU_SOURCE")

# compile in debug mode
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING
    "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
    FORCE)
endif(NOT CMAKE_BUILD_TYPE)

# version
set (SOCKSLINK_VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")

# Find config.h
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(src)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake config.h ESCAPE_QUOTES)

## Package ##
set(CPACK_PACKAGE_VERSION_MAJOR ${VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${VERSION_PATCH})
set(CPACK_VERSION ${SOCKSLINK_VERSION})
set(CPACK_SOURCE_IGNORE_FILES
  "~$"
  "^${PROJECT_SOURCE_DIR}/\\\\.git"
  "^${PROJECT_SOURCE_DIR}/build/")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "sockslink-${CPACK_VERSION}")
set(CPACK_SOURCE_GENERATOR "TGZ;TBZ2")

include(CPack)
