#
# CMakeLists.txt
#
# Copyright (C) 2023 Sebastian Reimers
#

##############################################################################
#
# Project and Versioning
#

cmake_minimum_required(VERSION 3.18)

project(restund VERSION 0.5.0 LANGUAGES C)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)

##############################################################################
#
# Module/Package Includes
#

include(GNUInstallDirs)
include(CheckIncludeFile)
find_package(RE REQUIRED)


##############################################################################
#
# Compile options
#

if(WIN32)
  option(STATIC "Build static" ON)
else()
  option(STATIC "Build static" OFF)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS OFF)

if(MSVC)
  add_compile_options("/W3")
else()
  add_compile_options(
    -Wall
    -Wextra
  )

  set(c_flags
    -pedantic
    -Wcast-align
    -Wbad-function-cast
    -Wmissing-declarations
    -Wmissing-prototypes
    -Wnested-externs
    -Wno-strict-aliasing
    -Wold-style-definition
    -Wshadow -Waggregate-return
    -Wstrict-prototypes
    -Wuninitialized
    -Wvla
  )

  if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    list(APPEND c_flags
      -Watomic-implicit-seq-cst
      -Wshorten-64-to-32
      -Wno-gnu-zero-variadic-macro-arguments
    )
  endif()

  add_compile_options(
    "$<$<COMPILE_LANGUAGE:C>:${c_flags}>"
  )
endif()

find_package(re CONFIG REQUIRED HINTS ../re/cmake)

list(APPEND RE_DEFINITIONS
  -DVERSION="${PROJECT_VERSION}"
)

add_definitions(${RE_DEFINITIONS})

include_directories(
  include
  src
  ${RE_INCLUDE_DIRS}
  ${OPENSSL_INCLUDE_DIR}
)

if(MOD_PATH)
  add_definitions(-DMOD_PATH="${MOD_PATH}")
elseif(CMAKE_INSTALL_FULL_LIBDIR)
  add_definitions(-DMOD_PATH="${CMAKE_INSTALL_FULL_LIBDIR}/restund/modules")
endif()

if(STATIC)
  add_definitions(-DSTATIC)
endif()

##############################################################################
#
# Source section
#

set(SRCS
  src/cmd.c
  src/db.c
  src/dtls.c
  src/log.c
  src/main.c
  src/stun.c
  src/tcp.c
  src/udp.c
)

##############################################################################
#
# Modules
#

find_package(MySQL)

if(NOT DEFINED MODULES)
  set(MODULES
    auth
    binding
    drain
    turn
  )

  if(MySQL_FOUND)
      list(APPEND MODULES mysql_ser)
  endif()
endif()

foreach(mod IN LISTS MODULES)
  add_subdirectory(modules/${mod})
  set_target_properties(${mod} PROPERTIES PREFIX "")
endforeach()

if(STATIC)
  foreach(mod IN LISTS MODULES)
    set(MOD_EXPORTS
      "${MOD_EXPORTS}extern const struct mod_export exports_${mod};\n")
    set(MOD_EXPORT_TABLE
      "${MOD_EXPORT_TABLE}  &exports_${mod},\n")
  endforeach()

  configure_file(src/static.c.in src/static.c)
  list(APPEND SRCS ${CMAKE_CURRENT_BINARY_DIR}/src/static.c)
else()
  foreach(mod IN LISTS MODULES)
    if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
      set_target_properties(${mod} PROPERTIES
                            LINK_FLAGS "-undefined dynamic_lookup")
    endif()
  endforeach()
endif()

##############################################################################
#
# Target executable
#

set(LINKLIBS ${RE_LIBRARIES} Threads::Threads)

if(ZLIB_FOUND)
  list(APPEND LINKLIBS ZLIB::ZLIB)
endif()

if(USE_OPENSSL)
  list(APPEND LINKLIBS OpenSSL::SSL OpenSSL::Crypto)
endif()

if(WIN32)
  list(APPEND LINKLIBS ws2_32 iphlpapi winmm gdi32 crypt32 strmiids
      ole32 oleaut32 qwave dbghelp)
else()
  list(APPEND LINKLIBS -lm ${RESOLV_LIBRARY})
endif()

add_executable(restund ${SRCS})

if(STATIC)
  target_link_libraries(restund PUBLIC ${LINKLIBS} ${MODULES})
else()
  target_link_libraries(restund PUBLIC ${LINKLIBS})
endif()
