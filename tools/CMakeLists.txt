cmake_minimum_required(VERSION 3.9)
project(sigtool)

IF(NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE Release)
ENDIF()

set(SRCS
	"${CMAKE_CURRENT_SOURCE_DIR}/../utils/reader.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/../elf/elf-op.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/../elf/elf-op.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gen_rsa_key.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/sigtool.c"
)

#
# Find libssl
#
find_library(SSL_LIBRARY
  NAMES ssl
  HINTS "/usr/lib"
  REQUIRED
)
if (${SSL_LIBRARY} STREQUAL "SSL_LIBRARY-NOTFOUND")
message(FATAL_ERROR "Can't find OpenSSL library. Please try to install libssl-dev.")
endif()

find_library(CRYPTO_LIBRARY
  NAMES crypto
  HINTS "/usr/lib"
  REQUIRED
)
if (${CRYPTO_LIBRARY} STREQUAL "CRYPTO_LIBRARY-NOTFOUND")
message(FATAL_ERROR "Can't find libcrypto of OpenSSL. Please try to install libssl-dev.")
endif()

find_path(SSL_INCLUDE
  NAMES openssl
  HINTS "/usr/include"
  REQUIRED
)
if (${SSL_INCLUDE} STREQUAL "SSL_INCLUDE-NOTFOUND")
message(FATAL_ERROR "Can't find OpenSSL header files. Please try to install libssl-dev.")
endif()

include_directories(
    "${CMAKE_CURRENT_SOURCE_DIR}/../include"
    ${SSL_INCLUDE}
)

set(COMMON_WARNINGS					"-Wall")

set(CMAKE_C_FLAGS_DEBUG           "-g ${COMMON_WARNINGS}")
set(CMAKE_C_FLAGS_RELEASE         "-O2 ${COMMON_WARNINGS}")
set(CMAKE_C_FLAGS_PROFILE         "-O2 -pg ${COMMON_WARNINGS}")

add_executable(${PROJECT_NAME} ${SRCS})
target_link_libraries(${PROJECT_NAME}
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)
