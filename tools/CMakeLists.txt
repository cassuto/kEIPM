cmake_minimum_required(VERSION 3.9)
project(sigtool)

IF(NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE Release)
ENDIF()

set(SRCS_LIB
  "${CMAKE_CURRENT_SOURCE_DIR}/../utils/fs.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/../elf/elf-parser.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/../elf/elf-writer.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gen_rsa_key.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gen_cert.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/sign_elf.c"
)

set(SRCS_TOOL
  "${CMAKE_CURRENT_SOURCE_DIR}/keipm_cli.c"
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

ADD_LIBRARY(sigelf ${SRCS_LIB})

add_executable(keipm_cli ${SRCS_TOOL})
target_link_libraries(keipm_cli
  sigelf
  ${SSL_LIBRARY}
  ${CRYPTO_LIBRARY}
)

install(TARGETS keipm_cli
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    PUBLIC_HEADER DESTINATION include
)
