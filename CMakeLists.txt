cmake_minimum_required(VERSION 3.9)
project(kvalidator)

IF(NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE Release)
ENDIF()

set(SRCS_LIB
  "${CMAKE_CURRENT_SOURCE_DIR}/builtin/builtin.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/validator/validator.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/utils/fs.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/elf/elf-parser.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/crypto/sha256.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/crypto/pkcs1.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/cert/base64.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/cert/asn1-oid.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/cert/asn1-parser.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/cert/asn1-types.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/cert/x509-name.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/cert/x509-path.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/cert/x509-pubkey.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/cert/x509.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/cert/pem-parser.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/cert/cert-validator.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/dso/rsa.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/dso/bignum.c"
)

set(SRCS_DSO_CLI
  "${CMAKE_CURRENT_SOURCE_DIR}/dso/cli_main.c"
)

include_directories(
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

set(COMMON_WARNINGS					"-Wall")

set(CMAKE_C_FLAGS_DEBUG           "-g ${COMMON_WARNINGS}")
set(CMAKE_C_FLAGS_RELEASE         "-O2 ${COMMON_WARNINGS}")
set(CMAKE_C_FLAGS_PROFILE         "-O2 -pg ${COMMON_WARNINGS}")

add_library(kvalidator STATIC ${SRCS_LIB})

add_executable(dso_cli ${SRCS_DSO_CLI})
target_link_libraries(dso_cli
  kvalidator
)

install(TARGETS kvalidator dso_cli
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    PUBLIC_HEADER DESTINATION include
)
