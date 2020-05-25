cmake_minimum_required(VERSION 3.9)
project(sigtool)

IF(NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE Release)
ENDIF()

set(SRCS
	"${CMAKE_CURRENT_SOURCE_DIR}/elfop.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/elf-reader.c"
	"${CMAKE_CURRENT_SOURCE_DIR}/sigtool.c"
)

set(COMMON_WARNINGS					"-Wall")

set(CMAKE_C_FLAGS_DEBUG           "-g ${COMMON_WARNINGS}")
set(CMAKE_C_FLAGS_RELEASE         "-O2 ${COMMON_WARNINGS}")
set(CMAKE_C_FLAGS_PROFILE         "-O2 -pg ${COMMON_WARNINGS}")

add_executable(${PROJECT_NAME} ${SRCS})
