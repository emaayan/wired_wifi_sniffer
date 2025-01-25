# The following lines of boilerplate have to be in your project's CMakeLists
# in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

#set(SDKCONFIG "${CMAKE_BINARY_DIR}/sdkconfig")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
idf_build_set_property(MINIMAL_BUILD ON)

file(READ "version.txt" PROJECT_VER)
set(PROJECT_PREF "WirelessSniffer") 
set(PROJECT_BIN "${PROJECT_PREF}_${PROJECT_VER}")

project("${PROJECT_BIN}")
