cmake_minimum_required(VERSION 3.20)
set(PROJECT_NAME "CLog")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()
project(${PROJECT_NAME} C CXX)

option(ENABLE_VERBOSE_LOG "Enable verbose logging" ON)
option(ENABLE_DEBUG_LOG "Enable debug log" ON)
set(BUILD_SHARED_LIBS ON CACHE BOOL "Build CLog as shared library" FORCE)

if(BUILD_SHARED_LIBS)
message(STATUS "${PROJECT_NAME}: Build CLog as shared library")
set(BUILD_LIB_FLAG "SHARED")
else()
message(STATUS "${PROJECT_NAME}: Build CLog as static library")
set(BUILD_LIB_FLAG "STATIC")
endif()

message("C Compiler Version: ${CMAKE_C_COMPILER_VERSION}")
message("C++ Compiler Version: ${CMAKE_CXX_COMPILER_VERSION}")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_library(CLog ${BUILD_LIB_FLAG} "${CMAKE_CURRENT_SOURCE_DIR}/src/CLog.c")
target_compile_definitions(CLog PRIVATE $<$<STREQUAL:${BUILD_LIB_FLAG},SHARED>:CLOG_BUILD_SHARED>)
target_compile_definitions(CLog PRIVATE CLOG_EXPORTS)

function(add_example name isCXX)
    if(${isCXX} STREQUAL "true")
    add_executable(${name} "${CMAKE_CURRENT_SOURCE_DIR}/examples/${name}.cpp")
    else()
    add_executable(${name} "${CMAKE_CURRENT_SOURCE_DIR}/examples/${name}.c")
    endif()
    target_include_directories(${name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
endfunction(add_example)

add_example(example3 "false")
target_link_libraries(example3 CLog)
target_compile_definitions(example3 PRIVATE $<$<STREQUAL:${BUILD_LIB_FLAG},SHARED>:CLOG_BUILD_SHARED>)

add_example(example1 "false")
add_example(example2 "true")
