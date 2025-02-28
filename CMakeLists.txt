cmake_minimum_required(VERSION 3.20)

project(Logger C CXX)

option(ENABLE_VERBOSE_LOG "Enable verbose logging" ON)
option(ENABLE_DEBUG_LOG "Enable debug log" ON)

message("Compiler Version: ${CMAKE_C_COMPILER_VERSION}")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

function(add_example name isCXX)
    if(${isCXX} STREQUAL "true")
    add_executable(${name} "${CMAKE_SOURCE_DIR}/examples/${name}.cpp")
    else()
    add_executable(${name} "${CMAKE_SOURCE_DIR}/examples/${name}.c")
    endif()
    target_include_directories(${name} PRIVATE "${CMAKE_SOURCE_DIR}/src")
endfunction(add_example)

add_example(example1 "true")
