cmake_minimum_required(VERSION 3.16)
project(StealthLib VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(STEALTH_BUILD_EXAMPLES "Build Windows examples" ON)
option(STEALTH_BUILD_TESTS "Build tests" ON)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(STEALTHLIB_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR})
else()
    set(STEALTHLIB_ROOT_DIR ${CMAKE_SOURCE_DIR})
endif()

set(STEALTHLIB_HEADER_DIR ${STEALTHLIB_ROOT_DIR}/stealthlib)

add_library(stealthlib INTERFACE)
target_include_directories(stealthlib INTERFACE
    $<BUILD_INTERFACE:${STEALTHLIB_ROOT_DIR}>
    $<INSTALL_INTERFACE:include>
)
target_compile_features(stealthlib INTERFACE cxx_std_20)

if(MSVC)
    target_compile_options(stealthlib INTERFACE /W4 /Zc:__cplusplus)
else()
    target_compile_options(stealthlib INTERFACE -Wall -Wextra -Wpedantic)
endif()

option(STEALTH_BUILD_BENCHMARK "Build benchmark" ON)

if(STEALTH_BUILD_EXAMPLES AND WIN32)
    add_subdirectory(examples)
elseif(STEALTH_BUILD_EXAMPLES AND NOT WIN32)
    message(STATUS "Skipping examples: examples use Windows APIs")
endif()

if(STEALTH_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(STEALTH_BUILD_BENCHMARK AND WIN32)
    add_subdirectory(benchmark)
elseif(STEALTH_BUILD_BENCHMARK AND NOT WIN32)
    message(STATUS "Skipping benchmark: benchmark uses Windows API resolution")
endif()

install(TARGETS stealthlib EXPORT stealthlib-targets)
install(FILES
    ${STEALTHLIB_HEADER_DIR}/stealth.hpp
    DESTINATION include/stealthlib
)

export(EXPORT stealthlib-targets FILE "${CMAKE_CURRENT_BINARY_DIR}/stealthlib-targets.cmake")

message(STATUS "StealthLib ${PROJECT_VERSION}")
message(STATUS "  Build Examples: ${STEALTH_BUILD_EXAMPLES}")
