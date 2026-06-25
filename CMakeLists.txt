cmake_minimum_required(VERSION 3.16)
project(StealthLib VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(STEALTHLIB_ROOT_DIR ${CMAKE_CURRENT_SOURCE_DIR})
else()
    set(STEALTHLIB_ROOT_DIR ${CMAKE_SOURCE_DIR})
endif()

option(STEALTH_BUILD_EXAMPLES    "Build examples"     ON)
option(STEALTH_BUILD_TESTS       "Build tests"        ON)
option(STEALTH_BUILD_BENCHMARK   "Build benchmark"    ON)
option(STEALTH_BUILD_FIXTURES    "Generate PE fixtures for tests" ON)
option(STEALTH_SANITIZERS        "Enable ASan + UBSan (Linux only)" OFF)
option(STEALTH_CLANG_TIDY        "Run clang-tidy on targets" OFF)
option(STEALTHLIB_SSE2_DECRYPT   "Enable SSE2 _mm_xor_si128 fast path for strings >= 32 bytes" OFF)

if(STEALTH_SANITIZERS)
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(FATAL_ERROR "Stealth sanitizers are Linux-only (ASan/UBSan). Current system: ${CMAKE_SYSTEM_NAME}")
    endif()
    set(_sb "-fsanitize=address,undefined")
    if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        message(WARNING "Sanitizers typically require Debug build. Forcing -O0.")
    endif()
    add_compile_options(${_sb})
    add_link_options(${_sb})
endif()

if(NOT DEFINED STEALTH_BUILD_KEY)
    execute_process(
        COMMAND git rev-parse --short HEAD
        WORKING_DIRECTORY ${STEALTHLIB_ROOT_DIR}
        OUTPUT_VARIABLE STEALTH_GIT_SHA
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(STEALTH_GIT_SHA)
        string(REPLACE "\n" "" STEALTH_GIT_SHA "${STEALTH_GIT_SHA}")
    else()
        set(STEALTH_GIT_SHA "0000000")
    endif()
    string(TIMESTAMP STEALTH_TS "%Y%m%d%H%M%S")
    set(STEALTH_BUILD_KEY_SEED "${STEALTH_GIT_SHA}-${STEALTH_TS}")
    string(MD5 STEALTH_BUILD_KEY_MD5 "${STEALTH_BUILD_KEY_SEED}")
    # Truncate MD5 to 64 bits so the resulting hex literal fits u64 cleanly,
    # without -Wconversion "integer constant is too large" warnings.
    string(SUBSTRING "${STEALTH_BUILD_KEY_MD5}" 0 16 STEALTH_BUILD_KEY_HEX)
    set(STEALTH_BUILD_KEY "0x${STEALTH_BUILD_KEY_HEX}ULL")
else()
    message(STATUS "STEALTH_BUILD_KEY provided externally: ${STEALTH_BUILD_KEY}")
endif()

message(STATUS "StealthLib ${PROJECT_VERSION}")
message(STATUS "  Build Examples : ${STEALTH_BUILD_EXAMPLES}")
message(STATUS "  Build Tests    : ${STEALTH_BUILD_TESTS}")
message(STATUS "  Build Benchmark: ${STEALTH_BUILD_BENCHMARK}")
message(STATUS "  Build Fixtures : ${STEALTH_BUILD_FIXTURES}")
message(STATUS "  Sanitizers     : ${STEALTH_SANITIZERS}")
message(STATUS "  Build Key      : ${STEALTH_BUILD_KEY}")

if(STEALTH_CLANG_TIDY)
    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        message(WARNING "STEALTH_CLANG_TIDY=ON requested but compiler is not Clang/GCC; skipping.")
    else()
        set(CMAKE_CXX_CLANG_TIDY "clang-tidy;-checks=bugprone-*,performance-*,portability-*,readability-*,modernize-*,-bugprone-easily-swappable-parameters,-readability-magic-numbers,-readability-isolate-declaration,-readability-identifier-length")
        message(STATUS "Clang-Tidy enabled: ${CMAKE_CXX_CLANG_TIDY}")
    endif()
endif()

set(STEALTHLIB_HEADER_DIR ${STEALTHLIB_ROOT_DIR}/stealthlib)
set(STEALTHLIB_THIRDPARTY_DIR ${STEALTHLIB_ROOT_DIR}/tests/third_party)
set(STEALTHLIB_FIXTURES_DIR ${STEALTHLIB_ROOT_DIR}/tests/fixtures)
set(STEALTHLIB_FIXTURES_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR}/fixtures)

add_library(stealthlib INTERFACE)
# Include root is the repo root, so callers can use #include "stealthlib/stealth.hpp".
target_include_directories(stealthlib INTERFACE
    $<BUILD_INTERFACE:${STEALTHLIB_ROOT_DIR}>
    $<BUILD_INTERFACE:${STEALTHLIB_THIRDPARTY_DIR}>
    $<INSTALL_INTERFACE:include>
)
target_compile_features(stealthlib INTERFACE cxx_std_20)
target_compile_definitions(stealthlib INTERFACE
    STEALTH_BUILD_KEY=${STEALTH_BUILD_KEY}
)

if(STEALTHLIB_SSE2_DECRYPT)
    message(STATUS "SSE2 decrypt fast-path: ENABLED (x86_64 only)")
    target_compile_definitions(stealthlib INTERFACE
        STEALTHLIB_SSE2_DECRYPT=1
    )
else()
    message(STATUS "SSE2 decrypt fast-path: disabled (scalar fallback)")
    target_compile_definitions(stealthlib INTERFACE
        STEALTHLIB_SSE2_DECRYPT=0
    )
endif()

if(MSVC)
    target_compile_options(stealthlib INTERFACE /W4 /Zc:__cplusplus)
else()
    target_compile_options(stealthlib INTERFACE -Wall -Wextra -Wpedantic)
endif()

if(STEALTH_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# --- Tests ----------------------------------------------------------------

if(STEALTH_BUILD_TESTS)
    enable_testing()
    include(CTest)
    add_subdirectory(tests)
    if(STEALTH_BUILD_FIXTURES)
        add_custom_command(
            OUTPUT ${STEALTHLIB_FIXTURES_BUILD_DIR}/is_forwarder.dll
                   ${STEALTHLIB_FIXTURES_BUILD_DIR}/tiny_null.dll
                   ${STEALTHLIB_FIXTURES_BUILD_DIR}/corrupt_header.bin
            COMMAND ${CMAKE_COMMAND} -E make_directory ${STEALTHLIB_FIXTURES_BUILD_DIR}
            COMMAND ${Python3_EXECUTABLE} ${STEALTHLIB_FIXTURES_DIR}/generate_pe.py
                    ${STEALTHLIB_FIXTURES_BUILD_DIR}
            DEPENDS ${STEALTHLIB_FIXTURES_DIR}/generate_pe.py
            COMMENT "Generating PE fixture files (DIE-compatible)"
            VERBATIM
        )
        add_custom_target(stealth_pe_fixtures
            DEPENDS ${STEALTHLIB_FIXTURES_BUILD_DIR}/is_forwarder.dll
                    ${STEALTHLIB_FIXTURES_BUILD_DIR}/tiny_null.dll
                    ${STEALTHLIB_FIXTURES_BUILD_DIR}/corrupt_header.bin
        )
    endif()
endif()

if(STEALTH_BUILD_BENCHMARK)
    add_subdirectory(benchmark)
endif()

# --- Install --------------------------------------------------------------

install(TARGETS stealthlib EXPORT stealthlib-targets)
install(FILES
    ${STEALTHLIB_HEADER_DIR}/stealth.hpp
    DESTINATION include/stealthlib
)
# Ensure installed target exposes the include subfolder so that
# "#include \"stealthlib/stealth.hpp\"" works after install.
install(EXPORT stealthlib-targets
    FILE stealthlib-targets.cmake
    NAMESPACE stealthlib::
    DESTINATION lib/cmake/stealthlib
)
# Re-export under the top-level binary directory too for in-tree consumption.
export(EXPORT stealthlib-targets FILE "${CMAKE_CURRENT_BINARY_DIR}/stealthlib-targets.cmake")
