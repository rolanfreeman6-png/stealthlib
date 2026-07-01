project(StealthLibTests)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_SOURCE_DIR}/stealthlib ${CMAKE_SOURCE_DIR})

# Fixture directory used by doctest-based tests. Generated at configure
# time (see top-level CMakeLists.txt) directly here == the tests' working
# directory, so runtime open("fixtures/...") resolves with no copy step.
set(STEALTH_FIXTURES_DIR "${CMAKE_BINARY_DIR}/tests/fixtures")

foreach(flags_var
    CMAKE_CXX_FLAGS_RELEASE
    CMAKE_CXX_FLAGS_RELWITHDEBINFO
    CMAKE_CXX_FLAGS_MINSIZEREL
)
    string(REPLACE "/DNDEBUG" "" ${flags_var} "${${flags_var}}")
    string(REPLACE "-DNDEBUG" "" ${flags_var} "${${flags_var}}")
endforeach()

function(add_stealth_test name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE stealthlib)
    target_include_directories(${name} PRIVATE
        ${CMAKE_SOURCE_DIR}/tests/third_party
    )
    if(MSVC)
        target_compile_options(${name} PRIVATE /W4 /Zc:__cplusplus /EHsc)
    else()
        target_compile_options(${name} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
endfunction()

# PE fixtures are generated at configure time (see top-level CMakeLists.txt)
# directly into ${STEALTH_FIXTURES_DIR} == the tests' working directory, so
# the doctest PE tests can open("fixtures/<file>") with no copy step.

# --- v1.x baseline tests (assert-based) -----------------------------------

add_stealth_test(string_test string_test.cpp)
add_stealth_test(portable_smoke_test portable_smoke_test.cpp)

if(WIN32)
    add_stealth_test(integration_test  integration_test.cpp)
    add_stealth_test(comprehensive_test comprehensive_test.cpp)
    add_stealth_test(peb_test          peb_test.cpp)
    add_stealth_test(regression_test   regression_test.cpp regression_tu_a.cpp regression_tu_b.cpp)
endif()

add_executable(binary_scan_target binary_scan_target.cpp)
target_link_libraries(binary_scan_target PRIVATE stealthlib)
if(MSVC)
    target_compile_options(binary_scan_target PRIVATE /W4 /Zc:__cplusplus /EHsc)
else()
    target_compile_options(binary_scan_target PRIVATE -Wall -Wextra -Wpedantic)
endif()
add_test(
    NAME binary_scan_test
    COMMAND ${CMAKE_COMMAND}
        -DSTEALTH_BINARY=$<TARGET_FILE:binary_scan_target>
        -P ${CMAKE_CURRENT_SOURCE_DIR}/binary_scan.cmake
)

# --- v2.0 doctest-based tests ---------------------------------------------

function(add_stealth_doctest_test name source)
    add_executable(${name} ${source})
    target_link_libraries(${name} PRIVATE stealthlib)
    target_include_directories(${name} PRIVATE
        ${CMAKE_SOURCE_DIR}/tests/third_party
        ${STEALTH_FIXTURES_DIR}
    )
    if(MSVC)
        target_compile_options(${name} PRIVATE /W4 /Zc:__cplusplus /EHsc)
    else()
        target_compile_options(${name} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        LABELS "v2;doctest"
    )
endfunction()

add_stealth_doctest_test(doctest_string_test    test_strings.cpp)
add_stealth_doctest_test(doctest_peb_test       test_peb_windows.cpp)
add_stealth_doctest_test(doctest_integrity_test test_integrity.cpp)
add_stealth_doctest_test(doctest_hashes_test    test_hashes.cpp)
add_stealth_doctest_test(doctest_sha256_test    test_sha256.cpp)
add_stealth_doctest_test(doctest_hwbp_test      test_hwbp.cpp)

# Tier 1C: thread-safety harness for encrypted_string{}. Only meaningful on
# Linux + pthreads. Built unconditionally so a TSan-stripped ctest still
# builds/runs the test; users opt into TSan via CMAKE_CXX_FLAGS.
add_stealth_test(test_concurrent_decrypt    test_concurrent_decrypt.cpp)
add_stealth_test(test_deterministic_concurrency test_deterministic_concurrency.cpp)

# --- Tier 2D: RTE scenarios ----------------------------------------------
# Three real-world endurance tests covering the key compositions --
#   1. libc-walk   : loader-style + tight toggle loops (correctness)
#   2. signal-sweep: long-running server + repeated detection::scan()
#   3. stress      : 50000-cycle churn over a 17-literal lexicon
# Each is platform-neutral so they run on Linux GCC + Windows MSVC.
add_stealth_test(scenario_rte_libc_walk    scenario_rte_libc_walk.cpp)
add_stealth_test(scenario_rte_signal_sweep scenario_rte_signal_sweep.cpp)
add_stealth_test(scenario_rte_stress       scenario_rte_stress.cpp)

# Tier 2E: SSE2 fast-path parity check. Verifies that the
# _mm_xor_si128 fast path produces byte-identical output to the scalar
# fallback for a long literal (N=80, well above the 32-byte threshold).
add_stealth_test(test_sse2_parity           test_sse2_parity.cpp)

# --- Fuzz harness ---------------------------------------------------
# Build with -DSTEALTH_BUILD_FUZZER=ON (typically under clang because
# libFuzzer is ship-of-clang for now). Without that flag, the harness
# runs as a deterministic local-fuzz driver using a fixed seed corpus.
option(STEALTH_BUILD_FUZZER "Build libfuzzer harness (requires clang)" OFF)
if(STEALTH_BUILD_FUZZER)
    function(add_stealth_fuzz name source)
        add_executable(${name} ${source})
        target_link_libraries(${name} PRIVATE stealthlib)
        if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
            target_compile_options(${name} PRIVATE -Wall -Wextra -Wpedantic)
            if(DEFINED STEALTH_FUZZ_FLAGS)
                target_compile_options(${name} PRIVATE ${STEALTH_FUZZ_FLAGS})
                target_link_options(${name} PRIVATE ${STEALTH_FUZZ_FLAGS})
                target_compile_definitions(${name} PRIVATE STEALTH_LIBFUZZER_LINKED)
            endif()
        endif()
        if(WIN32)
            target_compile_options(${name} PRIVATE /W4 /permissive-)
        endif()
    endfunction()
    add_stealth_fuzz(fuzz_hashes   fuzz_hashes.cpp)
    add_stealth_fuzz(fuzz_strings  fuzz_strings.cpp)
    add_stealth_fuzz(fuzz_decoders fuzz_decoders.cpp)
endif()
