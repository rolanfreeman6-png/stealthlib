project(StealthLibTests)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_SOURCE_DIR}/stealthlib ${CMAKE_SOURCE_DIR})

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
    if(MSVC)
        target_compile_options(${name} PRIVATE /W4 /Zc:__cplusplus /EHsc)
    else()
        target_compile_options(${name} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
    add_test(NAME ${name} COMMAND ${name})
endfunction()

add_stealth_test(string_test string_test.cpp)
add_stealth_test(portable_smoke_test portable_smoke_test.cpp)

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

if(WIN32)
    add_stealth_test(integration_test integration_test.cpp)
    add_stealth_test(comprehensive_test comprehensive_test.cpp)
    add_stealth_test(peb_test peb_test.cpp)
    add_stealth_test(regression_test regression_test.cpp regression_tu_a.cpp regression_tu_b.cpp)
endif()
