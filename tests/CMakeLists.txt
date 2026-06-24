project(StealthLibTests)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_SOURCE_DIR}/stealthlib ${CMAKE_SOURCE_DIR})

function(add_stealth_test name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE stealthlib)
    if(MSVC)
        target_compile_options(${name} PRIVATE /W4 /Zc:__cplusplus /EHsc)
    else()
        target_compile_options(${name} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endfunction()

add_stealth_test(string_test string_test.cpp)
add_stealth_test(peb_test peb_test.cpp)
add_stealth_test(integration_test integration_test.cpp)