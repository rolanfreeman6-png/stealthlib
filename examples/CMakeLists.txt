project(StealthLibExamples)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

function(add_stealth_example name)
    add_executable(${name} ${ARGN})
    target_link_libraries(${name} PRIVATE stealthlib)
    if(MSVC)
        target_compile_options(${name} PRIVATE /W4 /Zc:__cplusplus /EHsc)
    else()
        target_compile_options(${name} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endfunction()

# Cross-platform examples — compile on Windows + Linux/macOS.
add_stealth_example(minimal_test    minimal_test.cpp)
add_stealth_example(unlock_demo     unlock_demo.cpp)
add_stealth_example(hash_resolution hash_resolution.cpp)

# Windows-only examples — pull in `<windows.h>` API surface.
if(WIN32)
    add_stealth_example(full_demo       full_demo.cpp)
    add_stealth_example(game_protection game_protection.cpp)
    add_stealth_example(server_protection server_protection.cpp)
endif()