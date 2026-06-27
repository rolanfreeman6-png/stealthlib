project(StealthLibBenchmark LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(benchmark benchmark.cpp)
target_link_libraries(benchmark PRIVATE stealthlib)

if(MSVC)
    target_compile_options(benchmark PRIVATE /W4 /Zc:__cplusplus /EHsc)
else()
    target_compile_options(benchmark PRIVATE -Wall -Wextra -Wpedantic)
endif()