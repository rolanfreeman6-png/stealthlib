cmake_minimum_required(VERSION 3.20)
project(StealthLibPackageConsumer LANGUAGES CXX)

find_package(stealthlib CONFIG REQUIRED)

add_executable(stealthlib_package_consumer main.cpp)
target_link_libraries(stealthlib_package_consumer PRIVATE stealthlib::stealthlib)
