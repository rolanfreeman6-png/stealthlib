# Installation Guide - v2.2.3

## Requirements

- A C++20 compiler.
- CMake 3.20 or newer for CMake integration.
- Windows SDK for Windows-only APIs.
- Python 3 when `STEALTH_BUILD_FIXTURES=ON` (the default test setting).

Linux and macOS build the portable surface: strings, hashes, SHA-256,
encoding, secure memory, and `secure_string`. PE walking, export resolution,
IAT comparison, and Windows inspection APIs are Windows-only.

## CMake package

```sh
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/your/prefix \
  -DSTEALTH_BUILD_EXAMPLES=OFF -DSTEALTH_BUILD_TESTS=OFF
cmake --build build --parallel
cmake --install build
```

```cmake
find_package(stealthlib CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE stealthlib::stealthlib)
```

The installed package exports the library's generated `STEALTH_BUILD_KEY` to
consumers. Do not define a conflicting key on the consuming target.

## FetchContent

```cmake
include(FetchContent)
FetchContent_Declare(
    stealthlib
    GIT_REPOSITORY https://github.com/rolanfreeman6-png/stealthlib.git
    GIT_TAG main # Replace with a reviewed immutable commit or release tag.
)
FetchContent_MakeAvailable(stealthlib)
target_link_libraries(your_target PRIVATE stealthlib)
```

## Manual header integration

Copy the complete `stealthlib/` directory into an include root, then compile
with that root on the include path:

```sh
cp -R stealthlib your_project/third_party/include/
g++ -std=c++20 -Iyour_project/third_party/include \
  -DSTEALTH_BUILD_KEY=0x0123456789ABCDEFULL your.cpp
```

Copying only `stealthlib/stealth.hpp` cannot work because the umbrella header
includes sibling implementation headers.

Manual-copy builds must define a non-zero `STEALTH_BUILD_KEY`. The CMake
package and FetchContent integrations generate and propagate that definition;
manual compiler invocations do not.

## Build options

| Option | Default | Description |
| --- | --- | --- |
| `STEALTH_BUILD_EXAMPLES` | `ON` | Build examples. |
| `STEALTH_BUILD_TESTS` | `ON` | Build and register tests. |
| `STEALTH_BUILD_BENCHMARK` | `ON` | Build the microbenchmark. |
| `STEALTH_BUILD_FIXTURES` | `ON` | Generate PE fixtures; requires Python 3. |
| `STEALTH_SANITIZERS` | `OFF` | Enable ASan and UBSan on Linux. |
| `STEALTH_CLANG_TIDY` | `OFF` | Run clang-tidy during supported Clang/GCC builds. |
| `STEALTHLIB_SSE2_DECRYPT` | `OFF` | Enable the x86/x64 SSE2 literal path. |
| `STEALTH_BUILD_KEY` | generated | Override the producer build key. |

## Verification commands

```sh
cmake -S . -B build -DSTEALTH_BUILD_EXAMPLES=ON -DSTEALTH_BUILD_TESTS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

On x86/x64 targets, verify the SSE2 literal path with a separate configured
build because the default build intentionally uses the scalar path:

```sh
cmake -S . -B build-sse2 -DSTEALTHLIB_SSE2_DECRYPT=ON \
  -DSTEALTH_BUILD_EXAMPLES=OFF -DSTEALTH_BUILD_TESTS=ON \
  -DSTEALTH_BUILD_BENCHMARK=OFF -DSTEALTH_BUILD_FIXTURES=OFF
cmake --build build-sse2 --target test_sse2_parity --parallel
ctest --test-dir build-sse2 -R test_sse2_parity --output-on-failure
```

The CTest suite includes an isolated install-and-consume check and an isolated
subproject-consume check. They validate the two CMake integration paths above.

For Visual Studio multi-config generators:

```cmd
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
```
