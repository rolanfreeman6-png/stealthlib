# Installation Guide (v2.0)

## Requirements

- C++20 compiler.
- Windows 10/11 x64 (primary target). Linux/macOS compiles the
  platform-independent surface for unit tests.
- Python 3 (only required to regenerate PE fixtures; not required to
  run tests — fixtures ship in `<build>/tests/fixtures/`).

## Supported Compilers

| Compiler | Minimum Version | CI job |
|----------|-----------------|--------|
| MSVC (VS 2022) | 19.29 | `windows-msvc-release` |
| Clang | 10+ | `windows-clang-release`, `linux-clang`, `linux-sanitizers` |
| GCC | 10+ | `linux-gcc` |

## Quick Install

### Option 1 — Header-only (recommended)

Copy `stealthlib/stealth.hpp` into your project:

```bash
mkdir -p your_project/third_party/stealthlib/include/stealthlib
cp stealthlib/stealth.hpp your_project/third_party/stealthlib/include/stealthlib/

g++ -std=c++20 -Iyour_project/third_party/stealthlib/include your.cpp
```

`S()`, `SW()` and the entire `stealth::*` API become available.

### Option 2 — CMake FetchContent

```cmake
include(FetchContent)
FetchContent_Declare(
    stealthlib
    GIT_REPOSITORY https://github.com/rolanfreeman6-png/stealthlib.git
    GIT_TAG main
)
FetchContent_MakeAvailable(stealthlib)

target_link_libraries(your_target PRIVATE stealthlib)
```

### Option 3 — CMake find_package (after install)

```bash
cmake -S . -B build --install-prefix /your/install/root
cmake --install build
```

```cmake
find_package(stealthlib CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE stealthlib::stealthlib)
```

## Build Options

| Option | Default | Description |
| --- | --- | --- |
| `STEALTH_BUILD_EXAMPLES` | ON | Build the example programs |
| `STEALTH_BUILD_TESTS` | ON | Build the test executables |
| `STEALTH_BUILD_BENCHMARK` | ON | Build the microbenchmark |
| `STEALTH_BUILD_FIXTURES` | ON | Generate PE fixtures for tests |
| `STEALTH_SANITIZERS` | OFF | Add `-fsanitize=address,undefined` (Linux only) |
| `STEALTH_CLANG_TIDY` | OFF | Run clang-tidy during compilation (clang/gcc only) |
| `STEALTH_BUILD_KEY` | auto | Override the build key (default: MD5 of git SHA + timestamp) |

## Build instructions

### Default

```bash
cmake -S . -B build -DSTEALTH_BUILD_EXAMPLES=ON -DSTEALTH_BUILD_TESTS=ON
cmake --build build --parallel
cd build && ctest --output-on-failure
```

### Linux with sanitizers (Debug + ASan + UBSan)

```bash
cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DSTEALTH_SANITIZERS=ON \
    -DSTEALTH_BUILD_TESTS=ON

cmake --build build --parallel
cd build && ctest --output-on-failure
```

`STEALTH_SANITIZERS=ON` is rejected on non-Linux systems.

### clang-tidy (Linux clang or GCC)

```bash
cmake -S . -B build -GNinja \
    -DCMAKE_CXX_COMPILER=clang++ \
    -DSTEALTH_CLANG_TIDY=ON \
    -DSTEALTH_BUILD_EXAMPLES=OFF -DSTEALTH_BUILD_TESTS=OFF

cmake --build build --parallel
```

### Windows MSVC

```cmd
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release --parallel
cd build && ctest -C Release --output-on-failure
```

If the GitHub Actions Windows runner is offering Visual Studio 2026,
use the `windows-2022` runs-on label (the project's CI already does).

## Platform-Specific Notes

### Windows (MSVC)

Native. All API surface available.

### Windows (Clang + Ninja)

Set `CMAKE_CXX_COMPILER=clang++`. All API surface available.

### Linux / macOS

Only the non-Windows surface compiles: `S()`, `SW()`, hashes,
encoding, secure memory, secure_string. Windows-only paths
(`stealth::get_peb_ptr`, `module_loader`, etc.) are wrapped in
`#ifdef _WIN32`. Tests that depend on Windows APIs are compiled
only when `_WIN32` is defined.

## What's in the install

| Path | Contents |
| --- | --- |
| `include/stealthlib/stealth.hpp` | The single public header |
| `lib/cmake/stealthlib/stealthlib-targets.cmake` | CMake targets export |
| `share/doc/stealthlib/` | README, PROJECT_PLAN, INSTALL, EXAMPLES |
