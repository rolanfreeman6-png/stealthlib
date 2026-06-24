# Installation Guide

## Requirements

- C++20 compiler
- Windows 10/11 x64 (primary target)
- Linux x64 for portable string/encoding/memory tests only

### Supported Compilers

| Compiler | Minimum Version |
|----------|-----------------|
| MSVC | 19.29 (VS 2022) |
| GCC | 10+ |
| Clang | 10+ |

## Quick Install

### Option 1: Header-only (Recommended)

Copy `stealthlib/stealth.hpp` to your project:

```bash
cp -r stealthlib/ your_project/include/
```

```cpp
#include "stealthlib/stealth.hpp"
```

### Option 2: CMake FetchContent

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

### Option 3: CMake ExternalProject

```cmake
include(ExternalProject)
ExternalProject_Add(stealthlib
    GIT_REPOSITORY https://github.com/rolanfreeman6-png/stealthlib.git
    GIT_TAG main
    SOURCE_DIR ${CMAKE_SOURCE_DIR}/thirdparty/stealthlib
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_SOURCE_DIR}/thirdparty/stealthlib_install
    BUILD_COMMAND ${CMAKE_COMMAND} --build .
    INSTALL_COMMAND ${CMAKE_COMMAND} --install .
)
```

## Building Examples

```bash
git clone https://github.com/rolanfreeman6-png/stealthlib.git
cd stealthlib
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

## Build Options

| Option | Default | Description |
|--------|---------|-------------|
| `STEALTH_BUILD_EXAMPLES` | ON | Build Windows example programs |
| `STEALTH_BUILD_TESTS` | ON | Build test suite |
| `STEALTH_BUILD_BENCHMARK` | ON | Build Windows benchmark |

## Platform-Specific Notes

### Windows (MSVC)

No additional setup required. Uses native Windows APIs.

### Windows (MinGW/GCC)

Works out of the box with GCC 10+.

### Linux

Linux builds cover portable string obfuscation, encoding, and memory helpers. PEB walking and dynamic API resolution are Windows-only.
