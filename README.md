# StealthLib

Header-only C++20 utilities for compile-time literal obfuscation, portable
encoding and memory helpers, plus Windows-only export resolution and
best-effort process inspection.

## Scope

`S("...")` and `SW(L"...")` transform literals at compile time and restore
them lazily. This is XOR **obfuscation**, not cryptography. The library does
not promise a binary without imports, API names, debug strings, or plaintext
outside the specific literals passed to `S`/`SW`.

Windows API resolution accepts a loaded module and resolves named exports by
name or FNV-1a hash. Forwarded exports are followed to their terminal loaded
module without loading a new DLL. `compare_iat_thunk()` checks a named import
in an **importing image** against the current terminal export address.

## Build and test

```sh
cmake -S . -B build -DSTEALTH_BUILD_EXAMPLES=ON -DSTEALTH_BUILD_TESTS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

The default test configuration generates PE fixtures, so it requires Python
3. Set `-DSTEALTH_BUILD_FIXTURES=OFF` when those fixture tests are not needed.

The configured suite includes literal, encoding, PE/export, IAT, package
installation, subproject integration, and thread-confinement regressions.
It also verifies a consumer built with `find_package(stealthlib)` and a
separate consumer built through `add_subdirectory`, the mechanism used by
`FetchContent`.

## Use

```cpp
#include "stealthlib/stealth.hpp"
#include <windows.h>

auto token = S("example-token");
{
    auto unlocked = token.unlock();
    consume(unlocked.c_str());
}
```

On Windows, use a function type or function-pointer type with hash lookup:

```cpp
using MessageBoxW_t = int(HWND, LPCWSTR, LPCWSTR, UINT);
constexpr auto module_hash = stealth::hashes::fnv("user32.dll");
constexpr auto function_hash = stealth::hashes::fnv("MessageBoxW");
auto message_box = stealth::get_function_by_hash<MessageBoxW_t>(
    module_hash, function_hash);
```

The target module must already be loaded. For a forwarded export, each
forwarded-to module must also already be loaded; the resolver deliberately
does not change process module reference counts.

## Installation

### CMake package

```sh
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/your/prefix \
  -DSTEALTH_BUILD_EXAMPLES=OFF -DSTEALTH_BUILD_TESTS=OFF
cmake --build build
cmake --install build
```

```cmake
find_package(stealthlib CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE stealthlib::stealthlib)
```

### FetchContent or add_subdirectory

```cmake
include(FetchContent)
FetchContent_Declare(
    stealthlib
    GIT_REPOSITORY https://github.com/rolanfreeman6-png/stealthlib.git
    GIT_TAG main # Pin this to a reviewed commit or release tag in production.
)
FetchContent_MakeAvailable(stealthlib)
target_link_libraries(your_target PRIVATE stealthlib)
```

### Manual header copy

Copy the entire `stealthlib/` directory, preserving its layout. Copying only
`stealth.hpp` is not sufficient because it includes implementation headers
from `detail/`, `encoding/`, `memory/`, `detection/`, `vmdetect/`, `pe/`, and
`integrity/`.

## Windows inspection contract

- PE export functions operate on a loaded image or a synthetic flat image
  buffer that spans its declared `SizeOfImage`; they do not accept an
  arbitrary truncated file buffer.
- `get_proc()` / `get_proc_by_hash()` follow `DLL.Function` and `DLL.#Ordinal`
  forwarders up to eight hops and return `nullptr` on a malformed forwarder,
  a cycle/depth limit, or an unloaded target module.
- `compare_iat_thunk(importing_module, function)` requires a named import with
  `OriginalFirstThunk` metadata. Its `hook_status` is `clean`, `hooked`,
  `not_found`, or `unavailable`; `hooked == false` alone is not a clean result.
- `detection::hardware_breakpoint_count()` returns `-1` for the current
  running thread because Windows cannot provide its valid context through
  `GetThreadContext`. Use `hardware_breakpoint_count_for_suspended_thread()`
  for a real suspended-thread handle. Debug registers are per-thread.

## Threading contract

Each `S()`/`SW()` object is thread-confined. Concurrent access to the same
object is a data race; use one instance per thread or external synchronization.
See [docs/THREADING.md](docs/THREADING.md).

## Security boundary

See [docs/SECURITY.md](docs/SECURITY.md) and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). The library is a hardening aid,
not a DRM system, cryptographic vault, anti-debug guarantee, or VM escape
detector.

## Version

StealthLib **2.2.1**.
