<div align="center">

# 🛡️ StealthLib

### Header-only C++20 hardening utilities for literals, loaded Windows exports, integrity checks, and portable encoders.

[![CI](https://github.com/rolanfreeman6-png/stealthlib/actions/workflows/ci.yml/badge.svg)](https://github.com/rolanfreeman6-png/stealthlib/actions/workflows/ci.yml)
[![Heavy CI](https://github.com/rolanfreeman6-png/stealthlib/actions/workflows/heavy-ci.yml/badge.svg)](https://github.com/rolanfreeman6-png/stealthlib/actions/workflows/heavy-ci.yml)
[![CodeQL](https://github.com/rolanfreeman6-png/stealthlib/actions/workflows/codeql.yml/badge.svg)](https://github.com/rolanfreeman6-png/stealthlib/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/rolanfreeman6-png/stealthlib?label=release)](https://github.com/rolanfreeman6-png/stealthlib/releases)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-orange)](https://en.cppreference.com/w/cpp/20)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**StealthLib v2.2.3** — practical obfuscation + Windows inspection helpers with explicit limits and regression tests.

</div>

---

## ✨ What it is

StealthLib is a **header-only C++20** library that helps with:

- 🔐 compile-time transformation of selected string literals;
- 🧭 resolving already-loaded Windows exports by name or FNV-1a hash;
- 🪝 checking selected named IAT entries against terminal export addresses;
- 🧬 following PE forwarded exports such as `KERNEL32.X -> KERNELBASE.X`;
- 🧯 scoped plaintext lifetime through RAII unlock guards;
- 🧪 portable hash, SHA-256, Base64, hex, XOR, ROT13, and secure memory helpers.

> StealthLib is a hardening utility, **not** cryptography, DRM, anti-debug magic, or a promise that every byte of a binary is free of strings/imports. Verify final binaries for your target compiler and build mode.

---

## 🚀 Quick start

```bash
git clone https://github.com/rolanfreeman6-png/stealthlib.git
cd stealthlib
cmake -S . -B build -DSTEALTH_BUILD_EXAMPLES=ON -DSTEALTH_BUILD_TESTS=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Optional x86/x64 SSE2 parity check:

```bash
cmake -S . -B build-sse2 -DSTEALTHLIB_SSE2_DECRYPT=ON \
  -DSTEALTH_BUILD_EXAMPLES=OFF -DSTEALTH_BUILD_TESTS=ON \
  -DSTEALTH_BUILD_BENCHMARK=OFF -DSTEALTH_BUILD_FIXTURES=OFF
cmake --build build-sse2 --target test_sse2_parity --parallel
ctest --test-dir build-sse2 -R test_sse2_parity --output-on-failure
```

Minimal usage:

```cpp
#include "stealthlib/stealth.hpp"

void send_secret(const char* value);

int main() {
    auto token = S("example-token");

    {
        auto unlocked = token.unlock();
        send_secret(unlocked.c_str());
    } // plaintext object storage is wiped and the object is re-encrypted
}
```

⚠️ `unlock()` is intentionally **lvalue-only**. This is valid:

```cpp
auto token = S("secret");
auto guard = token.unlock();
```

This is rejected at compile time:

```cpp
// Rejected: calling unlock() directly on an S("secret") temporary.
```

---

## 📦 Installation

### CMake package

```bash
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=/your/prefix \
  -DSTEALTH_BUILD_EXAMPLES=OFF -DSTEALTH_BUILD_TESTS=OFF
cmake --build build --parallel
cmake --install build
```

```cmake
find_package(stealthlib CONFIG REQUIRED)
target_link_libraries(your_target PRIVATE stealthlib::stealthlib)
```

### FetchContent

```cmake
include(FetchContent)
FetchContent_Declare(
    stealthlib
    GIT_REPOSITORY https://github.com/rolanfreeman6-png/stealthlib.git
    GIT_TAG v2.2.3
)
FetchContent_MakeAvailable(stealthlib)
target_link_libraries(your_target PRIVATE stealthlib)
```

### Manual copy

Copy the **entire** `stealthlib/` directory into your include path. Copying only `stealth.hpp` is not enough because the umbrella header includes implementation headers from subdirectories.

Manual-copy builds must define a non-zero `STEALTH_BUILD_KEY` because the CMake-generated key is unavailable outside CMake integration:

```bash
c++ -std=c++20 -I/path/to/include -DSTEALTH_BUILD_KEY=0x0123456789ABCDEFULL your.cpp
```

---

## 🧩 Modules

| Area | API | Scope |
| --- | --- | --- |
| 🔐 Literal obfuscation | `S("...")`, `SW(L"...")` | Compile-time transform + lazy decrypt/re-encrypt object state. |
| 🧯 RAII plaintext window | `.unlock()` | Scoped access; guard destruction wipes plaintext storage and re-encrypts. |
| 🧭 Export resolver | `get_proc`, `get_function`, `get_function_by_hash` | Windows-only; resolves exports from already-loaded modules. |
| 🔁 Forwarded exports | `get_proc`, `is_eat_forwarded` | Follows `DLL.Function` / `DLL.#Ordinal` forwarders up to a bounded depth. |
| 🪝 IAT checks | `compare_iat_thunk` | Checks selected named imports and returns `hook_status`. |
| 🧠 Debug signals | `detection::scan()` | Best-effort user-mode signals; current-thread HWBP state is `unknown`. |
| 🖥️ VM hints | `vmdetect::scan()` | CPUID bit, vendor strings, and disk-size heuristic. |
| 🧮 Hashes | `hashes::fnv`, `hashes::djb2` | Compile-time/runtime hashing helpers. |
| 🔒 SHA-256 | `detail::sha256_oneshot` | Inline SHA-256 implementation with KAT tests. |
| 🧰 Encoding | Base64, hex, XOR, ROT13 | Portable helpers; decoders reject malformed input. |
| 🧼 Memory | `secure_zero`, `compare_constant_time` | Volatile zeroing and constant-time byte comparison. |

---

## 📜 Public API Contract

| Stable public surface | Notes |
| --- | --- |
| `S`, `SW` | Literal objects and lvalue-only `unlock()` guards. |
| `stealth::version`, `stealth::build_key` | Version/build metadata. |
| `stealth::hashes::*` | FNV-1a and DJB2 helpers. |
| `stealth::encoding::*` | Base64, hex, XOR, and ROT13 helpers. |
| `stealth::memory::*` | Secure zero and constant-time comparison. |
| `stealth::get_proc`, `get_function`, `get_function_by_hash` | Windows loaded-module export helpers. |
| `stealth::integrity::*` | Selected import/export integrity checks. |
| `stealth::detection::*`, `vmdetect::*` | Best-effort signals and environment hints. |

`stealth::detail::*` is internal and has no compatibility guarantee.

---

## 🧭 Support Matrix

| Surface | Windows | Linux | macOS |
| --- | --- | --- | --- |
| `S` / `SW` | yes | yes | yes |
| hashes / encoding / memory | yes | yes | yes |
| Windows PE resolver | yes | no | no |
| IAT / integrity checks | yes | no | no |
| debug signals | partial | partial | partial |
| VM hints | yes | yes | limited |

---

## 🪟 Windows API resolution

```cpp
#include "stealthlib/stealth.hpp"
#include <windows.h>

using MessageBoxW_t = int(HWND, LPCWSTR, LPCWSTR, UINT);

constexpr auto user32_hash = stealth::hashes::fnv("user32.dll");
constexpr auto msgbox_hash = stealth::hashes::fnv("MessageBoxW");

auto message_box = stealth::get_function_by_hash<MessageBoxW_t>(
    user32_hash,
    msgbox_hash
);
```

Important contract:

| Rule | Meaning |
| --- | --- |
| ✅ Already loaded modules | Resolver walks loaded modules; it does not call `LoadLibrary`. |
| ✅ Forwarder-aware | Forwarded exports resolve to the terminal loaded target. |
| ✅ Function type support | `get_function_by_hash<int(HWND, LPCWSTR, LPCWSTR, UINT)>` returns a function pointer. |
| ⚠️ Case-sensitive exports | Export names are compared as PE export names, not case-folded. |
| ⚠️ Bounded recursion | Malformed/cyclic forwarders return `nullptr`. |

---

## 🪝 Integrity API

```cpp
auto info = stealth::integrity::compare_iat_thunk(
    "your_module.exe",
    "kernel32.dll",
    "GetModuleFileNameA"
);

if (info.status == stealth::integrity::hook_status::hooked) {
    // info.actual != info.expected
}
```

| Status | Meaning |
| --- | --- |
| `clean` | Named IAT entry matches the resolved terminal export. |
| `hooked` | Runtime IAT entry differs from expected target. |
| `not_found` | Import was not present. |
| `unavailable` | Required metadata/dependency was unavailable or malformed. |

Use `status`, not only `hooked == false`.

---

## 🧪 Verification

Current local Windows verification for v2.2.3:

| Check | Result |
| --- | --- |
| Release build with examples/tests/benchmark | ✅ Passed |
| Default CTest suite with generated PE fixtures | ✅ 23/23 |
| No-fixture CTest suite | ✅ 22/22 |
| SSE2 parity target | ✅ Passed |
| Fuzz seed drivers in CTest | ✅ Passed |
| Installed package consumer | ✅ Build + run |
| FetchContent/subproject consumer | ✅ Build + run |
| Benchmark executable | ✅ Completed |
| Rvalue `unlock()` negative compile check | ✅ Rejected |
| x86 public syntax check | ✅ Passed |

GitHub workflows:

| Workflow | Trigger | Purpose |
| --- | --- | --- |
| ✅ CI | push, PR, daily, manual | Windows/MSVC, Linux/GCC, macOS/Clang build + tests. |
| 🧪 Heavy CI | weekly, manual | Sanitizers, strict warnings, clang-tidy, cppcheck, coverage, fuzz. |
| 🔎 CodeQL | push, PR, weekly, manual | GitHub CodeQL SAST. |
| 🚢 Release | tag `v*` | Build + CTest, then publish GitHub Release. |

---

## ⚙️ Build options

| Option | Default | Description |
| --- | --- | --- |
| `STEALTH_BUILD_EXAMPLES` | `ON` | Build examples. |
| `STEALTH_BUILD_TESTS` | `ON` | Build and register tests. |
| `STEALTH_BUILD_BENCHMARK` | `ON` | Build benchmark. |
| `STEALTH_BUILD_FIXTURES` | `ON` | Generate PE fixtures; requires Python 3. |
| `STEALTH_SANITIZERS` | `OFF` | Enable ASan + UBSan on Linux. |
| `STEALTH_CLANG_TIDY` | `OFF` | Run clang-tidy when configured. |
| `STEALTHLIB_SSE2_DECRYPT` | `OFF` | Enable SSE2 decrypt path for long literals on x86/x64; CI runs an explicit parity configuration. |
| `STEALTH_BUILD_KEY` | generated | Per-build obfuscation key. |

---

## 🧵 Threading contract

Each encrypted literal object is **thread-confined**.

| Pattern | Status |
| --- | --- |
| One `S()` object per thread | ✅ Supported |
| Shared object with external lock | ✅ Supported if all access is synchronized |
| Concurrent access to the same object without sync | ❌ Data race |
| Temporary `.unlock()` | ❌ Compile-time error |

See [`docs/THREADING.md`](docs/THREADING.md).

---

## 🛡️ Security boundary

| Topic | Honest boundary |
| --- | --- |
| Literal transform | Obfuscation, not encryption. |
| Plaintext lifetime | Plaintext exists while decrypted/unlocked. |
| Debug/VM signals | Best-effort user-mode hints; spoofable by privileged tooling. |
| IAT checks | Named imports with valid metadata only. |
| PE parsing | Loaded or sufficiently mapped PE images; malformed data returns failure where detectable. |
| Hash resolver | Does not load missing DLLs. |

Read the full docs:

- 📘 [`docs/INSTALL.md`](docs/INSTALL.md)
- 🔐 [`docs/SECURITY.md`](docs/SECURITY.md)
- 🧵 [`docs/THREADING.md`](docs/THREADING.md)
- 🧭 [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
- 📊 [`docs/AUDIT_REPORT.html`](docs/AUDIT_REPORT.html)

---

## 📁 Layout

```text
stealthlib/
  stealth.hpp
  detail/
  detection/
  encoding/
  integrity/
  memory/
  pe/
  vmdetect/

tests/
  fixtures/
  package_consumer/
  subproject_consumer/
  fuzz_*.cpp
  test_*.cpp

docs/
examples/
benchmark/
.github/workflows/
```

---

## 📌 Release

| Version | Release |
| --- | --- |
| `2.2.3` | https://github.com/rolanfreeman6-png/stealthlib/releases/tag/v2.2.3 |

Release asset `stealthlib-v2.2.3.zip` is a clean library package: `stealthlib/`, `cmake/`, `CMakeLists.txt`, `README.md`, and `LICENSE` only.

GitHub's automatically generated `Source code` archives remain full repository snapshots by design; use the custom `stealthlib-v*.zip` asset for a minimal library-only package.

---

## 📜 License

MIT — see [`LICENSE`](LICENSE).

---

<div align="center">

**StealthLib v2.2.3**<br>
Built for practical hardening, explicit contracts, and reproducible tests.

[Report bug](https://github.com/rolanfreeman6-png/stealthlib/issues) · [Releases](https://github.com/rolanfreeman6-png/stealthlib/releases) · [Security](docs/SECURITY.md)

</div>
