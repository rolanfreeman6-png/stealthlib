# StealthLib

Header-only C++20 utilities for Windows-focused string obfuscation, PEB-based API resolution, debugger signals, and secure memory helpers.

StealthLib is designed for applications that want fewer plain-text strings and fewer static imports in release binaries. It is obfuscation and hardening, not cryptography and not a promise of complete protection against a determined reverse engineer.

## Why This Project Exists

Most small C++ obfuscation headers focus only on string literals. StealthLib aims to combine the common hardening pieces a Windows application usually needs:

- compile-time `S()` / `SW()` string obfuscation
- PEB module walking and export resolution
- forwarded export handling
- debugger detection signals
- secure zeroing and constant-time byte comparison
- focused regression tests for multi-translation-unit string bugs and PE resolver edge cases

## Current Status

This repository is being prepared for a public release. The core header is usable, but the project should not be advertised as "complete binary protection".

Before publishing widely, keep CI green and make the binary-scan tests part of release validation.

## Quick Start

```cpp
#include "stealthlib/stealth.hpp"
#include <windows.h>

int main() {
    auto api_key = S("sk-12345abcde");
    (void)api_key;

    using MessageBoxW_t = int(HWND, LPCWSTR, LPCWSTR, UINT);
    auto MessageBoxW = stealth::get_function<MessageBoxW_t*>("user32.dll", "MessageBoxW");

    if (MessageBoxW) {
        MessageBoxW(nullptr, L"Protected", L"StealthLib", MB_OK);
    }

    if (stealth::detection::is_debugger_present()) {
        // Treat this as a signal, not proof.
    }
}
```

## String Obfuscation

```cpp
auto password = S("P@ssw0rd!123");
auto title = SW(L"Protected Application");

std::cout << password << "\n";
std::wcout << title << L"\n";
```

The string macros are intentionally global preprocessor macros, not `stealth::S()` functions.

## Dynamic API Resolution

```cpp
using GetTickCount_t = DWORD();

stealth::stealth_api<GetTickCount_t> tick("kernel32.dll", "GetTickCount");
if (tick) {
    DWORD value = tick.get()();
}

stealth::module_loader kernel32("kernel32.dll");
if (kernel32) {
    auto VirtualAlloc = kernel32.get_function<LPVOID(*)(LPVOID, SIZE_T, DWORD, DWORD)>("VirtualAlloc");
}
```

The resolver supports forwarded exports and uses bounded PE structure checks where practical. PEB walking still depends on Windows internal process structures and should be treated as best-effort hardening.

## Encoding Helpers

```cpp
auto encoded = stealth::encoding::base64_encode("sensitive_data");
auto decoded = stealth::encoding::base64_decode<256>(encoded);
if (decoded) {
    std::cout.write(reinterpret_cast<const char*>(decoded.data), decoded.len);
}

auto hex = stealth::encoding::hex_encode("data", 4);
auto raw = stealth::encoding::hex_decode<16>(hex);
```

Base64, Hex, XOR, and ROT13 are encoding/obfuscation utilities. They are not encryption.

## Secure Memory

```cpp
char sensitive[] = "secret_data";
stealth::memory::secure_zero(sensitive, sizeof(sensitive));

if (stealth::memory::compare_constant_time(a, b, len)) {
    // Equal
}
```

On Windows, `secure_zero` uses `SecureZeroMemory`.

## Build And Test

```bash
cmake -S . -B build -DSTEALTH_BUILD_EXAMPLES=ON -DSTEALTH_BUILD_TESTS=ON -DSTEALTH_BUILD_BENCHMARK=ON
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Linux builds are limited to the portable header/encoding/memory smoke tests. Windows is the primary target for PEB walking, API resolution, examples, and benchmarks.

## Release Checklist

- Windows MSVC Release build passes.
- Windows clang/Ninja Release build passes.
- CTest passes on Windows and Linux smoke jobs.
- Multi-translation-unit string regression passes.
- Forwarded export regression passes.
- Debug and Release binaries are scanned for sentinel string literals.
- README claims match what CI actually verifies.

## Security and Hardening Notes

StealthLib is obfuscation and hardening, not cryptography or a promise of complete protection. See the full details in:

- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model, supported public surface, and responsible disclosure.
- [`docs/HARDENING_REPORT.md`](docs/HARDENING_REPORT.md) — what was fixed, how it was verified, competitive assessment, and remaining tasks.

## Requirements

- C++20 compiler
- Windows x64/x86 for PEB walking and dynamic API resolution
- MSVC 19.29+, recent clang-cl/Clang, or recent GCC for portable tests

## License

MIT License
