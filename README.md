# StealthLib

**Zero strings. Zero imports. Complete binary protection.**

A header-only C++20 library for compile-time string encryption and dynamic API resolution.

---

## Features

- **Compile-time string encryption** — Strings encrypted at compile-time, decrypted only at runtime
- **PEB walking** — Resolve API functions dynamically without IAT entries
- **Encoding utilities** — Base64, Hex, XOR, ROT13
- **Debugger detection** — Detect local and remote debuggers
- **Secure memory** — Secure zero, constant-time comparison
- **Header-only** — Copy-paste integration, no dependencies
- **MSVC compatible** — Works with Visual Studio 2019/2022

---

## Quick Start

```cpp
#include "stealthlib/stealth.hpp"

int main() {
    // Encrypted at compile-time
    auto api_key = stealth::S("sk-12345abcde");
    
    // Resolved dynamically, no IAT entry
    using MessageBoxW_t = int(HWND, LPCWSTR, LPCWSTR, UINT);
    auto msg = stealth::get_function<MessageBoxW_t*>("user32.dll", "MessageBoxW");
    
    if (msg) {
        msg(nullptr, L"Protected!", L"StealthLib", MB_OK);
    }
    
    // Check for debugger
    if (stealth::detection::is_debugger_present()) {
        // Handle debugger detected
    }
    
    return 0;
}
```

---

## String Encryption

Encrypt sensitive strings at compile-time:

```cpp
// Char strings
auto db_password = stealth::S("P@ssw0rd!123");
auto api_key = stealth::S("sk-live-abc123def456");

// Wide strings
auto title = stealth::SW(L"Protected Application");
auto msg = stealth::SW(L"Sensitive data here");

// Access decrypted string
std::cout << db_password.c_str() << "\n";
std::cout << db_password.size() << "\n"; // length
```

---

## Dynamic API Resolution

Resolve Windows APIs without IAT entries:

```cpp
// Function pointer type
using MessageBoxW_t = int(HWND, LPCWSTR, LPCWSTR, UINT);

// Get function pointer
auto MessageBoxW = stealth::get_function<MessageBoxW_t*>("user32.dll", "MessageBoxW");

// Call it
if (MessageBoxW) {
    MessageBoxW(nullptr, L"Hello", L"Title", MB_OK);
}

// With stealth_api template
auto msg = stealth::stealth_api<int(HWND, LPCWSTR, LPCWSTR, UINT)>("user32.dll", "MessageBoxW");
if (msg) {
    msg->operator()(nullptr, L"Hello", L"Title", MB_OK);
}
```

### Module Loader

```cpp
stealth::module_loader kernel32("kernel32.dll");
if (kernel32) {
    auto GetTickCount = kernel32.get_function<DWORD(*)()>("GetTickCount");
    auto VirtualAlloc = kernel32.get_function<LPVOID(HMODULE, SIZE_T, DWORD, DWORD)>("VirtualAlloc");
}
```

---

## Encoding

### Base64

```cpp
auto encoded = stealth::encoding::base64_encode("sensitive_data");
auto decoded = stealth::encoding::base64_decode(encoded);
if (decoded) {
    std::cout << *decoded << "\n";
}
```

### Hex

```cpp
auto hex = stealth::encoding::hex_encode("data", 4);
auto raw = stealth::encoding::hex_decode(hex);
```

### XOR

```cpp
stealth::encoding::xor_key<16> key{"MySecretKey123456"};
std::vector<uint8_t> data = /* your data */;

stealth::encoding::xor_encode(data.data(), data.size(), key);
stealth::encoding::xor_decode(data.data(), data.size(), key); // same operation
```

### ROT13

```cpp
stealth::encoding::rot13_encode(dst, src, len);
stealth::encoding::rot13_decode(dst, src, len); // same as encode
```

---

## Debugger Detection

```cpp
// PEB BeingDebugged check
if (stealth::detection::is_debugger_present()) {
    std::cout << "Debugger detected!\n";
}

// Remote debugger (NtQueryInformationProcess)
if (stealth::detection::check_remote_debugger()) {
    std::cout << "Remote debugger detected!\n";
}
```

---

## Secure Memory

```cpp
char sensitive[] = "secret_data";
stealth::memory::secure_zero(sensitive, sizeof(sensitive));

// Constant-time comparison (prevents timing attacks)
if (stealth::memory::compare_constant_time(a, b, len)) {
    // Arrays are equal
}
```

---

## Build

### CMake

```bash
git clone https://github.com/rolanfreeman6/stealthlib.git
cd stealthlib
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

### Visual Studio

Open in Visual Studio or use:
```bash
.\compile.bat
```

---

## Before vs After

| Analysis | Without StealthLib | With StealthLib |
|----------|-------------------|-----------------|
| `strings.exe` | 47 sensitive strings | 0 visible |
| IAT entries | 12 imports | 0 |
| Dependencies | user32.dll, kernel32.dll | (empty or minimal) |

---

## Requirements

- C++20 compiler (MSVC 19.29+, GCC 10+, Clang 10+)
- Windows x64/x86 (primary target)

---

## License

MIT License

---

*Made with stealth by [rolanfreeman6-png](https://github.com/rolanfreeman6)*