# StealthLib — Project Plan

**Created:** 2026-06-24  
**Updated:** 2026-06-24  
**Status:** ALL COMPLETE  
**Version:** 1.0.0  
**Repository:** https://github.com/rolanfreeman6-png/stealthlib  
**Release:** https://github.com/rolanfreeman6-png/stealthlib/releases/tag/v1.0.0

---

## Implementation Status

### ✅ Phase 1: Core Implementation (COMPLETE)
- [x] `stealth.hpp` — Main header with all features:
  - Compile-time XOR string encryption (MSVC/GCC/Clang compatible)
  - PEB walking for dynamic API resolution
  - Base64/Hex/XOR/ROT13 encoding
  - Debugger detection (PEB + NtQueryInformationProcess)
  - Secure memory operations (secure_zero, constant-time compare)
  - `stealth_api<T>` template for dynamic function handle
  - `module_loader` class for DLL loading
  - `get_function<T>()`, `get_module_base()`, `get_proc()` functions

### ✅ Phase 2: Examples (COMPLETE)
- [x] `minimal_test.cpp` — Basic functionality test
- [x] `full_demo.cpp` — Complete feature demonstration
- [x] `game_protection.cpp` — Game dev use case
- [x] `server_protection.cpp` — Server software use case

### ✅ Phase 3: Tests (COMPLETE)
- [x] `string_test.cpp` — String encryption tests
- [x] `peb_test.cpp` — PEB walking tests
- [x] `integration_test.cpp` — Full integration tests

### ✅ Phase 4: CI/CD & Documentation (COMPLETE)
- [x] `.github/workflows/ci.yml` — GitHub Actions CI
- [x] `docs/INSTALL.md` — Installation guide
- [x] `docs/EXAMPLES.md` — Examples documentation
- [x] `benchmark/benchmark.cpp` — Performance benchmarks
- [x] `LICENSE` — MIT License
- [x] `.gitignore` — Git ignore rules

### ✅ Phase 5: GitHub Repository (COMPLETE)
- [x] Create GitHub repo
- [x] Push code
- [x] Create release

---

## API Reference

### String Encryption
```cpp
auto api_key = stealth::S("sk-12345abcde");
auto db_pass = stealth::SW(L"Password123!");
std::cout << api_key << "\n";
std::cout << std::strlen(api_key) << "\n";
```

### Dynamic API Resolution
```cpp
using MessageBoxW_t = int(HWND, LPCWSTR, LPCWSTR, UINT);
auto msg = stealth::get_function<MessageBoxW_t*>("user32.dll", "MessageBoxW");
if (msg) msg(nullptr, L"Hello", L"Title", MB_OK);

auto msg2 = stealth::stealth_api<int(HWND, LPCWSTR, LPCWSTR, UINT)>("user32.dll", "MessageBoxW");
if (msg2) msg2.get()(nullptr, L"Hello", L"Title", MB_OK);
```

### Module Loader
```cpp
stealth::module_loader kernel32("kernel32.dll");
if (kernel32) {
    auto GetTickCount = kernel32.get_function<DWORD(*)()>("GetTickCount");
}
```

### Encoding
```cpp
auto b64 = stealth::encoding::base64_encode("data");
auto decoded = stealth::encoding::base64_decode(b64);
auto hex = stealth::encoding::hex_encode("data");
stealth::encoding::xor_key<16> key{"secret"};
stealth::encoding::xor_encode(data, len, key);
```

### Debugger Detection
```cpp
if (stealth::detection::is_debugger_present()) { /* detected! */ }
if (stealth::detection::check_remote_debugger()) { /* remote debugger! */ }
```

### Secure Memory
```cpp
stealth::memory::secure_zero(ptr, size);
if (stealth::memory::compare_constant_time(a, b, len)) { /* match */ }
```

---

## File Structure
```
stealthlib/
├── .github/workflows/ci.yml
├── benchmark/benchmark.cpp
├── docs/
│   ├── EXAMPLES.md
│   └── INSTALL.md
├── examples/
│   ├── CMakeLists.txt
│   ├── full_demo.cpp
│   ├── game_protection.cpp
│   ├── minimal_test.cpp
│   └── server_protection.cpp
├── stealthlib/
│   └── stealth.hpp
├── tests/
│   ├── CMakeLists.txt
│   ├── integration_test.cpp
│   ├── peb_test.cpp
│   └── string_test.cpp
├── .gitignore
├── CMakeLists.txt
├── LICENSE
├── PROJECT_PLAN.md
└── README.md
```

---

## Build Instructions

### CMake (Recommended)
```bash
git clone https://github.com/rolanfreeman6/stealthlib.git
cd stealthlib
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DSTEALTH_BUILD_EXAMPLES=ON -DSTEALTH_BUILD_TESTS=ON
cmake --build .
```

### Visual Studio
Open in Visual Studio or use:
```bash
.\build_project.cmd
```

---

## Technical Decisions

### MSVC CTAD Solution
Use static local variables in helper function to handle encryption:
```cpp
template<size_t N, size_t Idx>
inline const char* make_encrypted_string(const char (&src)[N]) noexcept {
    static encrypted_string_t<N, Idx> holder(src);
    return holder.decrypt();
}
```

### Namespace Structure (Flat Design)
All functions directly in `stealth::` namespace:
- `stealth::version()` — version string
- `stealth::S("str")` — char string encryption
- `stealth::SW(L"str")` — wide string encryption
- `stealth::get_function<T>(module, func)` — dynamic API
- `stealth::module_loader` — DLL loader class
- `stealth::stealth_api<T>` — function handle template
- `stealth::detection::*` — debugger detection
- `stealth::encoding::*` — encoding utilities
- `stealth::memory::*` — memory operations

---

*Document updated by Kilo Agent for rolanfreeman6-png*