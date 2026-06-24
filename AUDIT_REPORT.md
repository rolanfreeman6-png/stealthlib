# StealthLib Audit Report v1.0.1
**Date:** 2026-06-24  
**Status:** 95/95 tests PASSED  

---

## File Locations

| Path | Description |
|---|---|
| `stealthlib/stealth.hpp` | Main header — all features, fully tested (FIXED) |
| `src/stealth.hpp` | Standalone copy for quick compilation |
| `src/compile.bat` | One-click build script for MSVC |
| `tests/comprehensive_test.cpp` | 95-test suite covering all features |
| `tests/string_test.cpp` | 10 string-specific tests (fixed warnings) |
| `tests/peb_test.cpp` | PEB walking tests (fixed warnings) |
| `tests/integration_test.cpp` | Integration tests |

> **Note:** The old secondary headers (`stealth_strings.hpp`, `stealth_peb.hpp`, `stealth_encode.hpp`, `stealth_iat.hpp`) were removed from the public surface during the 1.0.0 hardening pass. Only `stealthlib/stealth.hpp` is the supported public header. See `docs/HARDENING_REPORT.md` and `docs/SECURITY.md` for details.

---

## Bugs Found and Fixed

### 1. PEB Struct Layout (CRITICAL)
**File:** `stealthlib/stealth.hpp`  
**Problem:** `LDR_ENTRY_TEMP2` was missing `InMemoryOrderLinks` and `InInitializationOrderLinks` fields. On x64, this shifted `DllBase` from offset 48 to offset 16, causing all PEB walking to read wrong memory.  
**Fix:** Added all three `LIST_ENTRY` fields + `EntryPoint` + `FullDllName` to match the real `LDR_DATA_TABLE_ENTRY64` layout. Same fix applied to `LDR_ENTRY_TEMP` in `check_remote_debugger()`.

### 2. secure_string Used std::memset Instead of secure_zero (HIGH)
**File:** `stealthlib/stealth.hpp`  
**Problem:** Destructor and `clear()` used `std::memset` which can be optimized away by the compiler, leaving sensitive data in memory.  
**Fix:** Replaced with `memory::secure_zero()` (volatile pointer pattern). Moved `namespace memory` before `secure_string` class definition.

### 3. Wide String XOR Used Only 4 Unique Key Bytes (MEDIUM)
**File:** `stealthlib/stealth.hpp`  
**Problem:** `encrypted_wstring_impl` used `i % 4` for key derivation, producing only 4 unique XOR bytes for wide strings. This made long wide strings trivially breakable.  
**Fix:** Changed to `i % 8` and combined two `derive_byte` calls into a 16-bit XOR mask for each wide character.

### 4. xor_key::operator[] Zero-Length Edge Case (MEDIUM)
**File:** `stealthlib/stealth.hpp`  
**Problem:** When `length == 0`, `operator[]` computed `idx % 1 = 0`, silently XOR-ing with `data[0]`.  
**Fix:** Added explicit `if (length == 0) return 0;` check.

### 5. module_loader::get_function Null Dereference (MEDIUM)
**File:** `stealthlib/stealth.hpp`  
**Problem:** `get_function()` didn't check `handle_` before calling `get_proc()`, causing undefined behavior when the module wasn't found.  
**Fix:** Added `if (!handle_) return nullptr;` guard.

### 6. DOS_HEADER Missing Fields (MEDIUM)
**File:** `stealthlib/stealth.hpp`  
**Problem:** `DOS_HEADER` had only `e_magic` and `e_lfanew`, with `e_lfanew` at struct offset 4 instead of the real offset 60. PE parsing read wrong offset for NT headers.  
**Fix:** Replaced with full 64-byte DOS header struct matching the real `IMAGE_DOS_HEADER` layout.

### 7. check_remote_debugger Hardcoded Byte Comparison (LOW)
**File:** `stealthlib/stealth.hpp`  
**Problem:** Compared "NtQueryInformationProcess" character-by-character with 25 individual `name[N] == 'X'` checks. Fragile and unmaintainable.  
**Fix:** Replaced with `std::strcmp()`.

---

## Test Coverage (95 tests)

| Section | Tests | Range |
|---|---|---|
| String Encryption (S macro) | 12 | 1-12 |
| Wide String Encryption (SW macro) | 8 | 13-20 |
| Secure String | 7 | 21-27 |
| Base64 Encoding | 10 | 28-37 |
| Hex Encoding | 8 | 38-45 |
| XOR Encoding | 8 | 46-53 |
| ROT13 Encoding | 5 | 54-58 |
| Secure Memory | 5 | 59-63 |
| Debugger Detection | 2 | 64-65 |
| PEB Walking | 8 | 66-73 |
| Export & API Resolution | 8 | 74-81 |
| module_loader | 5 | 82-86 |
| stealth_api | 6 | 87-92 |
| Version & Integration | 3 | 93-95 |

### Edge Cases Covered
- Empty strings (S(""), base64(""), hex(""))
- Single character strings
- Overflow/truncation (secure_string<8> with 16-char input)
- Invalid input (base64 odd length, hex odd length, invalid chars)
- Null handles (get_proc(nullptr,...), module_loader with bad name)
- Zero-length operations (secure_zero with 0, compare_constant_time with 0)
- Case-insensitive module name matching
- Non-existent modules/functions
- Key wrapping for XOR with short key + long data
- Double XOR encode = identity
- Unicode (Cyrillic, CJK) wide strings
- Secure zero after scope exit (destructor verification)

---

## Build & Run

```bash
git clone https://github.com/rolanfreeman6-png/stealthlib.git
cd stealthlib
mkdir build && cd build
cmake .. -DSTEALTH_BUILD_EXAMPLES=ON -DSTEALTH_BUILD_TESTS=ON
cmake --build . --config Release

# Run tests:
./tests/Release/comprehensive_test.exe
./tests/Release/string_test.exe
./tests/Release/peb_test.exe
./tests/Release/integration_test.exe
```

---

## Known Limitations
1. `get_user32_api()` / `stealth_api` with user32.dll requires user32 to be loaded in the process (not loaded by default in console apps)
2. `check_remote_debugger()` uses raw offset-based PE parsing for ntdll exports — not portable across Windows versions
3. Wide string encryption uses 16-bit XOR mask — sufficient for obfuscation but not cryptographic security
4. `secure_string` default constructor uses `std::memset` (only destructor/clear use `secure_zero`)
