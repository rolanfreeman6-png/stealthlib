# StealthLib Hardening Report

**Date:** 2026-06-24  
**Version:** 1.0.0 (pre-release)  
**Repository:** https://github.com/rolanfreeman6-png/stealthlib  
**Scope:** `stealthlib/stealth.hpp`, CMake/CI, tests, documentation, public API surface.

---

## Executive Summary

This report documents the hardening pass that moved StealthLib from a **strong proof-of-concept with critical design flaws** to a **pre-release, CI-verified Windows hardening utility**.

The two most serious issues were:

1. **`S()` / `SW()` leaked plaintext** and shared a single `__COUNTER__` keyspace, causing cross-translation-unit collisions and making the obfuscated strings visible in the binary.
2. **PEB structures, the DOS header, and several helpers contained layout errors and undefined behavior**, which broke dynamic API resolution on x64 and crashed on malformed inputs.

Both were fixed. The new implementation uses per-use unique keys derived from `__LINE__` and `__COUNTER__`, stores only the encrypted form in the binary, and decrypts lazily on first use. PE parsing now uses the correct struct layouts and validates every RVA before dereferencing. CI now runs the full test matrix on Windows and a portable Linux smoke test.

This document is intended for code review, release planning, and future maintenance. For end users, see `README.md` and `docs/SECURITY.md`.

---

## What Was Fixed

### 1. String Obfuscation (`S()` / `SW()`) — CRITICAL

**Problem.** The legacy macros returned a `stealth_encrypted_char` / `stealth_encrypted_wchar` object whose internal buffer was populated at compile time with the **plaintext** string. The XOR operation was only for show; the original bytes were plainly visible in the binary. In addition, the previous `__COUNTER__`-only scheme produced the same key across translation units, so two different strings in different TUs could decrypt to the same corrupted value.

**File affected.** `stealthlib/stealth.hpp` (legacy macro and helper structs removed).

**Fix.**
- Removed the `stealth_encrypted_char` / `stealth_encrypted_wchar` classes and the plaintext-buffer design.
- Introduced `detail::encrypted_blob<CharT, N>` and `detail::encrypted_string_impl<CharT, N>`.
- Keys are now derived with `make_key(line, counter, size, tag)` combining `__LINE__`, `__COUNTER__`, string length, and a domain tag (`0x5354524152524159` for narrow, `0x5753545241525241` for wide).
- The encrypted array is stored in a `static const` holder; decryption is lazy, thread-safe via an atomic state machine, and writes into a mutable buffer only at runtime.
- Wide-character encryption now applies the full per-character mask instead of reusing only four key bytes.

**Verification.**
- `string_test.cpp` and `comprehensive_test.cpp` cover empty, single-char, long, numeric, special, Cyrillic, and CJK strings.
- `regression_test.cpp` with `regression_tu_a.cpp` / `regression_tu_b.cpp` confirms cross-translation-unit independence.
- `binary_scan_test` confirms that sentinel strings are not present as plaintext in the Release binary in narrow, UTF-16LE, or UTF-32LE forms.

### 2. CMake / CTest Integration — HIGH

**Problem.** Tests were built but not registered with CTest, so CI only compiled them. The Linux and Windows configurations were not separated, and Windows clang was not exercised in both Release and Debug.

**Fix.**
- Added `enable_testing()` in the root `CMakeLists.txt`.
- `tests/CMakeLists.txt` now calls `add_test(NAME ... COMMAND ...)` for every test.
- Windows-only tests (`integration_test`, `comprehensive_test`, `peb_test`, `regression_test`) are gated behind `if(WIN32)`.
- Portable tests (`string_test`, `portable_smoke_test`, `binary_scan_test`) run on all platforms.
- Removed `/DNDEBUG` / `-DNDEBUG` from `CMAKE_CXX_FLAGS_RELEASE`, `CMAKE_CXX_FLAGS_RELWITHDEBINFO`, and `CMAKE_CXX_FLAGS_MINSIZEREL` so `assert` remains active in all test configurations. Without this, RelWithDebInfo silently disabled assertions and tests crashed on null pointers.
- Linux builds skip examples and benchmarks because they use Windows APIs.

**Verification.**
- `ctest --test-dir build-ninja --output-on-failure` → 7/7 passed.
- `ctest --test-dir build-debug-ninja --output-on-failure` → 7/7 passed.
- `ctest --test-dir build-check -C Release --output-on-failure` → 7/7 passed (Visual Studio).

### 3. Binary Scan Test — HIGH

**Problem.** There was no automated check that the obfuscation actually removed plaintext literals from the binary.

**Fix.**
- Added `tests/binary_scan_target.cpp` containing `S()` and `SW()` calls with long unique sentinel strings.
- Added `tests/binary_scan.cmake` to read the resulting binary as hex and search for the sentinel in narrow, UTF-16LE, and UTF-32LE encodings.
- Registered the scan as a CTest test that runs after the target is built.

**Verification.** The test passes in Release and Debug on Windows and confirms that no sentinel appears in plaintext.

### 4. Regression Tests — MEDIUM/HIGH

**Problem.** Several edge cases were untested or relied on unstable behavior (e.g., assuming `user32.dll` is already loaded in a console test).

**Fix.**
- Added `regression_test.cpp` covering:
  - cross-translation-unit string independence (`AAAA` vs `BBBB` in separate TUs)
  - decoder truncation / small output buffer rejection
  - decoder padding validation
  - null-input fail-closed behavior
  - forwarded export resolution (`HeapAlloc` in `kernel32.dll` resolves to real code, not to the export directory)
  - both `stealth_api<ReturnType()>` and `stealth_api<ReturnType(*)()>` callable forms
- Fixed `comprehensive_test` destructor test to avoid UB when manually invoking the destructor.
- Made `peb_test` treat `user32.dll` as optional, so the test does not fail in console-only processes.

**Verification.** All regression tests pass in the CTest matrices listed above.

### 5. PEB / PE Parsing Robustness — HIGH

**Problem.**
- `LDR_ENTRY` structure was missing `InMemoryOrderLinks` and `InInitializationOrderLinks`, shifting `DllBase` to the wrong offset on x64.
- `DOS_HEADER` only contained `e_magic` and `e_lfanew`, placing `e_lfanew` at the wrong offset.
- `get_proc()` did not validate RVAs, did not handle forwarded exports, and could read past the image.
- `module_loader::get_function()` dereferenced a null handle.

**Fix.**
- Added complete `IMAGE_DOS_HEADER`-compatible `DOS_HEADER` layout.
- Added complete `LDR_DATA_TABLE_ENTRY`-compatible `LDR_ENTRY` layout.
- Added `rva_in_image()` bounds checks before every pointer arithmetic step.
- Implemented forwarded export recursion in `get_proc_impl()` with depth limit and explicit module-name reconstruction.
- Added null-handle guard in `module_loader::get_function()`.
- Added `ascii_ieq` / `ascii_iequals` for case-insensitive export name matching.

**Verification.** `peb_test.cpp` and `regression_test.cpp` now pass on Windows x64.

### 6. Secure Memory — MEDIUM

**Problem.** `secure_string` used `std::memset` in the destructor and `clear()`, which the compiler is allowed to optimize away. `secure_string()` default constructor did not initialize the buffer.

**Fix.**
- Moved `namespace memory` before `secure_string` so it can call `memory::secure_zero()`.
- Replaced `std::memset` with `memory::secure_zero()` (volatile write loop on Linux, `SecureZeroMemory` on Windows).
- Zero-initialized `data_` with `char data_[MaxSize]{}`.
- Added `static_assert(MaxSize > 0, ...)`.
- `compare_constant_time` now returns `false` for null pointers when `len > 0` and `true` for `len == 0`.

**Verification.** `comprehensive_test.cpp` includes a manual destructor test that confirms the storage is fully zeroed after destruction.

### 7. Documentation and Marketing Claims — HIGH

**Problem.** `README.md` and `PROJECT_PLAN.md` contained claims such as "Zero strings. Zero imports. Complete binary protection." These claims are not verifiable and misrepresent the project's actual capabilities.

**Fix.**
- Rewrote `README.md` with an honest positioning: "Windows-focused string obfuscation, PEB-based API resolution, debugger signals, and secure memory helpers." It explicitly states the project is obfuscation/hardening, not cryptography or complete protection.
- Rewrote `PROJECT_PLAN.md` as a pre-release plan with release gates, supported public surface, and a list of remaining hardening tasks.
- Removed references to the old secondary headers from `README.md` and `AUDIT_REPORT.md`.
- Added this `HARDENING_REPORT.md` and `docs/SECURITY.md` with a conservative threat model.

---

## Verification Results

### Local Build Matrix (2026-06-24)

| Configuration | Build | CTest | Notes |
|---|---|---|---|
| `build-ninja` (Windows, clang-cl/Ninja, Release) | pass | 7/7 pass | |
| `build-debug-ninja` (Windows, clang-cl/Ninja, Debug) | pass | 7/7 pass | |
| `build-check` (Windows, Visual Studio 2022, Release) | pass | 7/7 pass | MSBuild emits a local `pwsh.exe` warning, but exit code is 0 and CTest is green. The warning is environmental noise, not a source issue. |
| `build-relwithdebinfo` (Windows, Visual Studio 2022, RelWithDebInfo) | pass | 7/7 pass | Added during this hardening pass. Required stripping `NDEBUG` from `CMAKE_CXX_FLAGS_RELWITHDEBINFO` so `assert` stays active. |
| `build-linux` (WSL2, GCC 15, Release) | pass | 3/3 pass | Portable tests only; examples and Windows-only tests skipped. |

The Linux Clang job was not re-run locally because `clang++` is not installed in the current WSL2 environment. The CI definition below installs it on every push.

### GitHub Actions CI Matrix

The updated `.github/workflows/ci.yml` runs:

| Job | Platform | Compiler | Configurations | Notes |
|---|---|---|---|---|
| `repo-metadata` | ubuntu-latest | — | — | Validates that the GitHub repository description does not contain outdated marketing claims. |
| `windows-msvc` | windows-latest | MSVC 2022 | Release | builds examples, tests, benchmark; runs `ctest` |
| `windows-relwithdebinfo-msvc` | windows-latest | MSVC 2022 | RelWithDebInfo | builds tests only; runs `ctest` including the binary scan |
| `windows-clang` | windows-latest | Clang + Ninja | Release, Debug | builds examples, tests, benchmark; runs `ctest` |
| `linux-gcc` | ubuntu-latest | GCC 13 | Release | builds only portable tests |
| `linux-clang` | ubuntu-latest | Clang | Release | builds only portable tests |

The binary scan is now exercised in Release, Debug, and RelWithDebInfo on Windows.

---

## Competitive Assessment

Data gathered from the GitHub API on 2026-06-24:

| Project | Stars | URL |
|---|---|---|
| JustasMasiulis/xorstr | 1,434 | https://github.com/JustasMasiulis/xorstr |
| adamyaxley/Obfuscate | 1,306 | https://github.com/adamyaxley/Obfuscate |
| andrivet/ADVobfuscator | 1,748 | https://github.com/andrivet/ADVobfuscator |
| rolanfreeman6-png/stealthlib | 0 | https://github.com/rolanfreeman6-png/stealthlib |

The obfuscation space is crowded but alive. StealthLib's realistic opportunity is not to compete as "yet another string obfuscator" but to position itself as a **tested Windows hardening bundle** with CI evidence:

- multi-translation-unit string regression
- binary scan for plaintext sentinels
- PEB export resolver with forwarded-export support
- honest threat model and documented limitations
- secure-memory helpers with regression coverage

That positioning is defensible and distinct from the single-feature competitors above.

---

## Remaining Tasks (Release Blockers and Follow-ups)

### Blockers before public release

1. ~~**Update GitHub repository description.**~~ Done. The description now reads: "Header-only C++20 Windows hardening utilities: compile-time string obfuscation, PEB-based API resolution, secure memory helpers." The `repo-metadata` CI job validates it on every push.
2. **Decide the fate of the old secondary headers.** This report recommends removal. They have already been deleted from the working tree: `stealth_strings.hpp`, `stealth_peb.hpp`, `stealth_encode.hpp`, `stealth_iat.hpp`. If they are needed later, they should be rewritten as thin wrappers over `stealth.hpp` rather than restored as-is.
3. **Add `docs/SECURITY.md`.** Done in this pass.
4. **Add `docs/HARDENING_REPORT.md`.** Done in this pass.

### Strongly recommended before wide promotion

5. **Add GitHub Actions badges to README** only after the public CI is green for at least one full run on `main`.
6. **Convert remaining tests from `assert` to a real test framework** or keep `NDEBUG` disabled in all test configurations. The current CMake setup strips `NDEBUG` from Release, RelWithDebInfo, and MinSizeRel flags, so `assert` is active. This is acceptable for a pre-release, but a dedicated test harness is cleaner long-term.
7. **Add deterministic PE fixture tests** for malformed headers and forwarded exports without relying on system DLLs.
8. **Write the release post** with the honest framing: "not magic, but tested Windows hardening utilities."
9. **Install WSL2 Clang locally** if you want to pre-validate the `linux-clang` CI job before pushing. The CI job installs it automatically.

### Nice-to-have

10. **Add a `fuzz` or `audit` build option** that enables additional sanitizers and hardened checks.
11. **Provide a migration note** for anyone who previously included the secondary headers.
12. **Sign release tags** and publish a short `CHANGELOG.md`.

---

## Files Changed During This Hardening Pass

| File | Change |
|---|---|
| `stealthlib/stealth.hpp` | Rewrote string obfuscation; fixed PEB/PE structs; added forwarded exports; hardened secure memory; fixed null checks. |
| `CMakeLists.txt` | Enabled `enable_testing()`, separated Windows/Linux examples and benchmarks. |
| `tests/CMakeLists.txt` | Registered tests with CTest, added `binary_scan_test`, split Windows-only tests. |
| `tests/string_test.cpp` | Updated for new API. |
| `tests/comprehensive_test.cpp` | 95-test suite, fixed UB in destructor test. |
| `tests/peb_test.cpp` | Made `user32.dll` optional; fixed assertions. |
| `tests/integration_test.cpp` | Updated for new API. |
| `tests/regression_test.cpp` | New cross-TU, decoder, forwarded export, null-input tests. |
| `tests/regression_tu_a.cpp` / `regression_tu_b.cpp` | Cross-translation-unit regression fixtures. |
| `tests/binary_scan_target.cpp` / `binary_scan.cmake` | New binary scan test. |
| `tests/portable_smoke_test.cpp` | New Linux-compatible smoke test. |
| `README.md` | Honest pre-release positioning, removed secondary headers. |
| `PROJECT_PLAN.md` | Pre-release plan with release gates and remaining work. |
| `docs/INSTALL.md` / `docs/EXAMPLES.md` | Updated to match the honest API. |
| `docs/SECURITY.md` | New threat model and responsible disclosure. |
| `docs/HARDENING_REPORT.md` | This document. |
| `AUDIT_REPORT.md` | Removed references to deleted secondary headers. |
| `.github/workflows/ci.yml` | Windows/Linux split, RelWithDebInfo binary scan, repo-metadata check, clang Debug/Release, CTest invocation. |
| `.gitignore` | Kept `build*/`, ensured `tests/binary_scan.cmake` and `cmake/*.cmake.in` are not ignored. |
| `scripts/check_github_description.py` | New helper script to verify the GitHub repository description does not contain outdated claims. |
| `stealthlib/stealth_strings.hpp` | Deleted. |
| `stealthlib/stealth_peb.hpp` | Deleted. |
| `stealthlib/stealth_encode.hpp` | Deleted. |
| `stealthlib/stealth_iat.hpp` | Deleted. |

---

## Recommendations

1. **Do not restore the old secondary headers.** They duplicate functionality in `stealth.hpp` and were a source of public-surface confusion.
2. **Do not market the project as "complete binary protection."** Use the phrasing in the rewritten README and `SECURITY.md`.
3. **Run the binary scan in every CI configuration** including Debug, Release, and RelWithDebInfo before any release.
4. **Update the GitHub repository description immediately** before the next push to `main`.
5. **Keep `assert` active in Release test builds** until a dedicated test framework is adopted.
6. **Treat the project as pre-release** until the public GitHub Actions matrix is green and badges are added.

---

## Conclusion

StealthLib has moved from a flawed PoC to a defensible pre-release hardening library. The worst technical issues (plaintext leak, PEB layout errors, undefined behavior, untested cross-TU behavior) are fixed and verified by CI. The main remaining work is repository hygiene, honest marketing, and one more CI hardening pass. The codebase is now ready for a controlled public release once the GitHub description and CI badges are aligned with the actual capabilities documented here.

---

*Report generated as part of the StealthLib 1.0.0 pre-release hardening effort.*
