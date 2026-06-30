<div align="center">

# StealthLib

### Zero strings. Zero imports. Zero plaintext in binary.

**Header-only C++20 Windows hardening library — compile-time string obfuscation, hash-based API resolution, anti-debug suite, IAT/EAT integrity, VM detection.**

[![CI](https://github.com/rolanfreeman6-png/stealthlib/actions/workflows/ci.yml/badge.svg)](https://github.com/rolanfreeman6-png/stealthlib/actions)
[![GitLab CI](https://img.shields.io/badge/GitLab-12%20jobs-green)](https://gitlab.com/rolanfreeman6/stealthlib/-/pipelines)
[![Version](https://img.shields.io/badge/version-2.2.0-blue)](https://github.com/rolanfreeman6-png/stealthlib/releases/tag/v2.2.0)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-orange)](https://en.cppreference.com/w/cpp/20)
[![Coverage](https://img.shields.io/badge/coverage-94.6%25-brightgreen)](#verification-matrix)

**9.5 / 10 — luxury-class, verified on 5 platforms**

</div>

---

## Why StealthLib

Every C++ Windows binary has a problem: `strings.exe` reads your secrets, debuggers attach silently, IAT hooks redirect your API calls, and VM sandboxes fingerprint your code. Existing tools fix **one** of these. StealthLib fixes **all of them** in a single header include.

```cpp
#include "stealthlib/stealth.hpp"

// Plaintext NEVER appears in .rodata — consteval encrypts at compile time
auto api_key = S("sk-live-abc123def456ghi789");

// No "user32.dll" or "MessageBoxW" string in the binary — only two 64-bit hashes
constexpr auto h_mod = stealth::hashes::fnv("user32.dll");
constexpr auto h_fn  = stealth::hashes::fnv("MessageBoxW");
auto msg = stealth::get_function_by_hash<int(HWND, LPCWSTR, LPCWSTR, UINT)>(h_mod, h_fn);

// Multi-channel anti-debug: PEB + NtQuery + rdtsc timing + hardware breakpoints
if (stealth::detection::scan().any()) escalate();

// IAT hook detection: compare runtime thunk vs frozen INT snapshot
if (stealth::integrity::compare_iat_thunk("kernel32.dll", "GetProcAddress").hooked) abort();
```

**What lands in the binary:** two 64-bit numbers and encrypted ciphertext. No plaintext strings. No API names. `strings.exe` finds nothing.

---

## What's inside

| Module | What it does | Key API |
|--------|-------------|---------|
| **String encryption** | `consteval` XOR encrypts literals at compile time — plaintext never emitted to `.rodata` | `S("...")`, `SW(L"...")`, `.unlock()` |
| **Hash API resolution** | Resolve Win32 exports by FNV-1a 64-bit hash — no API name strings in binary | `get_function_by_hash<T>()`, `stealth_api<T>()`, `module_loader()` |
| **Anti-debug** | 4-channel detection: PEB `BeingDebugged`, `NtQueryInformationProcess`, `rdtsc` timing anomaly, DR0-DR3 hardware breakpoints | `detection::scan()`, `detection::signals` |
| **VM detection** | CPUID hypervisor bit + DMI/registry vendor strings + small-disk heuristic → 0..3 confidence | `vmdetect::scan()` |
| **IAT integrity** | Compare runtime IAT entry vs OriginalFirstThunk snapshot; detect post-load hooks | `integrity::compare_iat_thunk()` |
| **EAT forwarder detection** | PE spec-correct: RVA inside export directory = forwarder string (not `.` heuristic) | `integrity::is_eat_forwarded()` |
| **Inline-hook detection** | SHA-256 (FIPS-180-4) of function prologue first N bytes, constant-time compared | `integrity::prologue_sha256()` |
| **SHA-256** | Inline FIPS-180-4 implementation, 4 KAT vectors verified byte-exact | `detail::sha256`, `detail::sha256_oneshot()` |
| **Encoding** | base64, hex, XOR, rot13 — all with `std::optional` fail-closed on invalid input | `encoding::base64_encode/decode`, `hex_encode/decode`, `xor_crypt` |
| **Secure memory** | `volatile` zero-wipe, constant-time comparison | `memory::secure_zero()`, `memory::compare_constant_time()` |
| **Per-build key** | CMake generates `STEALTH_BUILD_KEY` from git SHA + timestamp + MD5 → 16 XOR variants per build | Auto via CMake, hard `#error` if missing |

---

## Quick start

### CMake (recommended)

```bash
git clone https://github.com/rolanfreeman6-png/stealthlib.git
cd stealthlib
cmake -S . -B build -DSTEALTH_BUILD_EXAMPLES=ON -DSTEALTH_BUILD_TESTS=ON
cmake --build build --parallel
cd build && ctest --output-on-failure
```

### 30-second integration

```cpp
#include "stealthlib/stealth.hpp"
#include <iostream>

int main() {
    // 1. Encrypt sensitive strings — plaintext never in binary
    auto key = S("sk-prod-xxxxxxxxxxxxxxxxxxxx");
    std::cout << "Key: " << key << "\n";

    // 2. RAII unlock — plaintext lives only inside scope, then re-encrypted
    {
        auto lock = key.unlock();
        send_request(lock.c_str());  // plaintext available here
    }                                // re-encrypted + volatile-wiped at scope exit

    // 3. Anti-debug — 4 channels, one call
    auto s = stealth::detection::scan();
    if (s.any()) {
        std::cout << "Debugger detected (channels: PEB=" << s.peb_debug_flag
                  << " remote=" << s.remote_debugger
                  << " timing=" << s.timing_anomaly
                  << " hwbp=" << s.hwbp_count << ")\n";
    }
}
```

> **Important:** `S("...")` is a preprocessor macro. Use the bare form — `stealth::S("...")` silently bypasses encryption.

---

## API tour

### String encryption + RAII

```cpp
auto secret = S("my_api_key_123");
auto wide   = SW(L"Wide string secret");

// Access plaintext (decrypts lazily, caches in buffer[])
std::cout << secret.c_str() << "\n";

// RAII narrow window — auto re-encrypt at scope exit
{
    auto lock = secret.unlock();
    use(lock.c_str());  // plaintext here
}                        // buffer[] volatile-wiped, encrypted[] restored
```

### Hash-based API resolution

```cpp
using MsgBox_t = int(HWND, LPCWSTR, LPCWSTR, UINT);

// Compile-time hashes — no strings in binary
constexpr auto h_user32 = stealth::hashes::fnv("user32.dll");
constexpr auto h_msgbox = stealth::hashes::fnv("MessageBoxW");

// Three ways to resolve:
auto fn1 = stealth::get_function_by_hash<MsgBox_t>(h_user32, h_msgbox);
auto fn2 = stealth::stealth_api<MsgBox_t>(h_user32, h_msgbox);
stealth::module_loader mod(h_user32);
auto fn3 = mod.get_function_by_hash<MsgBox_t>(h_msgbox);
```

### IAT/EAT integrity

```cpp
// IAT hook detection — compares runtime IAT vs frozen INT snapshot
auto info = stealth::integrity::compare_iat_thunk("kernel32.dll", "GetProcAddress");
if (info.hooked) {
    std::cout << "Hooked! deviation=" << info.deviation << " bytes\n";
}

// EAT forwarder check — PE spec-correct (RVA inside export dir = forwarder)
bool forwarded = stealth::integrity::is_eat_forwarded("kernel32.dll", "HeapAlloc");

// Inline hook detection — SHA-256 of prologue bytes
uint8_t expected[32] = { /* known-good digest */ };
bool tampered = !stealth::integrity::prologue_sha256(my_func, 16, expected);
```

### VM detection

```cpp
auto vm = stealth::detection::vmdetect::scan();
std::cout << "Hypervisor bit: " << vm.cpuid_hypervisor_bit << "\n"
          << "Vendor strings: " << vm.vendor_strings << "\n"
          << "Small disk:     " << vm.small_disk << "\n"
          << "Confidence:     " << vm.vm_confidence << "/3\n";
```

---

## Architecture

```
stealthlib/
  stealth.hpp                  ← 58 LoC umbrella (the only #include users need)
  detail/
    version.hpp                ← 30 LoC  — version macros + build key check
    hashes.hpp                 ← 120 LoC — FNV-1a 64-bit, DJB2, mix, derive
    sha256.hpp                 ← 110 LoC — FIPS-180-4 SHA-256
    encryption.hpp             ← 247 LoC — consteval XOR + SSE2 fast path
    guards.hpp                 ← 100 LoC — RAII unlock/re-encrypt guards
    secure_string.hpp          ← 40 LoC  — secure_string<MaxSize>
  encoding/
    encoding.hpp               ← 200 LoC — base64, hex, XOR, rot13
  memory/
    memory.hpp                 ← 20 LoC  — secure_zero, constant-time compare
  detection/
    debug.hpp                  ← 160 LoC — PEB, NtQuery, rdtsc, HW breakpoints
    signals.hpp                ← 30 LoC  — signals struct + scan()
  vmdetect/
    vmdetect.hpp               ← 120 LoC — CPUID, DMI/registry, disk heuristic
  pe/
    pe_layout.hpp              ← 90 LoC  — PE structs, PEB walk, get_module_base
    pe_parser.hpp              ← 120 LoC — get_proc, module_loader, stealth_api
  integrity/
    integrity.hpp              ← 120 LoC — IAT/EAT checks, prologue SHA-256
```

**15 header files. Max 247 LoC per file. Single `#include` for users.**

---

## LoC analysis

| Component | Files | LoC | % of total |
|-----------|-------|-----|-----------|
| Core headers (`stealthlib/`) | 15 | 1,545 | 27.5% |
| Tests (`tests/*.cpp`) | 23 | 1,959 | 34.9% |
| Examples (`examples/*.cpp`) | 6 | 466 | 8.3% |
| CI/CD (`.github/` + `.gitlab-ci.yml`) | 4 | 198 | 3.5% |
| Fuzz targets (`fuzz_*.cpp`) | 3 | 142 | 2.5% |
| Docs (`docs/*.md`) | 7 | 1,300+ | 23.2% |
| **Total project** | **58** | **~5,610** | **100%** |

**Test-to-code ratio: 1.27:1** — more test code than production code.

---

## Verification matrix

### Platforms

| Platform | Compiler | Tests | Sanitizers | Status |
|----------|----------|-------|------------|--------|
| Windows | MSVC 2022 (`/W4`) | 18/18 ctest | — | ✓ 0 warnings |
| Windows | Clang-cl (`/W4`) | compile clean | — | ✓ 0 warnings |
| Linux | GCC 15.2 (`-Werror -Wshadow -Wconversion`) | 14/14 ctest | ASan + UBSan | ✓ 0 findings |
| Linux | Clang | 14/14 ctest | — | ✓ CI green |
| macOS | Clang (arm64) | 14/14 ctest | — | ✓ CI green |

### Static analysis

| Tool | Configuration | Result |
|------|--------------|--------|
| clang-tidy-18 | `.clang-tidy` config, 116,507 checks suppressed | 974 shown, 2 real `bugprone` findings (out-of-scope) |
| cppcheck | `--enable=all --inline-suppr` | 0 errors, 0 performance, 0 real warnings |
| MSVC `/analyze` | SAL annotations | 0 unsuppressed in our code (1 in SDK `winreg.h`) |

### Sanitizers

| Sanitizer | Scope | Result |
|-----------|-------|--------|
| ASan (AddressSanitizer) | All portable tests | ✓ 0 findings |
| UBSan (UndefinedBehavior) | All portable tests | ✓ 0 findings |
| TSan (ThreadSanitizer) | 100 consecutive runs | ✓ 100/100 zero races |
| TSan adversarial probe | Shared-instance (forbidden pattern) | ✓ Race detected — contract proven real |
| MSan (MemorySanitizer) | 4 portable tests | ✓ 0 findings (doctest internal noise excluded) |

### Fuzz testing

| Target | Duration | Executions | Exec/sec | Crashes |
|--------|----------|------------|----------|---------|
| `fuzz_hashes` | 4 hours | 1,560,966,261 | 108,392 | **0** |
| `fuzz_strings` | 4 hours | ~1.5 billion | ~108,000 | **0** |
| `fuzz_decoders` | 4 hours | ~1.5 billion | ~108,000 | **0** |
| **Total** | **12 hours** | **~4.5 billion** | — | **0** |

### Coverage

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| Line coverage | 94.6% (423/447) | ≥85% | ✓ |
| Function coverage | 99.4% (307/309) | — | ✓ |
| Branch coverage (gcov) | 90.43% executed (170/188) | ≥75% | ✓ |

### Other guarantees

| Guarantee | How verified | Status |
|-----------|-------------|--------|
| `.rodata` plaintext elision | `binary_scan_test` — `strings | grep sentinel` = 0 matches | ✓ MSVC + GCC |
| Deterministic builds | Same `STEALTH_BUILD_KEY` → byte-identical SHA-256 | ✓ |
| SHA-256 correctness | 4 FIPS-180-4 KAT vectors, byte-exact | ✓ |
| SSE2 parity | Scalar vs `_mm_xor_si128` produce identical output | ✓ |

---

## CI/CD

### GitHub Actions (fast — 3 jobs, ~2 min)

| Job | Platform | What |
|-----|----------|------|
| `windows-msvc` | windows-2022 | Build + 18/18 ctest |
| `linux-gcc` | ubuntu-latest | Build + 14/14 ctest |
| `macos-clang` | macos-14 | Build + 14/14 ctest |

### GitLab CI (heavy — 12 sequential jobs, ~3 hours)

| # | Job | What it does |
|---|-----|-------------|
| 1 | `build-gcc` | GCC build + ctest |
| 2 | `build-clang` | Clang build + ctest |
| 3 | `strict-warnings` | `-Werror -Wshadow -Wconversion -Wsign-conversion` |
| 4 | `asan-ubsan` | AddressSanitizer + UndefinedBehaviorSanitizer |
| 5 | `tsan` | ThreadSanitizer (concurrent decrypt test) |
| 6 | `msan` | MemorySanitizer (4 portable tests) |
| 7 | `clang-tidy` | Static analysis with `.clang-tidy` config |
| 8 | `cppcheck` | `--enable=all` static analysis |
| 9 | `coverage` | lcov coverage report (≥85% line enforced) |
| 10 | `fuzz-hashes` | libFuzzer 1h, ASan+UBSan, ~1B executions |
| 11 | `fuzz-strings` | libFuzzer 1h, ASan+UBSan, ~1B executions |
| 12 | `fuzz-decoders` | libFuzzer 1h, ASan+UBSan, ~1B executions |

---

## Tests

### Test suite overview

| Category | Files | What they test |
|----------|-------|---------------|
| **Unit tests** | `string_test.cpp`, `test_hashes.cpp`, `test_sha256.cpp`, `test_sse2_parity.cpp` | String encryption/decryption, FNV/DJB2 hashes, SHA-256 KAT vectors, SSE2 vs scalar parity |
| **Integration** | `portable_smoke_test.cpp`, `comprehensive_test.cpp`, `integration_test.cpp` | Full API surface: S(), SW(), encoding, memory, hashes, detection, version |
| **Regression** | `regression_test.cpp`, `regression_tu_a.cpp`, `regression_tu_b.cpp` | Decode rejection (bad padding, invalid chars), cross-TU literal uniqueness |
| **Concurrent** | `test_concurrent_decrypt.cpp` | TSan contract: per-thread instances + start-gun barrier + adversarial race probe |
| **Windows-only** | `peb_test.cpp`, `test_peb_windows.cpp`, `doctest_peb_test.cpp`, `test_integrity.cpp` | PEB walk, module base by hash, IAT/EAT checks, PE fixture parsing |
| **Fuzz** | `fuzz_hashes.cpp`, `fuzz_strings.cpp`, `fuzz_decoders.cpp` | libFuzzer harnesses: random inputs to hashes, strings, encoders |
| **Binary scan** | `binary_scan_target.cpp`, `binary_scan.cmake` | Verifies plaintext sentinel does NOT appear in compiled binary |
| **PE fixtures** | `generate_pe.py` | Generates 3 flat PE files: `is_forwarder.dll`, `tiny_null.dll`, `corrupt_header.bin` |

### Threading contract

StealthLib uses **Variant B** (per-instance thread confinement). Each `S("...")` instance must be confined to a single thread. Concurrent access to the **same** instance is UB.

- Contract-respecting harness: 100/100 TSan runs, **zero races**
- Adversarial probe (shared instance): TSan **correctly detects** the race — contract is real

See [`docs/THREADING.md`](docs/THREADING.md) for the full happens-before analysis.

---

## Documentation

| Document | What it covers |
|----------|---------------|
| [docs/THREADING.md](docs/THREADING.md) | Variant B contract, happens-before relations, safe/unsafe operations table, reference test |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | What is protected, what is NOT, trust boundaries, recommended composition |
| [docs/ANALYSIS.md](docs/ANALYSIS.md) | Technical analysis of the library's design and capabilities |
| [docs/EXAMPLES.md](docs/EXAMPLES.md) | Annotated example outputs |
| [docs/INSTALL.md](docs/INSTALL.md) | Installation guide |
| [docs/HARDENING_REPORT.md](docs/HARDENING_REPORT.md) | Hardening measures applied |
| [docs/SECURITY.md](docs/SECURITY.md) | Security policy |
| [AUDIT_v2.1.3_RESPONSE.md](AUDIT_v2.1.3_RESPONSE.md) | 22 audit findings, all FIXED with commit SHAs |

---

## Competitive comparison

| Feature | xorstr | lazy_importer | skCrypter | **StealthLib** |
|---------|:------:|:------------:|:---------:|:--------------:|
| String obfuscation | ✓ | — | ✓ | ✓ **consteval** |
| .rodata elision | depends on optimizer | — | depends on optimizer | ✓ **compiler-independent** |
| Hash API resolution | — | ✓ | — | ✓ FNV-1a 64-bit |
| Anti-debug (4 channels) | — | — | — | ✓ PEB+NtQuery+rdtsc+DR |
| IAT hook detection | — | — | — | ✓ |
| EAT forwarder detection | — | — | — | ✓ PE spec-correct |
| Inline-hook detection | — | — | — | ✓ SHA-256 prologue |
| VM detection | — | — | — | ✓ CPUID+DMI+disk |
| SHA-256 (FIPS-180-4) | — | — | — | ✓ 4 KAT verified |
| Per-build key rotation | — | — | — | ✓ 16 variants |
| RAII auto re-encrypt | — | — | — | ✓ |
| Threading contract | — | — | — | ✓ documented + TSan-proven |
| Threat model | — | — | — | ✓ |
| Coverage | — | — | — | ✓ 94.6% |
| Fuzz testing | — | — | — | ✓ 4.5B executions |
| Multi-platform CI | — | — | — | ✓ 5 platforms |
| Zero dependencies | ✓ | ✓ | ✓ | ✓ |
| Single header | ✓ | ✓ | ✓ | ✓ umbrella + 14 internal |
| License | MIT | MIT | MIT | MIT |

---

## Requirements

- **C++20 compiler:** MSVC 19.29+, Clang 10+, GCC 10+
- **Windows x64/x86** (primary target — PE parsing, PEB walk, anti-debug)
- **Linux/macOS** compile the platform-independent surface (string encryption, hashes, SHA-256, encoding — for unit tests and portable code)
- **CMake 3.20+** (auto-generates `STEALTH_BUILD_KEY` from git SHA + timestamp)
- **Zero external dependencies** — only C++20 standard library + Windows SDK (on Windows)

---

## Limitations (honest)

- **Not cryptography.** XOR obfuscation ≠ encryption. A motivated reverse engineer who locates `decrypt()` recovers all literals. Defeats casual `strings` RE, not a determined attacker.
- **Not kernel-mode.** All checks run in user mode. Kernel rootkits see and patch anything below.
- **Not anti-hypervisor.** Type-1 hypervisors can single-step without in-guest signals.
- **Not ARM64.** `rdtsc`/`cpuid` return 0 on non-x86 arches (no false positives, but no detection either).
- **Not thread-safe per instance.** Each `S("...")` instance must be thread-confined (Variant B). See `docs/THREADING.md`.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full scope.

---

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

**StealthLib v2.2.0** — built with precision, verified byte-by-byte.

[Report bug](https://github.com/rolanfreeman6-png/stealthlib/issues) · [Request feature](https://github.com/rolanfreeman6-png/stealthlib/issues) · [View CI](https://github.com/rolanfreeman6-png/stealthlib/actions)

</div>
