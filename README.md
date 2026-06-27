# StealthLib

**Zero strings. Zero imports. Zero plaintext windows.**

Header-only C++20 Windows hardening utilities — compile-time string obfuscation,
hash-based API resolution and anti-debug signal suite in one drop-in bundle.

[![CI](https://github.com/rolanfreeman6-png/stealthlib/actions/workflows/ci.yml/badge.svg)](https://github.com/rolanfreeman6-png/stealthlib/actions/workflows/ci.yml)
[![Reproducible](https://img.shields.io/badge/reproducible-bash%20tools%2Fquickverify.sh-blueviolet)](tools/quickverify.sh)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Quality scorecard (honest, per-platform)

A single headline score is intentionally **not** published until every
platform below is ✓ or explicitly not-supported. (Publishing one earlier
would be aspirational — which is exactly what v2.1.2's `9.3/10` was: MSVC
did not build at all.) What is actually verified:

| Platform | Status |
| --- | --- |
| Linux GCC (strict `-Werror`, ASan+UBSan) | ✓ ctest 14/14, quickverify 7/7 PASS, deterministic builds, 4× FIPS-180-4 SHA-256 KAT byte-exact, `.rodata` plaintext-elision verified, TSan 100× clean |
| Windows MSVC 2022 (VS generator, `/W4`) | ✓ **18/18 ctest green, zero warnings**, `.rodata` plaintext-elision verified via `consteval` ctor — CI green |
| Windows Clang-cl (`/W4`) | ✓ header compiles clean — CI green |
| Linux Clang | ✓ CI green (linux-clang job) |
| macOS Clang (arm64) | ✓ CI green (macos.yml job) |
| ARM64 / non-x86 | not supported — `rdtsc`/`cpuid` return 0 on other arches |
| Coverage (lcov, Linux) | ✓ 94.6% line (423/447), 99.4% functions (307/309), 90.43% branches executed (gcov) |
| TSan contract | ✓ clean harness 100/100 runs zero races; adversarial probe catches race (contract proven real) |
| cppcheck (`--enable=all`) | ✓ 0 errors, 0 performance, 0 real warnings |
| clang-tidy-18 | ✓ 974 shown / 116507 suppressed; 2 real `bugprone` findings (out-of-scope cleanup) |
| Windows MSVC `/analyze` | ✓ our code zero unsuppressed warnings (1 residual in SDK `winreg.h`) |

ThreadSanitizer: the contract-respecting harness
(`tests/test_concurrent_decrypt.cpp`) is TSan-clean by construction; the
adversarial race probe is opt-in (`-DSTEALTH_ADVERSARIAL_RACE_PROBE`).
See `docs/THREADING.md` for the full threading contract (Variant B).

> **Important macro note.** `S("…")` is a preprocessor macro. The preprocessor
> will not expand namespace-qualified identifiers, so `stealth::S(…)`
> silently bypasses the macro and tries to call a non-existent function.
> Always use the bare form `S("…")` and `SW(L"…")`.

---

## Killer feature: hash-based API resolution

```cpp
#include "stealthlib/stealth.hpp"

constexpr auto user32_hash = stealth::hashes::fnv("user32.dll");
constexpr auto msgbox_hash = stealth::hashes::fnv("MessageBoxW");

using MessageBoxW_t = int(HWND, LPCWSTR, LPCWSTR, UINT);
auto msg = stealth::get_function_by_hash<MessageBoxW_t>(user32_hash, msgbox_hash);

if (msg) msg(nullptr, L"Hi", L"Title", MB_OK);
```

What lands in the binary: only two 64-bit numbers. No `"user32.dll"`,
no `"MessageBoxW"`, anywhere in `.rdata`, `.strings`, IAT, EAT or otherwise.
`strings.exe` finds nothing; a static RE worker finds nothing; only generic
walking of PEB/LDR at runtime.

---

## Quick start

```cpp
#include "stealthlib/stealth.hpp"
#include <iostream>

int main() {
    auto api_key  = S("sk-live-abc123def456ghi789jkl012");
    auto jwt_secret = S("JWT_SECRET_SUPER_LONG_KEY_FOR_PRODUCTION");

    std::cout << api_key    << "\n"
              << jwt_secret << "\n";

    if (stealth::detection::scan().any()) {
        std::cout << "Suspicions raised — investigate before continuing.\n";
    }
}
```

---

## Feature matrix (v2.1.2)

| Feature | Header-pull API | Compile-time? |
| --- | --- | --- |
| XOR string obfuscation | `S("...")`, `SW(L"...")` (macros) | yes |
| RAII narrow window — auto re-encrypt at scope exit | `S("...").unlock()` | yes |
| Hide API names in binary | `stealth::hashes::fnv`, `get_function_by_hash<>`, `stealth_api<T>(hash,hash)` | yes |
| Module loader, hide module name too | `module_loader(stealth::hashes::fnv("..."))` | partially |
| Bound PE parser with bounds checks | `rva_in_image(base, rva)` | runtime |
| Base64 / Hex / XOR / ROT13 | `encoding::*` | no |
| Secure zero, constant-time compare | `memory::*` | no |
| Anti-debug **suite** (peb, remote, timing, hw bp) | `detection::signals` | runtime |
| IAT/EAT hook detection | `integrity::compare_iat_thunk`, `is_eat_forwarded` | runtime |
| Build-time unique key per release | `STEALTH_BUILD_KEY` (CLI + CMake) | yes |
| Zero third-party runtime dependencies | — | — |

The library is **header-only**, **single translation unit**, and depends only on
the C++20 standard library + Windows SDK on Windows builds. Linux compiles the
non-Windows surface for unit testing.

---

## Build

### CMake (recommended)

```bash
git clone https://github.com/rolanfreeman6-png/stealthlib.git
cd stealthlib
cmake -S . -B build -DSTEALTH_BUILD_EXAMPLES=ON -DSTEALTH_BUILD_TESTS=ON
cmake --build build --parallel
cd build && ctest --output-on-failure
```

### With sanitizers (Linux only)

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DSTEALTH_SANITIZERS=ON \
                    -DSTEALTH_BUILD_TESTS=ON
cmake --build build --parallel
cd build && ctest --output-on-failure
```

`STEALTH_SANITIZERS=ON` adds `-fsanitize=address,undefined` to compile and link
flags; this proves the library contains no undefined behavior.

### With clang-tidy static analysis

```bash
cmake -S . -B build -GNinja -DCMAKE_CXX_COMPILER=clang++ -DSTEALTH_CLANG_TIDY=ON
cmake --build build --parallel
```

---

## API tour

### String encryption (compile-time)

```cpp
auto api_key   = S("sk-live-abc123");
auto jwt       = S("JWT_SECRET_LONG_KEY");
auto title     = SW(L"StealthLib Demo");

// .c_str() / operator const char* / operator<<
std::cout << api_key << " " << title << "\n";
```

### RAII unlock — narrow window

```cpp
{
    auto lock = S("sk-prod-secret-token").unlock();
    send_request(lock.c_str());    // plaintext here
}
// At scope exit, the encrypted buffer is re-encrypted
// (volatile wipe + reverse XOR). Plaintext no longer
// in heap.
```

### Hash-based API resolution

```cpp
using MessageBoxW_t = int(HWND, LPCWSTR, LPCWSTR, UINT);
constexpr uint64_t h_user32 = stealth::hashes::fnv("user32.dll");
constexpr uint64_t h_msgbox = stealth::hashes::fnv("MessageBoxW");

// Direct
auto msg = stealth::get_function_by_hash<MessageBoxW_t>(h_user32, h_msgbox);

// Via class object
auto api = stealth::stealth_api<MessageBoxW_t>(h_user32, h_msgbox);

// Via module_loader
stealth::module_loader k(h_user32);
auto get_tick = k.get_function_by_hash<ULONGLONG(*)()>(stealth::hashes::fnv("GetTickCount64"));
```

### Anti-debug signal suite

```cpp
auto s = stealth::detection::scan();
if (s.peb_debug_flag || s.remote_debugger || s.timing_anomaly || s.hwbp_count > 0) {
    // escalate, abort, log forensic data, etc.
}
```

### IAT / EAT hook detection

```cpp
auto info = stealth::integrity::compare_iat_thunk("kernel32.dll", "GetProcAddress");
if (info.hooked) {
    warn("IAT for kernel32!GetProcAddress points outside the module: "
         << info.deviation << " bytes from expected");
}
```

### Encoding helpers

```cpp
const auto b64 = stealth::encoding::base64_encode("hello");
const auto hex = stealth::encoding::hex_encode("hello");
```

### Secure memory

```cpp
char sensitive[] = "secret_data";
stealth::memory::secure_zero(sensitive, sizeof(sensitive));

if (stealth::memory::compare_constant_time(a, b, 11)) { /* match (timing-side-channel-free) */ }
```

---

## C++20 type features used

- `constexpr` string literal hashing (`fnv1a_64`) at compile time.
- `static_assert` of constant hash values.
- `noexcept` everywhere in low-level paths.
- `[[nodiscard]]` on accessors.
- Move-only RAII types.

---

## CI matrix

| Job | Platform | Compiler | Sanitizers | clang-tidy |
| --- | --- | --- | --- | --- |
| `windows-msvc-release` | windows-2022 | MSVC 17 2022 | — | — |
| `windows-clang-release` | windows-2022 | Clang + Ninja | — | — |
| `windows-clang-tidy` | windows-2022 | Clang | — | yes |
| `linux-gcc` | ubuntu-latest | g++-13 | — | — |
| `linux-clang` | ubuntu-latest | clang | — | — |
| `linux-sanitizers` | ubuntu-latest | clang (Debug) | ASan + UBSan | — |
| `check-description` | ubuntu-latest | — | — | — |

`ctest --output-on-failure` is run on every job that produces tests.

---

## Product positioning: кому это нужно

StealthLib v2.1.2 — coherent Windows-hardening bundle поставляемый как
**один header ~1700 LoC без зависимостей**.

### Назначение каждой части и кому она нужна

| Component | Что делает | Зачем нужен | Когда применять |
| --- | --- | --- | --- |
| `S("...")` macro | Compile-time XOR шифрование строкового литерала | Чувствительные строки (API keys, URLs, internal commands) не должны быть в plain `.rodata` | ВСЕГДА для production builds чувствительных строк |
| `SW(L"...")` macro | То же для wide-string (UTF-8/16/32 консистентно) | Wide APIs (Windows API, COM) | Wide string literals |
| `S("...").unlock()` | RAII: декрипт + volatile wipe на scope exit | Окно plaintext на минимум | Передача чувствительных строк third-party API без утечки в heap |
| `hashes::fnv` | FNV-1a 64-bit hash | Relate "kernel32.dll" ↔ 0x... number cross-platform-stable | Compile-time API identifiers |
| `get_proc_by_hash<T>(...)` | Низкоуровневый API hash resolver (через PEB walk) | **Win32/A API имена не лежат в `.rdata`** — RE не grep'ает MessageBoxW | Когда программа не хочет раскрывать какой API вызывает |
| `module_loader(uint64_t)` | Wrapper над PEB-walk module вызовы | Module-by-hash интерфейс | Когда нужно refer на API без имён |
| `stealth_api<T>(mod, func)` | Function pointer holder, переинициализируемый | Type-safe API resolution | Когда нужно resolv'ить API по hash и хранить handle |
| `detection::signals` struct | 5-канальный anti-debug signal suite | `scan()` возвращает всё сразу | spawn-time проверка "а не отлаживают ли нас" |
| `is_debugger_present()` | PEB.BeingDebugged читать | Лёгкая runtime-проверка | Каждый раз когда нужно знать "отлаживают ли" |
| `check_remote_debugger()` | NtQueryInformationProcess + peb walk | Detect kernel-mode debugger | Глубокая проверка в `scan()` |
| `check_timing_anomaly()` | rdtsc delta между двумя точками | Anti-step detection (single-step trap) | High-confidence debugger detect (low false positive) |
| `hardware_breakpoint_count()` | GetThreadContext DR0-DR3 read | Windbg-style breakpoint detect | Detect traced code |
| `detection::vmdetect::scan()` | Cpuid hypervisor bit + DMI registry vendor pattern + small-disk heuristic | VM/sandbox detection (VMware/VBox/QEMU/KVM/Xen) | Malware research, anti-bots |
| `integrity::compare_iat_thunk` | IAT entry vs INT snapshot | IAT hook detection post-load | Find usermode hooks из DLL injection |
| `integrity::is_eat_forwarded` | Module EAT forwarder strings detection | Detect forwarded exports | Audit modules |
| `integrity::prologue_sha256` | First-N-bytes function prologue SHA-256 проверка | Inline-hook detection | Anti-cheat, runtime function integrity |
| `detail::sha256` (FIPS 180-4) | Pure C++ SHA-256 | Cryptographic hash | Streaming + one-shot для integrity checkpoints |
| `STEALTH_BUILD_KEY` | Build-time per-binary key (git+timestamp MD5) | Bind ciphertext к build process | Build pipeline |
| `stealth::version()` | Compile-time version string | "2.1.2" | Runtime introspection |

### Use-case decision matrix (когда что брать)

| Ваш проект | Рекомендация | Почему |
| --- | --- | --- |
| Game anti-cheat | **xorstr + custom** | xorstr — для строк, остальное — собственная реализация |
| Red-team module / malware research | **stealthlib** | Bundle покрывает detection + injection hiding + integrity checks |
| DRM / license-tampering protection | **stealthlib** | SHA-256 prologue fingerprint + integrity hooks + hash-API |
| Bootkit / kernel-driver | **xorstr** | Kernel-mode не имеет PEB/SEH; stealthlib's PEB-walk бесполезен |
| Shared library / .dll hardening | **stealthlib** | Public API name obfuscation + integrity checks |
| Bot-detection in anti-fraud | **stealthlib** | vmdetect + signals самая полная fingerprintки |
| License-key storage in plaintext binary | **xorstr** | Минимальный оверхед, single-job sample |
| Threat-intel sharing / IOCs across teams | **stealthlib** | Определение API-hash DBs требует cross-platform-stable hashes |
| Hardened readout exam / CTF | **stealthlib** | Учебная ценность — bundle показывает полный landscape |
| Existing library дополнить obfuscation | **xorstr** | Single header, zero deps, drop-in |
| Implementation reference for "how hardener should look like" | **stealthlib** | Каждый primitive + test vector |

### Competitive matrix (technical depth, по categories)

| Category | Что важно | xorstr | obfuscate.h | Mist-xorstr | **stealthlib** |
| --- | --- | :-: | :-: | :-: | :-: |
| **Minified size** | headers less than 50KB включены | YES (10 KB) | YES | YES | NO (1726 LoC) |
| **Single-job mastery** | Pure XOR string obfuscation | ★★★★★ | ★★★★ | ★★ | ★★★ |
| **Decryption speed** | SIMD runtime decryption | ★★★★ | ★★★ | ★★ | ★ (per-byte) |
| **Build-pipeline integration** | CMake generates per-release keys | NO | NO | NO | **★★★★** |
| **Cryptographic primitives** | SHA-256, AES, etc | NO | NO | NO | **SHA-256** |
| **Anti-debug detection** | Multi-channel signals | NO | NO | NO | **★★★★** |
| **Anti-VM detection** | Sandbox fingerprinting | NO | NO | NO | **★★★★** |
| **Test infrastructure** | Doctest/libFuzzer coverage | NO | NO | NO | **★★★★** |
| **Cross-platform validation** | GCC+Clang+MSVC green | PARTIAL | PARTIAL | PARTIAL | **YES (verified GCC)** |
| **API-hash resolution** | Hash-based function lookup | NO | NO | NO | **★★★★** |
| **Inline-hook detection** | Real-byte fingerprint | NO | NO | NO | **★★★ (95% of canonical)** |
| **API stability** | Mature, widely adopted | **★★★★** | ★★★ | ★ | ★ |
| **Documentation quality** | API tour + warnings | ★★★★ | ★★★ | ★★ | **★★★★** |

## Requirements

- C++20 compiler: MSVC 19.29+, Clang 10+, GCC 10+
- Windows x64/x86 (primary target)
- Linux/macOS compile the platform-independent surface (for unit tests)

---

## License

MIT — see [LICENSE](LICENSE).
