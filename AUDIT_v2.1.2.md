# AUDIT_v2.1.2 — StealthLib Static Review

**Date:** 2026-06-26
**Head commit:** 8d991b6 (v2.1.2, 1 commit ahead of origin, unpushed)
**Scope:** `stealthlib/stealth.hpp` (A, D), `tests/` (B), `tools/quickverify.sh` (C), docs (E)
**Methodology:** Full end-to-end read of `stealth.hpp` (1855 LoC); every claim below was re-verified against the actual file at the cited line numbers. Windows-only paths reviewed even though Linux CI does not compile them. Empirical reproducers given where possible; static reasoning where the toolchain is not available locally.

> **Headline:** seven critical compile-time bugs in the Windows path; the v2.1.2 binary on MSVC will not build *at all* — every translation unit that pulls in the header fails before the first `S("...")` even gets to template instantiation. Five of the seven were not in the previous audit pass. Read C-1..C-7 first.

---

## ⚠ CRITICAL FINDINGS (7)

All seven prevent the Windows MSVC build from compiling. C-4, C-5, C-6, C-7 were missed by the prior pass; C-1, C-2, C-3 are re-verified.

---

### C-1 — `check_remote_debugger()`: redeclared `pe_off` and `export_rva` — compile error on MSVC/Windows GCC

**File:** `stealthlib/stealth.hpp:1052-1069`
**Severity:** critical — Windows MSVC/clang build cannot link; detection subsystem is dead on Windows.

The author added a correct fix for the wrong export-directory offset (PE32+ uses `nt + 0x88`, not `nt + 0x78 + 0x80 = 0xF8`). The explanatory comment was written, the corrected block added — but the old block was never removed. Both now exist in the same function scope:

```cpp
// OLD block (lines 1052-1055) — never removed
auto dosb = reinterpret_cast<uint8_t*>(ntdll);
auto pe_off = *reinterpret_cast<uint32_t*>(dosb + 0x3C);          // ← first decl
auto nt = reinterpret_cast<uint8_t*>(ntdll) + pe_off;
auto export_rva = *reinterpret_cast<uint32_t*>(nt + 0x78 + 0x80); // ← first decl

if (!export_rva) return false;
// [comment explaining why above is wrong]

// NEW (correct) block (lines 1064-1069)
auto dos = reinterpret_cast<uint8_t*>(ntdll);
auto pe_off = *reinterpret_cast<uint32_t*>(dos + 0x3C);           // ← REDECL — error
auto nt8 = reinterpret_cast<uint8_t*>(ntdll) + pe_off;
uint16_t magic = *reinterpret_cast<uint16_t*>(nt8 + 0x18);
std::size_t dd_offset = (magic == 0x20b) ? 0x88 : 0x78;
uint32_t export_rva = *reinterpret_cast<uint32_t*>(nt8 + dd_offset); // ← REDECL — error
```

**Reproducer:**
```
cl /std:c++20 /DSTEALTH_BUILD_KEY=0x1234567890ABCDEFULL /I. examples/game_protection.cpp
# error C2086: 'auto pe_off': redeclaration
# error C2086: 'uint32_t export_rva': redeclaration
```

On Linux, the entire `#ifdef _WIN32` block is excluded, so GCC never sees this.

**Fix:** Delete lines 1052-1057 (the old block + its `if (!export_rva) return false;`). The new block at 1064-1071 already has the same guard.

---

### C-2 — `is_eat_forwarded`: stray `return false;` and braces at namespace scope — compile error

**File:** `stealthlib/stealth.hpp:1772-1776`
**Severity:** critical — second Windows-only compile error; renders the entire `#ifdef _WIN32` block unparseable.

After `is_eat_forwarded` closes at line 1771, five lines of orphaned code remain at namespace scope:

```cpp
1771: }              // ← closes is_eat_forwarded correctly
1772:             return false;   // ← ERROR: return at namespace scope
1773:         }
1774:     }
1775:     return false;   // ← ERROR: return at namespace scope
1776: }              // ← closes namespace integrity prematurely
```

`return` at namespace scope is ill-formed in C++. The extra `}` at line 1776 also closes `namespace integrity` early, so `prologue_sha256` on line 1792 ends up declared in the wrong scope (the parent `namespace stealth { #ifdef _WIN32 ... }`). See C-4 for the second-order consequence.

**Reproducer:** Same MSVC compile as C-1; fails before reaching C-1's lines.

**Fix:** Delete lines 1772-1776 entirely — uncleared remnant of an earlier edit.

---

### C-3 — `DOS_HEADER_NT` and `NT_HEADERS64_NT`: wrong struct layouts — all PE parsing reads garbage on Windows

**File:** `stealthlib/stealth.hpp:1428-1429`
**Severity:** critical — every Windows PE helper (`get_nt`, `get_export`, `get_proc`, `get_proc_by_hash`, `get_module_base`, `stealth_api`, `module_loader`) silently returns wrong data or crashes; would still fail regression_test even after C-1/C-2.

**`DOS_HEADER_NT` (line 1428):**
```cpp
struct DOS_HEADER_NT { uint16_t e_magic; int32_t e_lfanew; };
```
With default alignment, `e_lfanew` lives at struct offset 4. In a real MZ header, `e_lfanew` is at byte offset `0x3C` (60). `get_nt()` calls `dos->e_lfanew` and reads whatever 4-byte value lives at offset 4-7 of the image (part of the COFF stub) — garbage.

**`NT_HEADERS64_NT` (line 1429):**
```cpp
struct NT_HEADERS64_NT {
    uint32_t Signature;
    uint8_t Padding[4];   // ← no such field in IMAGE_NT_HEADERS64
    uint16_t Machine;
    ...
    uint64_t ImageBase;
    ...
    uint32_t DataDirectory[32];
};
```
`IMAGE_NT_HEADERS64` has no padding between `Signature` and `IMAGE_FILE_HEADER`. The spurious `Padding[4]` shifts every subsequent field by 4 bytes. Compiler-inserted alignment padding for `uint64_t ImageBase` (offset 52 → 56) adds another 4 bytes. Net result: `DataDirectory[0]` in this struct sits at offset 0x90, whereas the real `IMAGE_NT_HEADERS64::OptionalHeader.DataDirectory[0]` is at offset 0x88 — 8 bytes off. `get_export()` returns a pointer derived from `DataDirectory[2]`-shaped bytes.

**Reproducer (pseudo, after fixing C-1/C-2):**
```cpp
void* k32 = nullptr;
stealth::get_module_base(L"kernel32.dll", &k32);
assert(stealth::get_proc(k32, "HeapAlloc") != nullptr); // FAILS
```

**Fix:**
```cpp
struct DOS_HEADER_NT {
    uint16_t e_magic;
    uint8_t  pad[0x3A];   // 58 bytes of MZ stub to reach e_lfanew at 0x3C
    int32_t  e_lfanew;
};

struct NT_HEADERS64_NT {
    uint32_t Signature;
    // NO Padding here — IMAGE_FILE_HEADER follows directly
    uint16_t Machine;
    ...
};
```

---

### C-4 — `integrity::prologue_sha256` defined twice on Windows — ODR / redefinition error  🆕

**File:** `stealthlib/stealth.hpp:1792, 1831`
**Severity:** critical — on Windows, both definitions are visible in the same TU and same namespace; immediate redefinition error.

The header defines `prologue_sha256` inside the Windows-only block:
```cpp
1792:    inline bool prologue_sha256(void const* func_ptr, std::size_t n,
1793:                                uint8_t const expected[32]) noexcept { ... }
1803: } // namespace integrity
1805: #endif // _WIN32
```
Then immediately re-opens `namespace integrity` outside the guard and defines the **same function with identical signature** with no `#if !defined(_WIN32)` guard:
```cpp
1807: namespace integrity {
...
1831:    inline bool prologue_sha256(void const* func_ptr, std::size_t n,
1832:                                uint8_t const expected[32]) noexcept { ... }
1841: } // namespace integrity (cross-platform helpers)
```

On Windows, both definitions land in `stealth::integrity` in the same TU. `inline` permits multiple definitions across TUs, **not within the same TU**. MSVC and GCC both reject:
```
error: redefinition of 'bool stealth::integrity::prologue_sha256(...)'
```

(C-2's premature `}` at line 1776 also leaves the *first* `prologue_sha256` definition in the wrong namespace — fixing C-2 alone exposes C-4 as the primary blocker.)

**Reproducer:** Any MSVC build of stealth.hpp on Windows after fixing C-1, C-2 → C-4 surfaces.

**Fix:** Guard the second definition so it only compiles when `_WIN32` is NOT defined:
```cpp
#ifndef _WIN32
namespace integrity {
    // ... existing cross-platform helpers ...
    inline bool prologue_sha256(...) noexcept { ... }
}
#endif
```
Or hoist the single definition above the `#ifdef _WIN32` block and remove both duplicates.

---

### C-5 — `__atomic_load_n` / `__atomic_store_n` block all MSVC compiles of `S()` / `SW()`  🆕

**File:** `stealthlib/stealth.hpp:239,291,307,318,368,389,427,441,457,472`
**Severity:** critical — `encrypted_string_impl::decrypt()`, `reencrypt()`, and the wide counterparts use GCC/Clang `__atomic_*` builtins unconditionally with no MSVC fallback. **Every** `S("...")` and `SW(L"...")` expansion instantiates one of these → MSVC fails before linking. This blocks the entire core API on Windows MSVC.

The comment at lines 201-209 acknowledges the choice (`std::atomic<bool>` would make the class non-literal and kill `constexpr` ctor), but does **not** provide the MSVC alternative. There is no `#if defined(_MSC_VER)` branch in the file targeting these intrinsics — confirmed by:
```
grep -n "_MSC_VER" stealthlib/stealth.hpp
1186:#if defined(_MSC_VER)        # ← only used for unrelated x86 intrinsic guard
```

**Reproducer:**
```
cl /std:c++20 /DSTEALTH_BUILD_KEY=0x1234567890ABCDEFULL /I. -c examples/game_protection.cpp
# error C3861: '__atomic_load_n': identifier not found
# error C3861: '__atomic_store_n': identifier not found
```

**Fix:** Add an MSVC branch using `<atomic>` free-functions or `<intrin.h>` interlocked intrinsics. The trick to preserve the literal-type property: store the flag as `unsigned char` and use `_InterlockedExchange8` / `_InterlockedCompareExchange8` — they're intrinsic, no header needed, and don't change layout:
```cpp
#if defined(_MSC_VER)
#  define STEALTH_ATOMIC_LOAD_ACQ(x)  (_ReadWriteBarrier(), (x))
#  define STEALTH_ATOMIC_STORE_REL(x, v)  do { (x) = (v); _ReadWriteBarrier(); } while(0)
#else
#  define STEALTH_ATOMIC_LOAD_ACQ(x)  __atomic_load_n(&(x), __ATOMIC_ACQUIRE)
#  define STEALTH_ATOMIC_STORE_REL(x, v)  __atomic_store_n(&(x), (v), __ATOMIC_RELEASE)
#endif
```
On x86/x64 TSO this compiles to a plain `mov` either way — but MSVC needs the barrier intrinsic to expose the right memory-model contract to the optimizer.

---

### C-6 — `rdtsc()` uses GCC inline-asm syntax under `_M_X64`; `_M_IX86` branch returns nothing  🆕

**File:** `stealthlib/stealth.hpp:1105-1115`
**Severity:** critical — MSVC x64 builds (the primary Windows target) fail; MSVC x86 also broken even if compilation passed.

```cpp
inline uint64_t rdtsc() noexcept {
#if defined(_M_X64) || defined(__x86_64__)
    unsigned int lo = 0, hi = 0;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));   // ← GCC-only syntax
    return (static_cast<uint64_t>(hi) << 32) | lo;
#elif defined(_M_IX86)
    __asm rdtsc;          // ← no return statement; falls off non-void function
#else
    return 0;
#endif
}
```

Two bugs:
1. `__asm__ __volatile__` is GCC/Clang inline-assembly syntax. `_M_X64` is defined under MSVC x64, which has **no inline asm at all** (32-bit only). Should use `__rdtsc()` intrinsic from `<intrin.h>`.
2. The `_M_IX86` branch uses MSVC `__asm rdtsc;` but never assigns to anything and falls off the end of a `uint64_t`-returning function → UB on a non-void function with no return. Even MSVC x86 is broken.

**Reproducer:**
```
cl /std:c++20 /DSTEALTH_BUILD_KEY=0x1234567890ABCDEFULL /I. -c [any-file-using-rdtsc].cpp
# error C2400: inline assembler syntax error in 'first operand'; found '__asm__'
```

**Fix:**
```cpp
inline uint64_t rdtsc() noexcept {
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
    return __rdtsc();                          // <intrin.h>; already pulled by <windows.h>
#elif defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
    unsigned int lo = 0, hi = 0;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return (static_cast<uint64_t>(hi) << 32) | lo;
#else
    return 0;
#endif
}
```

---

### C-7 — `unlocked_wstring_guard(L"", 0, nullptr)` — no `nullptr_t` overload; `SW(L"").unlock()` fails to compile  🆕

**File:** `stealthlib/stealth.hpp:531-567, 737`
**Severity:** critical — `SW(L"")` empty-literal specialization's `unlock()` body calls a ctor that doesn't exist. Every TU that even *instantiates* `SW(L"")` is a compile error.

The narrow `unlocked_string_guard` has the nullptr-pool overload (line 497):
```cpp
unlocked_string_guard(const char* ptr, size_t n, std::nullptr_t) noexcept
    : ptr_(ptr), n_(n), pool_ptr_(nullptr), reen_(nullptr) {}
```
The wide `unlocked_wstring_guard` (lines 531-567) defines **only** the default ctor + templated ctor + move ctor. There is no `(const wchar_t*, size_t, std::nullptr_t)` overload.

The empty-literal `unlock()` (line 736-738) calls it:
```cpp
detail::unlocked_wstring_guard unlock() noexcept {
    return detail::unlocked_wstring_guard(L"", 0, nullptr);   // ← no matching ctor
}
```
Template deduction for the templated ctor `template<size_t S, size_t I> unlocked_wstring_guard(const wchar_t*, size_t, encrypted_wstring_impl<S, I>*)` fails because `S` and `I` cannot be deduced from `std::nullptr_t`.

This is silent today only because no test instantiates `SW(L"").unlock()`. The narrow analog `S("").unlock()` would actually compile (the nullptr_t ctor exists), but is also untested (see M-5).

**Reproducer:**
```cpp
#include "stealthlib/stealth.hpp"
int main() { auto g = SW(L"").unlock(); (void)g; return 0; }
// error: no matching function for call to 'unlocked_wstring_guard::unlocked_wstring_guard(const wchar_t*, int, std::nullptr_t)'
```

**Fix:** Add the missing overload, mirroring the narrow version:
```cpp
// After line 545 (after the templated ctor):
unlocked_wstring_guard(const wchar_t* ptr, size_t n, std::nullptr_t) noexcept
    : ptr_(ptr), n_(n), pool_ptr_(nullptr), reen_(nullptr) {}
```

---

## IMPORTANT FINDINGS (5)

---

### I-1 — `is_eat_forwarded`: wrong DataDirectory offset `0x78 + 0x78 = 0xF0`

**File:** `stealthlib/stealth.hpp:1747-1748`
**Severity:** important — silent: `is_eat_forwarded` always reads the wrong offset and returns `false` whether the export is forwarded or not. Forwarded-export detection is effectively dead even after C-1/C-2/C-3 are fixed.

```cpp
auto exp_dir = reinterpret_cast<uint8_t*>(base) + *reinterpret_cast<uint32_t*>(
                   reinterpret_cast<uint8_t*>(stealth::get_nt(base)) + 0x78 + 0x78);
```

`0x78 + 0x78 = 0xF0`. Correct offsets from the NT header for `DataDirectory[0]`:
- PE32+: `+0x88`
- PE32:  `+0x78`

`0xF0` lands in the Debug Directory entry region on PE32+. The same bug class was closed for `check_remote_debugger` in v2.1.1 (ANALYSIS.md §3.1 Bug 20) but was not applied here.

**Fix:**
```cpp
auto nt8 = reinterpret_cast<uint8_t*>(stealth::get_nt(base));
uint16_t magic = *reinterpret_cast<uint16_t*>(nt8 + 0x18);
std::size_t dd_off = (magic == 0x20b) ? 0x88u : 0x78u;
uint32_t exp_rva = *reinterpret_cast<uint32_t*>(nt8 + dd_off);
if (!exp_rva) return false;
auto exp_dir = reinterpret_cast<uint8_t*>(base) + exp_rva;
```

---

### I-2 — `compare_iat_thunk`: no ordinal-import guard; reads only 4 of 8 bytes of PE32+ INT entry

**File:** `stealthlib/stealth.hpp:1705-1707`
**Severity:** important — functions imported by ordinal (common in kernel32/ntdll exports) cause `compare_iat_thunk` to treat the ordinal number as an RVA to a HINT/NAME record, producing garbage names + potential OOB reads.

```cpp
// orig is uintptr_t* — on PE32+, each INT entry is 8 bytes
auto hintNameRva = *reinterpret_cast<uint32_t*>(reinterpret_cast<uintptr_t>(orig));
auto fname = reinterpret_cast<const char*>(mod) + hintNameRva + 2;
```

Two bugs:
1. Reads only 4 bytes (`uint32_t`) of an 8-byte PE32+ thunk entry.
2. Never checks bit 63 (`IMAGE_ORDINAL_FLAG64 = 0x8000000000000000`). When set, the entry is an ordinal import — the lower bits are an ordinal number, not an RVA. Using it as `RVA + 2` is an OOB pointer.

The bizarre `reinterpret_cast<uint32_t*>(reinterpret_cast<uintptr_t>(orig))` style adds no functional difference (still reads at address `orig`) but obscures intent.

**Fix:**
```cpp
uintptr_t thunk_val = *orig;
#if defined(_WIN64)
static constexpr uintptr_t ORDINAL_FLAG = 0x8000000000000000ULL;
#else
static constexpr uintptr_t ORDINAL_FLAG = 0x80000000ULL;
#endif
if (thunk_val & ORDINAL_FLAG) {
    importDesc += 20;
    continue;
}
auto hintNameRva = static_cast<uint32_t>(thunk_val & 0x7FFFFFFF);
auto fname = reinterpret_cast<const char*>(mod) + hintNameRva + 2;
```

---

### I-3 — `regression_test.cpp`: calls non-existent `base64_decode<4>` and `hex_decode<4>` templates

**File:** `tests/regression_test.cpp:22, 27, 29, 30`
**Severity:** important — Windows-only regression test cannot compile; decode-rejection coverage is silently zero on every platform that does try to build it.

```cpp
auto b64_small = stealth::encoding::base64_decode<4>(b64);      // line 22
auto hex_small = stealth::encoding::hex_decode<4>(hex);          // line 27
stealth::encoding::base64_decode<16>("AA=A");                    // line 29
stealth::encoding::base64_decode<16>("AAAA====");                // line 30
```

`stealth::encoding::base64_decode` (line 807, 912) and `hex_decode` (line 812, 967) are plain `inline` functions taking `const std::string_view&`. **Not templates.** MSVC would emit:
```
error C2062: 'stealth::encoding::base64_decode' is not a template
```

Likely a stale API: the templated `<MaxOutSize>` form was probably refactored out. The current API does its own allocation; there is no output-buffer limit to test.

**Fix:** Rewrite to test what the current API rejects (malformed padding, odd-length hex, invalid chars):
```cpp
static void test_decode_rejects_bad_input() {
    assert(!stealth::encoding::base64_decode("AA=A").has_value());      // bad padding
    assert(!stealth::encoding::base64_decode("AAAA====").has_value()); // too many pads
    assert(!stealth::encoding::base64_decode("A").has_value());         // len % 4 != 0
    assert(!stealth::encoding::hex_decode("ABC").has_value());          // odd length
    assert(!stealth::encoding::hex_decode("ZZ").has_value());           // invalid chars
}
```

---

### I-4 — `unlocked_wstring_guard` missing move-assign operator

**File:** `stealthlib/stealth.hpp:531-567`
**Severity:** important — `unlocked_wstring_guard` is not fully move-assignable; `wguard1 = std::move(wguard2)` is a deleted-function compile error.

The narrow `unlocked_string_guard` defines `operator=(unlocked_string_guard&&)` at line 511. The wide version (line 554) defines the move-ctor but omits move-assign. Because copy-assign is `= delete`, the compiler does not synthesize move-assign either.

**Reproducer:**
```cpp
auto w1 = SW(L"hello").unlock();
decltype(w1) w2;
w2 = std::move(w1);  // error: use of deleted function
```

**Fix:** Add after the move-ctor (line 557):
```cpp
unlocked_wstring_guard& operator=(unlocked_wstring_guard&& o) noexcept {
    if (this != &o) {
        if (reen_ && pool_ptr_) reen_(pool_ptr_);
        ptr_ = o.ptr_; n_ = o.n_;
        pool_ptr_ = o.pool_ptr_; reen_ = o.reen_;
        o.ptr_ = nullptr; o.n_ = 0; o.pool_ptr_ = nullptr; o.reen_ = nullptr;
    }
    return *this;
}
```

---

### I-5 — `encrypted_string_impl::decrypt()` / `reencrypt()` data-race on `buffer[]` and `encrypted[]` (not just the flag)  🆕

**File:** `stealthlib/stealth.hpp:235-310 (narrow decrypt), 317-391 (narrow reencrypt), 426-444 (wide decrypt), 446-477 (wide reencrypt)`
**Severity:** important — "TSan-clean" claim in the v2.1.2 changelog overstates coverage; the synchronization is on the wrong object.

The code synchronizes the `decrypted` boolean with `__atomic_*` acquire/release, but does the actual mutation of `buffer[]` / `encrypted[]` with plain non-atomic writes inside the check-then-act region:

```cpp
const char* decrypt() noexcept {
    if (!__atomic_load_n(&decrypted, __ATOMIC_ACQUIRE)) {   // check
        // ... write to buffer[] (plain, non-atomic) ...
        __atomic_store_n(&decrypted, true, __ATOMIC_RELEASE);  // act
    }
    return buffer;
}
```

Three observable races, ordered by likelihood:

1. **decrypt + decrypt (most likely seen by TSan):** Threads A and B both load `decrypted=false`, both pass the if, both write `buffer[i]` concurrently. Same value, but C++ memory model says concurrent unsynchronized writes to a non-atomic object are UB regardless of value equality. The `test_concurrent_decrypt.cpp` Probe 1 (8 threads × 2000 iters) exercises exactly this path.

2. **decrypt + reencrypt (most damaging):** reencrypt thread starts XOR'ing `encrypted[]` back to ciphertext while decrypt thread is reading `encrypted[]` to fill `buffer[]`. Decrypt observes a partially-restored ciphertext mix → returns garbage to caller, then writes garbage to `buffer[]`, then writes `decrypted=true`. Probe 2 of `test_concurrent_decrypt.cpp` triggers this but only by chance (no barrier forcing the interleave).

3. **The `volatile char* = 0` zeroing of `buffer[]` (lines 366, 387, 469):** `volatile` prevents elision; it does **not** add atomicity. A concurrent reader of `c_str()` after `reencrypt()` ran far enough to write `decrypted=false` (release-stored) but still in the middle of zeroing `buffer[]` can see partial zeros mixed with plaintext.

The `test_concurrent_decrypt.cpp` Probe 2 reports "TSan-clean" only because both threads work in their own loops without a barrier — TSan's scheduler very rarely catches the dangerous interleave. The bug is real but the test does not adversarially exercise it.

**Reproducer (adversarial test sketch):**
```cpp
std::atomic<int> ready{0};
auto lit = S("RACE_PROBE_GUARDED_INTERLEAVE_LONG_ENOUGH_FOR_SSE2");
std::thread a([&]{
    while (ready.load() == 0) {}
    for (int i = 0; i < 100000; ++i) { (void)*lit; }
});
std::thread b([&]{
    while (ready.load() == 0) {}
    for (int i = 0; i < 100000; ++i) { auto g = lit.unlock(); (void)g; }
});
ready.store(1);
a.join(); b.join();
// Under TSan: race on encrypted[] and buffer[] is reported.
```

**Fix (proper):** Promote the critical section to a mutex (`std::mutex` or `pthread_spinlock_t` for hot paths), or refactor so each unlock allocates its own scratch buffer and never reuses `buffer[]` across threads. The current "lazy decrypt with shared buffer" pattern is fundamentally racy and cannot be made safe with just an atomic flag.

A minimal fix that preserves `constexpr`-literality (keeps the .rodata-elision property):
- Add `std::mutex` in a non-constexpr per-object wrapper, OR
- Document `S("...")` as **thread-local only** — every TU that uses S in a multi-threaded context must take its own copy via `unlock().c_str()` and not call `*lit` from multiple threads.

---

## MINOR FINDINGS (10)

---

### M-1 — `signals::any()`: `build_key_match == 0` is dead code

**File:** `stealthlib/stealth.hpp:1162, 1173`

```cpp
s.build_key_match = STEALTH_BUILD_KEY;     // compile-time non-zero literal
// ...
return ... || (build_key_match == 0);      // static_assert guarantees false
```

`STEALTH_BUILD_KEY` is a preprocessor `#define`; the `static_assert` at line 42 makes `build_key_match == 0` tautologically false. The field is dead and misleads readers into thinking there is a runtime tamper signal.

**Fix:** Either remove the field, or replace it with a real runtime check (compare against a separately stored copy taken at startup and re-read every call) and document the threat model.

---

### M-2 — Version macros two patch levels behind

**File:** `stealthlib/stealth.hpp:7-8`

```cpp
#define STEALTH_VERSION_PATCH 0
#define STEALTH_VERSION_STRING "2.1.0"
```

HEAD is tagged v2.1.2. Both should read `2.1.2` / `2`.

---

### M-3 — `quickverify.sh` Phase D `warn` exits 1 in `finalize()` (Phase D itself returned 0)

**File:** `tools/quickverify.sh:203-204, 318-319`

Phase D explicitly returns exit code 0 on non-determinism (line 204: `return 0`), but `finalize()` sets `any_fail=1` for `warn` (line 319), causing the whole script to exit 1.

**Reproducer:**
```bash
QV_SKIP=A,B,C,E,F,G bash tools/quickverify.sh   # only Phase D runs
# if non-deterministic build: script exits 1 even though [warn] is non-fatal
```

**Fix:** Change line 319 from `any_warn=1; any_fail=1` to just `any_warn=1`.

---

### M-4 — `quickverify.sh` Phase D uses `sha256sum` — absent on macOS

**File:** `tools/quickverify.sh:171, 193-194`

```bash
require_tool sha256sum    # macOS ships shasum, not sha256sum
h1="$(sha256sum "$b1" | awk '{print $1}')"
```

macOS does not have `sha256sum` in the base install; the equivalent is `shasum -a 256`. Phase D hard-fails on macOS instead of skipping.

**Fix:**
```bash
SHA256SUM="sha256sum"
if ! command -v sha256sum >/dev/null 2>&1; then
    if command -v shasum >/dev/null 2>&1; then
        SHA256SUM="shasum -a 256"
    else
        skip "Phase D: sha256sum / shasum not found"; record "D" skip; return 0
    fi
fi
# then: $SHA256SUM "$b1" instead of sha256sum
```

---

### M-5 — Test gap: `S("")` / `SW(L"")` empty-literal specialisations and `unlock()` not exercised

**File:** `tests/` (all)

The v2.1.2 `stealth_encrypted_char<0, Idx>` (lines 698-708) and `stealth_encrypted_wchar<0, Idx>` (lines 730-739) — including the new `operator*()` for narrow — are not tested anywhere. `string_test.cpp` and `test_strings.cpp` contain no `S("")` or `SW(L"")` call. C-7 (above) shows that `SW(L"").unlock()` does not even compile; the absence of any test masking C-7 is the only reason the bug is sitting in v2.1.2.

**Suggested test (add to `string_test.cpp` after C-7 is fixed):**
```cpp
{
    auto empty_n = S("");
    assert(std::strcmp(empty_n, "") == 0);
    assert(empty_n.size() == 0);
    assert(std::strcmp(*empty_n, "") == 0);  // operator*() new in v2.1.2
    auto g = empty_n.unlock();               // exercises nullptr-pool ctor
    assert(std::strcmp(g.c_str(), "") == 0);
}
{
    auto empty_w = SW(L"");
    assert(std::wcscmp(empty_w, L"") == 0);
    assert(empty_w.size() == 0);
    auto wg = empty_w.unlock();              // catches C-7 today
    assert(std::wcscmp(wg.c_str(), L"") == 0);
}
```

---

### M-6 — `test_concurrent_decrypt.cpp` lacks adversarial interleave; "TSan-clean" claim is weak

**File:** `tests/test_concurrent_decrypt.cpp:40-51`

Probe 2 (thread A `*lit`, thread B `lit.unlock()`) runs each thread in its own loop with no `std::atomic` barrier forcing the dangerous interleave (between `decrypt()` setting `decrypted=true` and `reencrypt()` resetting it). TSan's default scheduler misses these races more often than not. The Probe-2 PASS does not prove the race-freedom claim — see I-5 for the real bug it should have caught.

This is a test-quality issue, but the v2.1.2 release notes lean on this test as evidence of thread safety. The test should be rewritten with a `std::atomic<int> ready` start-gun and tight inner loops to maximize the chance of catching I-5.

---

### M-7 — Documentation stale: ANALYSIS.md, HARDENING_REPORT.md, README.md, PROJECT_PLAN.md reference v2.1.1 / v1.0.0 / wrong LoC

| Document | Line | Stale claim | Correct value |
|---|---|---|---|
| `README.md` | 20, 291 | `~1722 LoC` | 1855 LoC |
| `README.md` | 244 | "StealthLib v2.1.1" | v2.1.2 |
| `README.md` | 18 | Scorecard `9.3 / 10` | needs re-justification after C-1..C-7 |
| `PROJECT_PLAN.md` | 18, 111 | `~1722 LoC` | 1855 |
| `PROJECT_PLAN.md` | 16, 109 | `9.3/10` Correctness | demonstrably untrue: MSVC does not build |
| `PROJECT_PLAN.md` | 45, 47 | "stealthlib v2.1.1" feature grid | v2.1.2 |
| `docs/ANALYSIS.md` | 5 | "v2.1.1" | v2.1.2 |
| `docs/ANALYSIS.md` | 26, 27 | scorecard 9.3 / 7.5 | needs update |
| `docs/ANALYSIS.md` | 289 | `~1722 LoC` | 1855 |
| `docs/HARDENING_REPORT.md` | 4 | `Version: 1.0.0 (pre-release)` | v2.1.2 |
| `docs/HARDENING_REPORT.md` | 263 | "1.0.0 pre-release hardening effort" | post-v2.1.1 |

The scorecards (9.3 / 7.5 / 8.0 / 7.0) are particularly load-bearing — they need to come down until MSVC actually compiles, otherwise the README's "9/9 ctests pass under ... ASan + UBSan clean" headline is misleading by omission (Linux-GCC-only is not the same as cross-platform clean).

---

### M-8 — `quickverify.sh` header doc out of sync with implementation  🆕

**File:** `tools/quickverify.sh:7-13`

The header banner advertises six phases (A-F):
```
#   A. Release smoke
#   B. Strict-warnings build
#   C. ASan + UBSan debug
#   D. Build determinism
#   E. SHA-256 KAT smoke
#   F. Fuzz corpus driver
```
…but the script actually runs seven (line 342: `phase_G || true`). Phase G — "SSE2 _mm_xor_si128 parity" — was added without updating the header comment.

**Fix:** Add the G line and a `QV_SKIP=G` example in the comment block.

---

### M-9 — Stale comment references non-existent `integrity::prologue_fingerprint`  🆕

**File:** `stealthlib/stealth.hpp:570`

```cpp
// Used by integrity::prologue_fingerprint to compare function prologue bytes...
```

`grep -n prologue_fingerprint stealth.hpp` returns only this one comment hit. The actual function is `integrity::prologue_sha256` (line 1792 / 1831). Earlier name, never updated after the rename.

**Fix:** Replace `prologue_fingerprint` with `prologue_sha256` in the comment.

---

### M-10 — Phase F builds fuzz corpus without sanitizers — bypasses ASan/UBSan path  🆕

**File:** `tools/quickverify.sh:244-249`

Phase F (standalone `g++` build of `tests/fuzz_hashes.cpp`) uses only `-O2 -Wall -Wextra -Wpedantic`. No `-fsanitize=address,undefined`. Phase C runs ASan over the *integrated* test set, but if `fuzz_hashes.cpp` exercises code paths the integrated tests don't, those paths get O2 release coverage only.

**Fix:** Add `-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer` to the Phase F compile line. Cost: ~2× slower; coverage gain: all paths Phase F is supposed to fuzz.

---

## Summary table

| ID | Severity | Area | One-liner |
|---|---|---|---|
| **C-1** | **critical** | detection | `check_remote_debugger`: old + new block both present → redeclaration |
| **C-2** | **critical** | integrity | `is_eat_forwarded`: stray `return false;` at namespace scope |
| **C-3** | **critical** | PE parsing | `DOS_HEADER_NT` + `NT_HEADERS64_NT` wrong layouts → all PE helpers read garbage |
| **C-4 🆕** | **critical** | integrity | `prologue_sha256` defined twice in `namespace integrity` on Windows → ODR error |
| **C-5 🆕** | **critical** | strings | `__atomic_*` GCC-only builtins with no MSVC fallback → MSVC can't compile `S()`/`SW()` |
| **C-6 🆕** | **critical** | detection | `rdtsc()` uses GCC `__asm__` under `_M_X64`; `_M_IX86` branch returns nothing |
| **C-7 🆕** | **critical** | strings | `unlocked_wstring_guard(L"", 0, nullptr)` — no `nullptr_t` ctor → `SW(L"").unlock()` fails |
| I-1 | important | integrity | `is_eat_forwarded`: DataDirectory offset `0xF0` wrong (PE32+: should be `0x88`) |
| I-2 | important | integrity | `compare_iat_thunk`: no ordinal-import guard; 4-byte read of 8-byte PE32+ thunk |
| I-3 | important | tests | `regression_test.cpp`: calls non-existent `base64_decode<4>` template |
| I-4 | important | API | `unlocked_wstring_guard` missing move-assign → deleted-function error |
| **I-5 🆕** | important | concurrency | decrypt/reencrypt race on `buffer[]` and `encrypted[]`; `__atomic_*` only protects the flag |
| M-1 | minor | detection | `signals::build_key_match == 0` check is dead (macro is constant) |
| M-2 | minor | API | `STEALTH_VERSION_STRING` is `"2.1.0"`, should be `"2.1.2"` |
| M-3 | minor | tooling | quickverify Phase D `warn` exits 1 despite Phase D choosing non-fatal return 0 |
| M-4 | minor | tooling | quickverify Phase D uses `sha256sum`, absent on macOS |
| M-5 | minor | tests | No test for `S("")` / `SW(L"")` empty specialisations or nullptr-pool guard |
| M-6 | minor | tests | TSan concurrent test lacks true-interleave pressure |
| M-7 | minor | docs | ANALYSIS.md / HARDENING_REPORT.md / README / PROJECT_PLAN reference v2.1.1 / v1.0.0 / wrong LoC |
| **M-8 🆕** | minor | tooling | quickverify header doc lists 6 phases A-F; script runs 7 (G unlisted) |
| **M-9 🆕** | minor | docs | `stealth.hpp:570` comment references non-existent `integrity::prologue_fingerprint` |
| **M-10 🆕** | minor | tooling | Phase F fuzz build lacks `-fsanitize=address,undefined` |

🆕 = new finding not in the prior audit pass.

---

## Root-cause pattern

All seven critical bugs (C-1..C-7) share the same root cause: **MSVC and the Windows-only `#ifdef _WIN32` branch are never compiled by CI**.

- C-1, C-2 are incomplete edits (old code not removed after a fix was added).
- C-3 is a struct layout that has been wrong since pre-v2.1.1 — never exercised by a passing ctest.
- C-4 is a code-organisation slip exposed when a function was promoted out of the Windows-only block.
- C-5, C-6 are toolchain-specific intrinsics used as if they were portable.
- C-7 is a code-symmetry miss between narrow and wide guards.

`PROJECT_PLAN.md` line 16 explicitly admits "MSVC and Clang locally unverified". Closing that line would catch all seven criticals in the first build.

**Recommended first action:** add a Windows CI job (GitHub Actions `windows-2022`, MSVC 2022 `/std:c++20`) that builds a minimal Windows target (`examples/game_protection.cpp` is sufficient). C-1, C-2, C-3, C-4, C-5, C-6 would all surface immediately as compile errors; C-7 would surface as soon as a test instantiates `SW(L"").unlock()`; I-1, I-2 would likely surface as failing tests once the build is green; I-5 needs the adversarial TSan test in M-6 to surface.

**Order of operations to recover Windows:**
1. Fix C-5 (atomic intrinsics) and C-6 (rdtsc) — needed before any Windows build can even reach the Windows-only blocks.
2. Fix C-1, C-2, C-4 (textual / brace fixes).
3. Fix C-3 (struct layout) — without this, no PE-touching code is correct.
4. Fix C-7 (missing wide nullptr_t ctor) — needed before adding M-5's empty-literal test.
5. Add the M-5 test + adversarial M-6 test; expect I-5 to surface.
6. Fix I-1, I-2, I-3, I-4.
7. Update docs (M-7) only after the above; the scorecard needs honest numbers, not aspirational ones.

After (1)-(4) the MSVC binary should at least link and the smoke test should pass; the rest is hardening.
