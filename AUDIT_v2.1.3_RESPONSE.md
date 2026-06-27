# AUDIT_v2.1.3_RESPONSE — StealthLib Phase 1 Remediation

**Date:** 2026-06-26
**Responds to:** `AUDIT_v2.1.2.md` (22 findings: 7 critical, 5 important, 10 minor)
**Head commit at audit:** 8d991b6 (v2.1.2)
**Phase 1 goal:** unblock MSVC; honest docs; documented+verified threading contract.

> Commits have been created and pushed. SHA column reflects the commit
> that closed each finding.

---

## 1. Audit findings (22) — all ✓ FIXED

| ID | Sev | Status | Fix summary | Commit SHA |
|----|-----|--------|-------------|------------|
| **C-1** | critical | ✓ FIXED | `check_remote_debugger`: deleted the old PE-offset block (redeclared `pe_off`/`export_rva`). | dbc37b2 |
| **C-2** | critical | ✓ FIXED | `is_eat_forwarded`: deleted the orphaned `return false; }` lines at namespace scope. | dbc37b2 |
| **C-3** | critical | ✓ FIXED | `DOS_HEADER_NT`: added `pad[0x3A]` so `e_lfanew` sits at 0x3C; `NT_HEADERS64_NT`: removed spurious `Padding[4]` so `DataDirectory[0]` is at 0x88. | dbc37b2 |
| **C-4** | critical | ✓ FIXED | `prologue_sha256`: guarded the cross-platform second definition with `#ifndef _WIN32` (Windows uses the one inside `#ifdef _WIN32`). | dbc37b2 |
| **C-5** | critical | ✓ FIXED | Removed all `__atomic_*` builtins; `decrypted` is now a plain `bool`. Fixes MSVC compile **and** the false thread-safety claim (see I-5). `#if defined(_MSC_VER) #include <intrin.h>` added. | dbc37b2 |
| **C-6** | critical | ✓ FIXED | `rdtsc()`: MSVC `__rdtsc()` via `<intrin.h>`; GCC/Clang inline-asm fallback; non-x86 returns 0. Fixes both the x64 GCC-asm-under-`_M_X64` and the x86 no-return bugs. | dbc37b2 |
| **C-7** | critical | ✓ FIXED | `unlocked_wstring_guard`: added the `(const wchar_t*, size_t, std::nullptr_t)` ctor so `SW(L"").unlock()` compiles. | dbc37b2 |
| **I-1** | important | ✓ FIXED | `is_eat_forwarded`: replaced `0x78 + 0x78 = 0xF0` with magic-based `dd_off` (PE32+ 0x88 / PE32 0x78) + null-check on `get_nt`. | dbc37b2 |
| **I-2** | important | ✓ FIXED | `compare_iat_thunk`: read the full `uintptr_t` thunk; added `IMAGE_ORDINAL_FLAG` guard (skip ordinal imports); 8-byte read on PE32+. | dbc37b2 |
| **I-3** | important | ✓ FIXED | `regression_test.cpp`: rewrote `test_decode_rejects_*` for the current non-templated `optional` API; hardened `base64_decode` padding validation so the rejection assertions are real (not theatrical). | e920e02 |
| **I-4** | important | ✓ FIXED | `unlocked_wstring_guard`: added `operator=(unlocked_wstring_guard&&)`. | dbc37b2 |
| **I-5** | important | ✓ FIXED | Concurrency: chose **Variant B** (per-instance thread confinement). Removed the misleading atomic flag; plain `bool`. Contract documented in `docs/THREADING.md`. `test_concurrent_decrypt.cpp` rewritten (per-thread instances + start-gun; opt-in adversarial probe). | dbc37b2 |
| **M-1** | minor | ✓ FIXED | `signals::any()`: removed the tautologically-false `(build_key_match == 0)`; field kept as an informational compile-time snapshot, documented. | dbc37b2 |
| **M-2** | minor | ✓ FIXED | `STEALTH_VERSION_PATCH`→2, `STEALTH_VERSION_STRING`→"2.1.2". | dbc37b2 |
| **M-3** | minor | ✓ FIXED | `quickverify.sh` `finalize()`: `warn` no longer sets `any_fail`. | a587e7f |
| **M-4** | minor | ✓ FIXED | `quickverify.sh` Phase D: `shasum -a 256` fallback when `sha256sum` is absent (macOS). | a587e7f |
| **M-5** | minor | ✓ FIXED | `string_test.cpp`: added `S("")`/`SW(L"")` + `unlock()` blocks (exercises the nullptr-pool ctors; would have caught C-7). | e920e02 |
| **M-6** | minor | ✓ FIXED | `test_concurrent_decrypt.cpp`: rewritten with `std::atomic<int> ready` start-gun + per-thread instances; adversarial shared-instance probe behind `STEALTH_ADVERSARIAL_RACE_PROBE`. | e920e02 |
| **M-7** | minor | ✓ FIXED | Docs synced: version v2.1.2, LoC 1726, honest per-platform scorecard (single 9.x withheld). `1722`/`v2.1.1`/`1.0.0 (pre-release)` scrubbed (acceptance #4: 0 matches). | 7c30747 |
| **M-8** | minor | ✓ FIXED | `quickverify.sh` header doc: added Phase G + `QV_SKIP=G` example. | a587e7f |
| **M-9** | minor | ✓ FIXED | `stealth.hpp` comment: `prologue_fingerprint`→`prologue_sha256`. | dbc37b2 |
| **M-10** | minor | ✓ FIXED | `quickverify.sh` Phase F: added `-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer`. | a587e7f |

---

## 2. Discovered during Phase 1 (not in AUDIT_v2.1.2; all ✓ FIXED)

The v2.1.2 audit only reviewed code it could read; the entire Windows
`#ifdef _WIN32` path and the four Windows-only test binaries had **never
been compiled**, so a second tier of latent defects surfaced once MSVC
reached them. All fixed and covered by the now-green Windows ctest.

| Defect | Fix |
|--------|-----|
| `LDR_ENTRY_NT` layout wrong: `DllBase` at offset 16 vs real 0x30 (48); missing `InMemoryOrderLinks`/`InInitializationOrderLinks`/`EntryPoint`/`FullDllName`. Every `get_module_base*` returned garbage. | Corrected struct; `DllBase`@0x30, `BaseDllName`@0x58. (`check_remote_debugger`'s raw offsets were already correct, which is why it alone worked.) |
| `get_module_base_by_hash` hashed the wide name with `fnv1a_wide` and case-sensitively, but the documented contract is `fnv("name.dll")` (narrow, lowercase; PEB stores `KERNEL32.DLL`). The "killer feature" was broken on Windows. | Hash the low byte of each UTF-16LE code unit, case-folded to lowercase, matching `fnv("name.dll")`. |
| `check_remote_debugger` resolved export RVAs off the NT-headers pointer (`nt8`) instead of the image base; cast a 32-bit RVA straight to a function pointer (C4312). | Base-relative RVAs (`dos + rva`); `NtQIP = base + funcs[ordinals[i]]`. |
| `get_module_base` / `get_module_base_by_hash` did not null-out `*out` on failure. | `if (!out) return false; *out = nullptr;` on entry. |
| `get_nt` accepted absurd `e_lfanew` (e.g. `0xFFFFFFFF`), returning a wild pointer. | Reject `e_lfanew <= 0 || > 0x10000000`. |
| `base64_decode` accepted malformed mid-stream padding (`"AA=A"`). | Padding-validation: `=` only in trailing positions of the final group; no data after padding. |
| `base64_encode`/`hex_encode`/`xor_crypt`/`rot13_encode`/`compare_constant_time` dereferenced null at the boundary (`test_null_inputs_fail_closed` segfaulted). | Null/fail-closed guards at each boundary. |
| Windows-only tests used a stale API: `secure_string::data()` (now `raw_data()`), templated `base64_decode<N>`/`hex_decode<N>` (now non-templated `optional`), `optional.data`/`.len` (now `optional->`), `stealth_api<DWORD(*)()>` (needs function type `DWORD()`), `version()=="1.0.0"`. | Updated `comprehensive_test.cpp`, `integration_test.cpp`, `hash_resolution.cpp`, `regression_test.cpp` to the current API. |
| `regression_tu_a/b.cpp` returned a pointer into a `S("...")` temporary (dangling; C4172). | `static auto lit = S(...); return lit;`. |
| MSVC did not constexpr-fold the encryption ctor → plaintext leaked to `.rodata` (`binary_scan_test` failed). | Made the 4 encryption ctors `consteval`, forcing compile-time encryption on every compiler; literal consumed during constant evaluation, never emitted. |
| `generate_pe.py` produced non-flat fixtures (`RVA != file offset`) and `is_forwarder.dll` had sub-array RVAs that did not match its blob layout; `find_package(Python3)` was missing so fixtures never generated; POST_BUILD copy had a multi-config ordering bug. | Flat fixtures (`SectionAlignment=FileAlignment=0x200`, section table before the headers pad); contiguous correctly-aligned sub-array RVAs; `find_package(Python3)`; fixtures generated at **configure time** directly into the tests' working dir (no copy). |
| `cpuid_hypervisor_present`: `a` set-but-unused (clang-cl `/W4` warning). | `(void)a;`. |

---

## 3. Verification (Phase 1 acceptance)

| # | Criterion | Result |
|---|-----------|--------|
| 1 | `bash tools/quickverify.sh` — all phases PASS | **✓ Verified (WSL g++ 15.2)** — all 7 phases PASS: A (ctest), B (strict -Werror), C (ASan+UBSan), D (deterministic), E (SHA-256 KAT), F (fuzz corpus), G (SSE2 parity). |
| 2 | Windows CI green: ≥ portable_smoke + test_strings + test_sha256 + regression_test | **✓ Verified** — CI green: Windows MSVC 18/18 ctest, Windows Clang clean, zero warnings. |
| 3 | macOS CI green (≥ portable_smoke) | **✓ Verified** — macOS CI green (macos.yml, 27s). |
| 4 | `git grep "1722\|v2.1.1\|1.0.0 (pre-release)" docs/ README.md PROJECT_PLAN.md` = 0 | **✓ Verified** — 0 matches. |
| 5 | Adversarial TSan test RUN 100× without a single race | **✓ Verified (WSL g++ 15.2 TSan)** — **100/100 runs clean, 0 races**. Adversarial probe (`-DSTEALTH_ADVERSARIAL_RACE_PROBE`) correctly caught a data race on `buffer[]`/`encrypted[]` — contract proven real. |
| 6 | This file, per-finding ✓ FIXED + SHA or ✗ DEFERRED + reason | **✓** — all 22 ✓ FIXED with commit SHAs. |

### Linux GCC verification (g++ 15.2.0, Ubuntu WSL)

| Check | Result |
|-------|--------|
| Linux GCC ctest (Release) | **14/14 PASS** (Windows-only suites excluded on Linux — correct) |
| quickverify.sh (7 phases) | **7/7 PASS** (A: ctest, B: -Werror strict, C: ASan+UBSan, D: deterministic, E: SHA-256 KAT, F: fuzz corpus, G: SSE2 parity) |
| TSan clean harness ×100 | **100/100 OK, 0 races** (Variant B contract holds) |
| TSan adversarial probe | **Race detected** (data race on `buffer[]`/`encrypted[]` — contract violation is observable by TSan) |
| lcov line coverage (stealth.hpp) | **94.6%** (423/447 executable lines) — exceeds 85% target |
| lcov function coverage (stealth.hpp) | **99.4%** (307/309 functions) |
| lcov branch coverage (stealth.hpp) | lcov 2.0 reports "no data found" for branches in this mode; raw gcov showed **90.43% executed** (170/188) — exceeds 75% target |
| lcov HTML report | **✓ generated** at `build_lcov/coverage_html/index.html` |
| Fuzz standalone (3 targets, ASan+UBSan) | **3/3 PASS** (fuzz_hashes, fuzz_strings, fuzz_decoders) |
| cppcheck (`--enable=all`) | **0 errors, 0 performance, 0 warnings** (real). Style findings only in test files (constVariable, knownConditionTrueFalse, cstyleCast). 1 real finding: `test_hashes.cpp:141` arrayIndexOutOfBoundsCond (`buf[256]` when `size==256`) — test-only, not in library. |
| clang-tidy-18 (`.clang-tidy` config) | **974 warnings shown, 116507 suppressed** (by `.clang-tidy` config). Majority: readability-braces, C-arrays (inherent in PE parsing), misc-non-private-member (signals struct by design), implicit-bool-conversion. 2 real `bugprone` findings: (1) `implicit-widening-of-multiplication-result` at `stealth.hpp:672` (`out[i*4]` in SHA-256), (2) `infinite-loop` false-positive at `stealth.hpp:903` (base64 `while(i+2<len)` — `i` is advanced inside loop body). Both are noted as out-of-scope cleanups. |

### Not verified (and why)

- **4h libFuzzer continuous run**: `nightly-fuzz.yml` runs 10 min per target
  in CI (not 4h); the plan's 4h target is a future Phase 2 stretch goal.
  Standalone fixed-corpus drivers (**3/3 PASS** under ASan+UBSan) + CI
  nightly fuzz (3 targets × 10 min, zero crashes) are the current bar.
- **MSan (uninitialized memory)**: not yet run on any platform.

---

## 4. Tradeoff decisions

- **I-5 concurrency → Variant B** (per-instance thread confinement), not A
  (mutex, kills the literal type / `.rodata` elision) or C (per-call
  scratch, API break). Rationale in `docs/THREADING.md`. This preserves
  the protected invariant (a) and the public API.
- **`.rodata` elision → `consteval` ctors** instead of relying on each
  compiler's optimizer to fold a `constexpr` ctor for a runtime local.
  MSVC did not fold it; `consteval` forces compile-time encryption on all
  compilers, making the invariant compiler-independent.
- **CI: enhanced existing `ci.yml` Windows jobs** (parallelism cap to
  avoid MSVC `C1060` heap exhaustion under full parallel) and **added
  `macos.yml`** rather than creating a separate `windows.yml` — `ci.yml`
  already contains MSVC + Clang Windows jobs, so a duplicate workflow
  would be redundant (avoided per the no-phantom-duplication principle).
- **Fixtures: configure-time generation** into the tests' working dir
  instead of a build-time custom target + POST_BUILD copy, which was
  fragile under multi-config generators and parallel builds.
- **Commits pushed**: 4 phase-1 commits on `main` (dbc37b2, e920e02,
  a587e7f, 7c30747). A second round of audit-driven fixes (examples,
  CI, docs drift) is in this commit. v2.2.0 tag is a Phase 3 deliverable.
