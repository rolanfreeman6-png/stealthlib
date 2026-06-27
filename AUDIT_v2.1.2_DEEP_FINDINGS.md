# StealthLib v2.1.2 — Deep Code Audit (Manual, Byte-Level)

**Auditor:** Claude (Opus 4.7), manual main-loop review after Workflow batch failed on $10/5h rate limit (1.6M tokens burned on 2 retries before switch).
**Scope:** every line of `stealthlib/stealth.hpp` (1909 LoC), key tests, examples, fixtures, CI, docs.
**Date:** 2026-06-27
**HEAD at audit:** 8d991b6 (v2.1.2) + 30 uncommitted Phase-1 files
**Method:** independent code reading vs spec (FIPS 180-4, Windows PE, RFC 4648), not claim-verification of fix log.

---

## Headline

The Phase-1 audit (35 fixes against AUDIT_v2.1.2.md) was correctly applied — every claimed fix is present in source. But **the project still ships with at least 4 real bugs that the audit did not surface**, including one that makes the documented "killer feature for hook detection" completely non-functional. The clean 18/18 ctest pass does not falsify these bugs because the matching tests are tautological.

| Class | Count |
|---|---|
| Critical (broken feature, test-blind) | **2** |
| High (false-positive/false-negative on documented behaviour) | **2** |
| Medium (UB pattern, demo misleading) | **2** |
| Low (documentation drift) | **1** |

---

## CRITICAL ① — `compare_iat_thunk` reads garbage as ImportDirectory

**File:** `stealthlib/stealth.hpp:1713-1775`
**Severity:** critical
**Category:** spec-mismatch / bug

### Evidence

```cpp
// stealth.hpp:1718-1726
auto dos = reinterpret_cast<uint8_t*>(mod);
auto pe = reinterpret_cast<uint8_t*>(mod) + *reinterpret_cast<uint32_t*>(dos + 0x3C);
uint16_t magic = *reinterpret_cast<uint16_t*>(pe + 0x18);
std::size_t dd_offset = (magic == 0x20b) ? 0x88 : 0x78;
auto opt = pe + 0x18 + *(reinterpret_cast<uint16_t*>(pe + 0x14));   // (A)
auto import_dir = opt + dd_offset;                                    // (B)
auto importRva = *reinterpret_cast<uint32_t*>(import_dir + 0x10);     // (C)
```

### Layout (Windows PE32+)

- `pe` → "PE\0\0" signature (4 bytes)
- `pe + 4` → IMAGE_FILE_HEADER (20 bytes)
- `pe + 0x14` → IMAGE_FILE_HEADER.SizeOfOptionalHeader (uint16) — ✓ correctly read
- `pe + 0x18` → **start** of IMAGE_OPTIONAL_HEADER
- `pe + 0x18 + 0x88` → DataDirectory[0] = Export
- `pe + 0x18 + 0x90` → DataDirectory[1] = Import
- `pe + 0x18 + SizeOfOptionalHeader` → **end** of OptionalHeader / start of section table

### What the code computes

- **(A)** `opt = pe + 0x18 + SizeOfOptionalHeader` ≈ `pe + 0x108` (PE32+) — that is the start of the **section table**, NOT the OptionalHeader.
- **(B)** `import_dir = opt + 0x88` ≈ `pe + 0x190` — deep into garbage past the section table.
- **(C)** `importRva = *(uint32_t*)(import_dir + 0x10)` — reads 4 bytes of garbage.

Even if `opt` were correct (drop the `+ SizeOfOptionalHeader`), `+ 0x10` after the Export entry would land on DataDirectory[2] (Resource), not [1] (Import). Each `IMAGE_DATA_DIRECTORY` is 8 bytes (VA + Size), so DataDirectory[1] is at offset `+ 8` from DataDirectory[0].

Compare with the **correct** `is_eat_forwarded` (`stealth.hpp:1798-1802`) which reads `nt8 + dd_off` directly off the PE signature — no extra `SizeOfOptionalHeader` term.

### Impact

`compare_iat_thunk` (and therefore `is_iat_hooked`) **never** correctly inspects the IAT. The documented "IAT hook detection" capability does not function. In practice `importRva` is usually zero garbage so the function returns `hook_info{hooked=false}` regardless of any real hook installed by Detours/EasyHook/Frida — a permanent false-negative on the entire integrity surface.

### Why test 18/18 passes anyway

`tests/test_integrity.cpp:11-14`:
```cpp
TEST_CASE("integrity: IAT/EAT hooks scan does not crash") {
    auto ki = stealth::integrity::compare_iat_thunk("kernel32.dll", "GetProcAddress");
    CHECK((ki.hooked == true || ki.hooked == false));   // tautology
}
```
The check `bool == true || bool == false` is **always true**. See Critical ②.

### Fix

```cpp
// Drop SizeOfOptionalHeader from opt; use DataDirectory[1] (Import) offset.
auto opt = pe + 0x18;                                          // OptionalHeader start
auto import_dir = opt + dd_offset + 0x08;                       // DataDirectory[1]
auto importRva = *reinterpret_cast<uint32_t*>(import_dir);
```
Then write a *real* test: hook GetProcAddress yourself with a known trampoline, assert `compare_iat_thunk` reports `hooked=true` and `actual != expected`.

---

## CRITICAL ② — Tautological tests mask broken behaviour

**File:** `tests/test_integrity.cpp`
**Severity:** critical
**Category:** test-quality

### Evidence

```cpp
// test_integrity.cpp:11-14
CHECK((ki.hooked == true || ki.hooked == false));        // tautology — bool is always one of these

// test_integrity.cpp:16-20
auto ok = stealth::integrity::is_eat_forwarded("ntdll.dll", "RtlUserThreadStart")
       || !stealth::integrity::is_eat_forwarded("ntdll.dll", "RtlUserThreadStart");
CHECK(ok);                                                // X || !X — always true

// test_integrity.cpp:109-112
bool b = stealth::detection::vmdetect::cpuid_hypervisor_present();
CHECK((b == true || b == false));                         // tautology
```

These tests assert that the functions don't crash. They assert NOTHING about whether the functions return correct values. They pass equally well whether the underlying code is correct, broken, or replaced with `return false;`.

### Impact

Two-fold:
1. Tests give false confidence — they hide Critical ① and would hide any future regression in any of those functions.
2. The `94.85% line coverage` and `90.43% branch coverage` numbers are inflated: lines are *executed* but the test assertions don't constrain behaviour.

### Fix

Replace tautologies with real assertions:
```cpp
// IAT-hook detection: install a known hook, assert detection.
TEST_CASE("compare_iat_thunk detects a manually installed hook") {
    auto baseline = stealth::integrity::compare_iat_thunk("kernel32.dll", "GetProcAddress");
    CHECK(baseline.hooked == false);
    CHECK(baseline.expected != nullptr);
    // Install a self-trampoline that points to a no-op stub.
    install_iat_hook("kernel32.dll", "GetProcAddress", &my_noop);
    auto hooked = stealth::integrity::compare_iat_thunk("kernel32.dll", "GetProcAddress");
    CHECK(hooked.hooked == true);
    CHECK(hooked.actual == reinterpret_cast<void*>(&my_noop));
    uninstall_iat_hook(...);
}
```

---

## HIGH ③ — `small_disk_heuristic_gb` on Windows reads free bytes, not disk size

**File:** `stealthlib/stealth.hpp:1336-1350` + `1362-1389` (`scan().reported_disk_gb`)
**Severity:** high
**Category:** bug / spec-mismatch (Win32 API misuse)

### Evidence

```cpp
// stealth.hpp:1338-1341
ULARGE_INTEGER free_bytes{};
if (!GetDiskFreeSpaceExA("C:\\", &free_bytes, nullptr, nullptr)) return false;
constexpr double GB = 1024.0 * 1024.0 * 1024.0;
return static_cast<double>(free_bytes.QuadPart) / GB < min_gb;
```

`GetDiskFreeSpaceExA` signature:
```
BOOL GetDiskFreeSpaceExA(
  LPCSTR          lpDirectoryName,
  PULARGE_INTEGER lpFreeBytesAvailableToCaller,   // ← 2nd arg = FREE bytes
  PULARGE_INTEGER lpTotalNumberOfBytes,           // ← 3rd arg = TOTAL bytes (passed nullptr)
  PULARGE_INTEGER lpTotalNumberOfFreeBytes);
```

The code passes the receiver as the **2nd** argument, which is "free bytes available to caller", not total disk size. The Linux path (line 1346-1348) correctly computes `v.f_blocks * v.f_frsize` = total filesystem bytes.

### Impact

- Stated heuristic: "<80GB on system drive = VM sandbox signal".
- Actual on Windows: "<80GB FREE on C: = VM sandbox signal".
- A real developer machine with a 1TB drive 95% full will trigger this as a VM.
- Conversely, a VM with a thin-provisioned 200GB disk but only 50GB used reports >150GB free → not flagged.
- The `scan_result.reported_disk_gb` shipped to library callers reports different metrics depending on platform — undocumented contract violation.

### Fix

```cpp
ULARGE_INTEGER total_bytes{};
if (!GetDiskFreeSpaceExA("C:\\", nullptr, &total_bytes, nullptr)) return false;
return static_cast<double>(total_bytes.QuadPart) / GB < min_gb;
```
Apply the same correction in `scan().reported_disk_gb` lambda (lines 1369-1374).

---

## HIGH ④ — `registry_or_dmi_vm_vendor` Windows mis-classifies "Microsoft Corporation" as VM evidence

**File:** `stealthlib/stealth.hpp:1240-1279`
**Severity:** high
**Category:** bug / design
**Comment claims:** `"Hyper-V", "Microsoft Corporation"  // weak: only triggers when paired with other hits`

### Evidence

```cpp
// stealth.hpp:1250-1264 — Windows path
static constexpr const char* patterns[] = {
    "VMware", "VirtualBox", "QEMU", "innotek", "Xen",
    "Hyper-V", "Microsoft Corporation"  // weak: only triggers when paired with other hits
};
for (auto p : patterns) {
    for (char const* q = s; *q; ++q) {
        if ((*q | 32) == p[0]) {
            char const* r = q + 1;
            char const* s2 = p + 1;
            while (*r && *s2 && (*r | 32) == *s2) { ++r; ++s2; }
            if (!*s2) return true;     // ← first match wins, "weak" is treated as strong
        }
    }
}
```

The Linux branch (lines 1294-1318) **does** separate `strong[]` and `weak[]` arrays and treats weak matches as not-evidence (`return false`). The Windows branch puts "Microsoft Corporation" in the same `patterns[]` array as the strong vendors, with no separation. The comment promises "only triggers when paired with other hits" but the code returns `true` on the first match regardless.

### Impact

On any Microsoft-branded hardware (Surface, Hyper-V host, even some Dell/HP machines whose firmware identifies "Microsoft Corporation" somewhere in BIOS), `registry_or_dmi_vm_vendor()` returns `true` → `scan().vendor_strings = true` → `vm_confidence` inflated by 1. A user-facing API claims this machine is a VM when it isn't.

Symmetric design vs Linux means a developer reading the Linux logic would assume Windows behaves the same — it doesn't.

### Fix

Mirror the Linux strong/weak structure on Windows:
```cpp
static constexpr const char* strong[] = {
    "VMware", "VirtualBox", "QEMU", "innotek", "Xen", "Hyper-V"
};
static constexpr const char* weak[] = { "Microsoft Corporation" };
// ... walk strong, return true on any hit; walk weak, return false on hit (informational only).
```
Apply the `mirror` skill rule — both platforms keep the same evidence model.

---

## MEDIUM ⑤ — Examples use `S("...").unlock()` on a prvalue ⇒ use-after-destroy

**File:** `examples/hash_resolution.cpp:83-87`, `examples/unlock_demo.cpp:30-33`
**Severity:** medium
**Category:** bug (UB) / design

### Evidence

```cpp
// hash_resolution.cpp:83
auto lock = S("hi").unlock();
std::cout << "    scope 1: decrypted = " << lock.c_str() << "\n";
// ...end of full-expression at ';' destroys the S("hi") temporary
// guard 'lock' lives to end of block, holds pool_ptr_ = &dead_impl

// unlock_demo.cpp:31
auto wlock = SW(L"\x0421\x0435\x043A\x0440\x0435\x0442").unlock();
```

`S("hi")` is a prvalue `stealth_encrypted_char<2, N>`. The temporary is materialised, `.unlock()` is called returning a `unlocked_string_guard` that holds `void* pool_ptr_ = &this->impl`. The temporary then dies at the semicolon (no reference binding extends its lifetime — the guard owns by raw pointer, not by reference). The named local `lock` outlives the temporary. When `lock`'s dtor runs at end of block, it invokes `reen_(pool_ptr_)` on the destroyed `impl` ⇒ **use-after-destroy** UB.

In practice (single-thread, no allocation between destruction and dtor call) the stack memory is undisturbed so it appears to work. Optimizers are entitled to break it any time. The fix-pattern `static auto lit = S(...)` was applied in `tests/regression_tu_a.cpp:4` precisely because of this hazard, but the examples kept the original UB pattern.

### Impact

- The "killer feature demo" teaches users a pattern that is technically UB. Anyone who copy-pastes it into a longer function with intervening allocations or in a multi-threaded context risks corruption.
- Documentation inconsistency: the lib's own test files acknowledge the issue but examples don't.

### Fix

```cpp
auto s = S("hi");
auto lock = s.unlock();              // s outlives lock
std::cout << lock.c_str() << "\n";

// or, for one-shot use within the full-expression only:
std::cout << S("hi").unlock().c_str() << std::endl;
// lifetime is bounded to the full-expression — UB-free, but no scope guard
```

---

## MEDIUM ⑥ — `hash_resolution.cpp:50` prints stack address, not resolved function address

**File:** `examples/hash_resolution.cpp:50`
**Severity:** medium
**Category:** bug / demo-misleading

### Evidence

```cpp
// hash_resolution.cpp:48-52
auto mb = stealth::get_function_by_hash<MessageBoxW_t>(h_user32, h_msgbox_w);
if (mb) {
    std::cout << "[+] MessageBoxW resolved by hash at " << reinterpret_cast<void*>(&mb) << "\n";
    (void)mb;
}
```

`&mb` is the stack address of the local pointer variable. Should be `mb` (the resolved function pointer itself) cast to `void*`. A user reading this output to confirm the killer feature works gets misleading data — `&mb` looks like a stack canary, not a user32 entry point.

### Fix

```cpp
std::cout << "[+] MessageBoxW resolved by hash at " << reinterpret_cast<void*>(mb) << "\n";
```

---

## LOW ⑦ — `PROJECT_PLAN.md` advertises `version()` returns "2.1.0", actually returns "2.1.2"

**File:** `PROJECT_PLAN.md:19` and `:112` (duplicated table)
**Severity:** low
**Category:** doc-inconsistency

### Evidence

```
PROJECT_PLAN.md:19:  ... `stealth::version()` returns `"2.1.0"` reflecting shipped API surface
PROJECT_PLAN.md:112: ... `stealth::version()` returns `"2.1.0"` reflecting shipped API surface
```

Actual:
```
stealth.hpp:8:  #define STEALTH_VERSION_STRING "2.1.2"
```

The M-7 doc-sync claim in `AUDIT_v2.1.3_RESPONSE.md` passed the narrow grep `1722|v2.1.1|1.0.0 (pre-release)` but missed the v2.1.0 reference that remains in PROJECT_PLAN.md. README and HARDENING_REPORT and SECURITY are correct.

### Fix

Single search-and-replace `"2.1.0"` → `"2.1.2"`, and `aligned with v2.0 surface` → `aligned with v2.1.2 surface` in PROJECT_PLAN.md.

---

## What was checked and confirmed correct (NOT bugs)

To bound the noise, the following passed byte-level inspection against spec:

| Subsystem | Reference | Verdict |
|---|---|---|
| SHA-256 (h init, K[64], rotations 7/18/3 + 17/19/10 + 6/11/25 + 2/13/22, padding 0x80 + 8-byte BE length, BE word load) | FIPS 180-4 | ✓ exact compliance |
| FNV-1a basis/prime, djb2 init | official refs | ✓ |
| base64 padding rejection (`AA=A`, `AAAA====`) | RFC 4648 §3.5 | ✓ |
| LDR_ENTRY_NT offsets DllBase@0x30, BaseDllName.Buffer@0x60 | Microsoft PE/COFF | ✓ counted byte-by-byte |
| DOS_HEADER_NT e_lfanew@0x3C, NT_HEADERS64.DataDirectory[0]@0x88 | PE/COFF | ✓ |
| `is_eat_forwarded` PE32/PE32+ magic-switched dd_off | PE/COFF | ✓ |
| Encrypted-string SSE2 keystream vs scalar (positions 0..N-1) | algebraic trace | ✓ matches |
| Encrypted-string `reencrypt` symmetry | XOR involution | ✓ |
| `consteval` ctor forces compile-time encryption | C++20 | ✓ confirmed cannot be runtime-instantiated |
| Null-safety: `base64_encode`, `hex_encode`, `xor_crypt`, `rot13_encode`, `compare_constant_time`, `xor_key::operator[]` | boundary discipline | ✓ all guarded |
| Variant B threading contract + adversarial test under TSan | `docs/THREADING.md` | ✓ contract documented and probed |
| PE struct offsets, byte-level | PE/COFF | ✓ |

---

## Test-quality verdict

Critical ② (tautological tests) is the most worrying finding because it means **passing CI is not evidence of behaviour correctness** for the integrity and vmdetect surfaces. The numerics in the audit summary (94.85% line / 90.43% branch coverage) reflect line execution, not assertion coverage. Recommended:

1. Add an "assertion-strength linter" — any `CHECK((x == true || x == false))` or `CHECK(X || !X)` patterns are auto-rejected.
2. Rewrite the four tautological cases (test_integrity.cpp lines 13, 17-19, 111) with real positive/negative assertions.
3. Add a mutation-testing pass: `mull-runner` or similar — flip individual operators and confirm at least one test fails. Today, mutating `compare_iat_thunk` to `return hook_info{};` would still pass 18/18.

---

## Suggested commit sequence

```
fix(integrity): correct compare_iat_thunk DataDirectory[1] address math — was reading past the OptionalHeader by SizeOfOptionalHeader bytes and indexing +0x10 (Resource) instead of +0x08 (Import); IAT-hook detection now functions
fix(vmdetect): GetDiskFreeSpaceExA must receive total-bytes, not free-bytes; small_disk_heuristic now matches Linux statvfs semantics
fix(vmdetect): mirror Linux strong/weak vendor-string separation on Windows; "Microsoft Corporation" no longer a strong hit
fix(test_integrity): replace tautological `bool == true || bool == false` assertions with real positive/negative checks; expose Critical ① if reintroduced
fix(examples): use named local `auto s = S("...")` before `.unlock()` — prvalue.unlock() pattern is UB
fix(examples/hash_resolution): print resolved function ptr `mb`, not stack address `&mb`
docs(PROJECT_PLAN): version() returns "2.1.2", not "2.1.0"
```

---

## Method limitations (honest)

- This audit was done in a single Claude main-loop session after the parallel-Workflow batch was blocked by API rate limits. The fan-out adversarial verification stage did not execute. Each finding above has been verified by the auditor reading the source and walking through the math, but no second pair of eyes refuted them.
- Files NOT individually read: `tests/scenario_rte_*.cpp`, `tests/test_strings.cpp`, `tests/test_hashes.cpp`, `tests/test_sha256.cpp`, `tests/test_sse2_parity.cpp`, `tests/test_peb_windows.cpp` (only grep'd), `tests/peb_test.cpp`, `tests/portable_smoke_test.cpp`, `tests/integration_test.cpp`, `tests/comprehensive_test.cpp`, `tests/fixtures/generate_pe.py`, `benchmark/benchmark.cpp`, `examples/full_demo.cpp`, `examples/game_protection.cpp`, `examples/server_protection.cpp`, `examples/minimal_test.cpp`, `docs/ANALYSIS.md`, `docs/HARDENING_REPORT.md`, `docs/SECURITY.md`, `docs/THREATS_MODEL.md`, `docs/INSTALL.md`, `docs/EXAMPLES.md`, `CMakeLists.txt` (root, only fragment).
- Recommend re-running the Workflow audit (or sequential continuation) once $10/5h plan rate-limit resets to fan out over these files.

---

## Score recalibration

Before this audit (claim-verification only): A- ≈ 8.9/10.
After this audit (incorporating 2 critical + 2 high): **B+ ≈ 8.0/10** until the four critical/high findings ship as fixes.
The path to 9.0+ is now four commits and one CI rebuild away.
