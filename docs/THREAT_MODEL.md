# StealthLib — Threat Model

**Version:** v2.1.2 (with Phase 1 hardening)
**Scope:** this document states explicitly what StealthLib **does** protect
against, what it **does not**, and maps each defence to the threat it
addresses. It exists so users know exactly what they are buying.

StealthLib is a **header-only, zero-dependency, in-process hardening
bundle**. It raises the cost of casual static and dynamic reverse
engineering; it is **not** a sandbox, a rootkit detector, or cryptography.

---

## 1. Assets the library helps protect

1. **Embedded secret strings** — API keys, connection strings, passwords,
   Win32 API names — that would otherwise be trivially recoverable with
   `strings(1)` or a hex viewer.
2. **The set of Win32/Nt APIs the program imports** — by replacing
   string-based `GetProcAddress("X")` with hash-based resolution so no
   API name appears in `.rdata`/IAT-by-name.
3. **Detection of an attached/interactive analysis session** — debuggers,
   hardware breakpoints, timing-instrumented VMs.

---

## 2. What is protected (and how)

| Threat | Defence | Limit / note |
|---|---|---|
| **Static string recovery** (`strings`, IDA "shift-F12") | `S("...")`/`SW(L"...")` XOR-encrypt literals at compile time (`consteval` ctor); plaintext is consumed during translation and **not** emitted. Verified by `binary_scan_test` (MSVC + GCC). | Single-round XOR + build-key mask is **obfuscation, not encryption**. A motivated attacker who locates `decrypt()` (it is in the binary) recovers all literals. Defeats casual/greppable RE, not a determined reverse engineer. |
| **API-name enumeration** | `hashes::fnv` + `get_proc_by_hash`/`stealth_api`/`module_loader(hash)` resolve exports by 64-bit FNV-1a hash; no `"MessageBoxW"` string in the binary. | The hash algorithm is public (FNV-1a); an attacker can rainbow-table common API names. Hides the *string*, not the *fact* that the API is called. |
| **Interactive debugger attach** | `detection::scan()` — PEB `BeingDebugged`, `NtQueryInformationProcess(ProcessDebugPort)`, `rdtsc` timing anomaly, hardware-breakpoint DR0–DR3 count. | Each signal is individually spoofable (PEB patching, `NtQuery*` hook, RDTSC virtualisation, DR-register clearing). The value is **multi-channel**: a tool that hides from one channel is less likely to hide from all. |
| **Inline function hooks** (Detours/EasyHook trampoline style) | `integrity::prologue_sha256` — SHA-256 of the first N bytes of a function, constant-time compared to a known-good digest. Catches ~95% of canonical first-bytes hooks. | Mid-function `mov`/`jcc` patches and hooks that preserve the prologue are **not** detected. No disassembler is shipped (deliberate simplicity). |
| **IAT tampering** | `integrity::compare_iat_thunk` — compares the runtime IAT entry to the frozen OriginalFirstThunk (INT) snapshot; flags post-load patches. | Only inspects the import descriptor's first thunk per DLL; does not walk all thunks. Hooking via `SetWindowsHookEx`/detours on the target function (not the IAT) is not caught by this check. |
| **EAT forwarder confusion** | `integrity::is_eat_forwarded` — distinguishes a forwarded export (RVA inside the export directory, points at a `"Module.Func"` string) from real code. | Heuristic byte-scan for `.`; a real-code export whose first bytes happen to contain `0x2E` could false-positive. |
| **VM/sandbox evocation** (dev/QA, not anti-anti-analysis of a skilled attacker) | `detection::vmdetect::scan()` — CPUID hypervisor bit + DMI/registry vendor strings + small-disk heuristic → 0..3 confidence. | Trivially defeated by hiding the hypervisor bit, spoofing DMI, or resizing the disk. Intended to detect **casual dev VMs**, not to resist an attacker who specifically evades VM detection. |
| **Build-fingerprint drift** | `STEALTH_BUILD_KEY` (git SHA + timestamp, MD5-truncated) baked into every build; missing key is a hard `#error`; per-build 16-variant encryption rotation. | Not a tamper seal; the key is a constant in the binary. It binds a binary to its build for *determinism* and *per-build uniqueness*, not integrity. |

---

## 3. What is NOT protected (out of scope, by design)

- **Kernel-mode rootkits / drivers.** All checks run in user mode; a
  kernel rootkit sees and patches anything below.
- **Hypervisor-based debugging / emulation.** A Type-1 hypervisor can
  single-step, read `guest physical` memory, and virtualise `rdtsc`/CPUID
  without any in-guest signal. `vmdetect` is not anti-bluepill.
- **Side-channel attacks** (cache timing, power, EM). Not addressed.
- **Complete reverse engineering by a motivated attacker.** The XOR
  scheme and hash algorithm are in the binary; with the binary, an expert
  recovers every string and resolves every hash. The goal is to **raise
  the floor** above script-kiddie `strings | grep`, not to be
  unbreakable.
- **Memory dumping** (`CreateMiniDump`, `procdump`, `/proc/<pid>/mem`).
  Decrypted plaintext lives in `buffer[]` only during an `unlock()` window;
  outside it the buffer is zeroed. But a live dump during the window
  captures plaintext. This is a narrow-window mitigation, not a guarantee.
- **File-based integrity of the library itself** (no self-hash / packer).
  The `STEALTH_BUILD_KEY` is a build fingerprint, not a runtime self-check.
- **Concurrency safety of a shared `S()` instance across threads.** See
  `docs/THREADING.md` (Variant B): one instance per thread, or external
  synchronisation. Sharing is UB.

---

## 4. Trust boundaries & assumptions

- The library trusts the **loader** (PEB walk, `InLoadOrderModuleList`).
  A hooked loader can lie about module bases.
- The library trusts the **Windows kernel APIs** it resolves
  (`NtQueryInformationProcess`, `GetThreadContext`). These can be hooked.
- The library assumes **x86/x64** for `rdtsc`/CPUID; on other arches
  those signals return 0 (no false positives, but no detection either).
- `STEALTH_BUILD_KEY` must be **unique per release** (CMake generates it).
  Two binaries built without CMake share nothing-by-default only because
  the missing key is a hard `#error`; do not bypass it.

---

## 5. Recommended composition for a target use case

For "raise the cost of casual RE of a Windows game/tool":

```cpp
auto key = S("sk-live-...");                 // no plaintext in .rodata
using Fn = int(HWND, LPCWSTR, LPCWSTR, UINT);
auto msg = stealth::stealth_api<Fn>(
    stealth::hashes::fnv("user32.dll"),
    stealth::hashes::fnv("MessageBoxW"));    // no API name in .rodata
auto s = stealth::detection::scan();
if (s.peb_debug_flag || s.remote_debugger || s.hwbp_count > 0 || s.timing_anomaly)
    escalate();                              // multi-channel, not single-signal
stealth::integrity::prologue_sha256(msg.get(), 16, known_good); // inline-hook guard
```

This composition raises the floor: an analyst cannot `grep` the binary
for the key or API name, an attached debugger trips at least one of four
channels, and a prologue hook changes the SHA-256. None of it stops a
skilled reverse engineer with the binary; all of it stops a casual one.
