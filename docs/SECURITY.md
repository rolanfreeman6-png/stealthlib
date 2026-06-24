# Security Policy and Threat Model for StealthLib

**Project:** StealthLib  
**Version:** 1.0.0 (pre-release)  
**Scope:** `stealthlib/stealth.hpp` and the public API documented in `README.md` and `docs/INSTALL.md`.

---

## What StealthLib Is

StealthLib is a **header-only C++20 hardening utility library** focused on:

- compile-time string obfuscation (`S()` / `SW()` macros)
- portable encoding helpers (Base64, Hex, XOR, ROT13)
- secure memory primitives (secure zeroing, constant-time comparison)
- Windows PEB-based module walking and export resolution
- lightweight debugger-detection signals

It is designed to raise the cost of casual static inspection and to reduce the number of plaintext literals and static imports in a Windows binary. It is **not a cryptographic library**, not a DRM system, and not a guarantee against a determined reverse engineer with a debugger.

---

## What StealthLib Does NOT Promise

- **No "complete binary protection".** No library can remove all strings, all imports, or all attack surface from a Windows executable.
- **No cryptographic security.** `S()`/`SW()` use compile-time XOR obfuscation. The key material and the algorithm are present in the binary. A motivated analyst can recover the plaintext.
- **No anti-debug perfection.** `is_debugger_present()` and `check_remote_debugger()` are best-effort signals. They can be bypassed, patched, or emulated.
- **No memory-dump protection.** Decrypted strings live in process memory while in use. Anyone with sufficient privileges can read them.
- **No Linux/PEB support.** PEB walking, API resolution, examples, and benchmarks are Windows-only.

---

## Supported Public Surface

Only `stealthlib/stealth.hpp` is the supported public header. The following secondary headers were removed from the public surface during the 1.0.0 hardening pass:

- `stealthlib/stealth_strings.hpp`
- `stealthlib/stealth_peb.hpp`
- `stealthlib/stealth_encode.hpp`
- `stealthlib/stealth_iat.hpp`

Do not include them. If you have an older copy, migrate to `#include "stealthlib/stealth.hpp"`.

---

## Threat Model

### In-Scope Attacks (StealthLib raises the bar here)

| Threat | Mitigation | Verified By |
|--------|------------|-------------|
| Casual `strings.exe` inspection of literals | `S()` / `SW()` obfuscation | `binary_scan_test` in CI |
| Static IAT analysis of commonly resolved APIs | PEB-based resolution | `peb_test`, `integration_test` |
| Forwarded-export resolution failures | Forwarded export recursion in `get_proc_impl` | `regression_test` |
| Cross-translation-unit string collisions | Per-use unique key derived from `__LINE__` and `__COUNTER__` | `regression_test` with TU A/B |
| Timing side-channels on byte comparison | `memory::compare_constant_time` | `comprehensive_test` |
| Compiler optimizing away sensitive zeroing | `memory::secure_zero` uses volatile writes / `SecureZeroMemory` | `comprehensive_test` destructor test |

### Out-of-Scope Attacks (Do not rely on StealthLib here)

| Threat | Why it is out of scope |
|--------|------------------------|
| Dynamic analysis with a debugger | Decrypted strings and resolved pointers are visible in memory |
| Kernel-level tampering | Hypervisor, kernel driver, or EDR-level bypasses operate below user-mode APIs |
| Memory dumping | Anyone with read access to the process can dump the decrypted buffer |
| Static key recovery | The XOR key is derivable from the binary and the algorithm is public |
| Side-channel attacks on execution flow | Branching on `is_debugger_present()` can be patched |
| Supply-chain / build-system compromise | Protect your build machines, CI secrets, and signing keys separately |

---

## Responsible Disclosure

If you discover a security issue in the project, please:

1. Open a private GitHub Security Advisory on the repository, or
2. Email the maintainer with a clear reproduction and impact statement.

Public disclosure before a fix is available is discouraged.

---

## Safe Use Checklist

Before shipping a binary that uses StealthLib:

- [ ] Run the full test suite: `ctest --test-dir build -C Release --output-on-failure`
- [ ] Verify the binary scan test passes in both Debug and Release.
- [ ] Ensure no real secrets are embedded in the repository or build logs.
- [ ] Combine StealthLib with other defenses (code signing, ASLR, DEP, integrity checks, server-side validation).
- [ ] Treat debugger detection as a signal, not a proof. Decide on the policy response (exit, delay, report) separately.
- [ ] Keep the library updated. Review `docs/HARDENING_REPORT.md` for known follow-up work.

---

## Reporting a Vulnerability

Please use GitHub Security Advisories for responsible disclosure. Include:

- affected version or commit
- minimal reproduction code
- observed vs expected behavior
- suggested severity and impact

---

*This document is part of the StealthLib pre-release hardening effort. It is intentionally conservative: the library is useful hardening, not magic.*
