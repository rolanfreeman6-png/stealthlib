# Security Policy - StealthLib v2.2.2

## Scope

StealthLib is a header-only C++20 hardening utility. It offers compile-time
literal obfuscation, encoding helpers, secure zeroing, Windows loaded-module
export resolution, and best-effort debugger/VM signals.

It is not cryptography, DRM, a secure secret store, anti-debug protection, or
a guarantee that an executable contains no imports or readable strings.

## Supported security-relevant behavior

| Area | Contract | Regression coverage |
| --- | --- | --- |
| Literal obfuscation | `S()` and `SW()` use a compile-time source-location seed and a build key. They protect only those literals from the tested binary sentinel scan. | `binary_scan_test`, string tests, cross-TU regression |
| Secure erase | `memory::secure_zero` uses volatile byte stores; `secure_string::clear()` and destruction call it for payload and length. | secure-string unit/integration tests |
| Base64 decoding | Invalid characters, malformed padding, and non-canonical unused pad bits are rejected. | decoder and regression tests |
| Forwarded exports | Named and hash resolution return terminal addresses for loaded `DLL.Function` and `DLL.#Ordinal` forwarders, with an eight-hop limit. | forwarder fixture and Windows resolver tests |
| IAT comparison | A named import with valid INT metadata is compared to the resolved terminal export. Results include `clean`, `hooked`, `not_found`, or `unavailable`. | normal and deliberately patched IAT tests |

## Limitations

- XOR literal transformation is reversible from the binary.
- Plaintext exists while a literal is decrypted or unlocked.
- `S()`/`SW()` instances are thread-confined; concurrent access to one
  instance is undefined behavior.
- Hash-based resolution only searches already loaded modules. It deliberately
  does not load a forwarded-to DLL.
- IAT comparison does not verify ordinal imports, delay-load imports, imports
  without `OriginalFirstThunk`, an unavailable dependency, or malformed image
  metadata. These return `unavailable` or `not_found`, not `clean`.
- `detection::hardware_breakpoint_count()` is unknown (`-1`) for the current
  running thread. It cannot use `GetThreadContext` safely for that thread.
- All user-mode signals can be spoofed by a sufficiently privileged debugger,
  kernel component, hypervisor, or EDR.

## Responsible disclosure

Report vulnerabilities through a private GitHub Security Advisory with the
affected commit, minimal reproduction, expected and observed behavior, and
impact.
