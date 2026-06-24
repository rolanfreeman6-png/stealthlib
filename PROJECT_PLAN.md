# StealthLib Release Plan

Updated: 2026-06-24

Status: **pre-release hardening complete**. The project is ready for a controlled public release after the GitHub repository metadata and public CI are aligned.

Repository: https://github.com/rolanfreeman6-png/stealthlib

## Related Documents

- [`docs/HARDENING_REPORT.md`](docs/HARDENING_REPORT.md) — full technical audit of what was fixed, how it was verified, competitive assessment, and remaining tasks.
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model, supported public surface, and responsible disclosure policy.
- [`docs/INSTALL.md`](docs/INSTALL.md) — build and integration instructions.
- [`docs/EXAMPLES.md`](docs/EXAMPLES.md) — example programs and use cases.

## Supported Public Surface

- `stealthlib/stealth.hpp` is the supported header.
- `S()` and `SW()` provide compile-time string obfuscation macros.
- `stealth::encoding::*` provides Base64, Hex, XOR, and ROT13 helpers.
- `stealth::memory::*` provides secure zeroing and constant-time byte comparison.
- Windows builds support PEB walking, dynamic API resolution, forwarded exports, debugger signals, `module_loader`, and `stealth_api`.

Secondary headers are not part of the documented public surface until they are either removed or rewritten as wrappers over `stealth.hpp`.

## Release Gates

### Completed

- [x] Windows MSVC Release build passes.
- [x] Windows clang/Ninja Release and Debug builds pass.
- [x] `ctest` passes on Windows and portable Linux jobs.
- [x] Binary scan test passes in Debug and Release.
- [x] Multi-translation-unit string regression passes.
- [x] Forwarded export regression passes.
- [x] README and docs avoid unverified claims.
- [x] `docs/HARDENING_REPORT.md` and `docs/SECURITY.md` added.
- [x] Old secondary headers removed from the public surface.
- [x] RelWithDebInfo binary-scan CI job added and passing locally.
- [x] GitHub repository description updated to honest pre-release positioning.
- [x] Public GitHub Actions matrix is green on `main`.
- [x] CI badges added to README after the first green public run.

### Remaining before public launch

- [ ] Make the release post with the honest framing: "not magic, but tested Windows hardening utilities."

## Current Competitive Angle

Existing C++ string obfuscation projects mostly focus on literals only. StealthLib can stand out by being a tested Windows hardening bundle:

- string obfuscation with multi-translation-unit regression coverage
- binary-scan test for plaintext sentinels
- PEB export resolver with forwarded export support
- practical secure memory helpers
- honest threat model and CI proof

## Next Hardening Work

- Convert all tests away from `assert` or keep CMake forcing assertions on for every test configuration.
- Add deterministic PE fixture tests for malformed headers and forwarded exports.
- Add badges only after the public CI is green.
- Make the release post with the honest framing: "not magic, but tested Windows hardening utilities."

See [`docs/HARDENING_REPORT.md`](docs/HARDENING_REPORT.md) for the complete remaining-tasks list and competitive assessment.

## Example API

```cpp
auto secret = S("api-key");
auto title = SW(L"Protected");

using GetTickCount_t = DWORD();
stealth::stealth_api<GetTickCount_t> tick("kernel32.dll", "GetTickCount");
if (tick) {
    auto value = tick.get()();
    (void)value;
}
```
