# StealthLib Threat Model - v2.2.2

## Intended use

StealthLib can reduce casual static exposure of selected literals and remove
the need for an application's direct import of selected, already-loaded Windows
exports. It is appropriate only as one layer alongside normal platform
defenses, signing, server-side authorization, and input validation.

## What the library can check

| Signal or API | What it observes | Important boundary |
| --- | --- | --- |
| `S()` / `SW()` | A specified literal is transformed at translation time and restored into an object-local buffer. | The implementation and key derivation remain in the program; this is not encryption. |
| `get_proc*` / `stealth_api` | Named export resolution, including loaded forwarder targets. | It does not load DLLs and cannot resolve a forwarder whose target is absent. |
| `compare_iat_thunk` | One named normal import in a supplied importing image. | It needs `OriginalFirstThunk`; use `hook_status`, not only `hooked`. |
| `prologue_sha256` | Equality of a caller-selected byte range and known digest. | It cannot detect a patch outside that range or replace a disassembler. |
| `is_debugger_present`, `check_remote_debugger`, `check_timing_anomaly` | Best-effort user-mode signals. | Each can be spoofed or destabilized by a debugger/VM. |
| `hardware_breakpoint_count_for_suspended_thread` | DR7-enabled slots in a supplied suspended thread context. | Debug registers are per-thread. Current-thread count is intentionally unknown. |
| `vmdetect::scan` | CPUID bit, DMI/registry vendor text, and disk-size heuristic. | This is a QA/environment hint, not anti-virtualization. |

## Explicitly out of scope

- Kernel-mode and hypervisor adversaries.
- Memory dumps while plaintext is live.
- Protection against an analyst who can read code, patch branches, or emulate
  Windows APIs.
- Cryptographic confidentiality, authentication, signing, or tamper-proofing.
- Thread safety for a shared encrypted-literal object.
- Full import-table, delay-load, ordinal-import, or file-format validation.

## Safe composition

Treat every detection result as one input to an application policy. Do not
make irreversible security decisions from one anti-debug or VM signal. Check
the status result from integrity APIs before acting on a negative finding, and
keep decrypted strings in the smallest practical scope.
