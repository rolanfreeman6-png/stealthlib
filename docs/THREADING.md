# StealthLib — Threading Contract

**Applies to:** `stealth::stealth_encrypted_char` / `stealth_encrypted_wchar`
(produced by the `S("...")` / `SW(L"...")` macros) and the
`detail::encrypted_string_impl` / `encrypted_wstring_impl` they wrap.

**Version:** v2.1.2 (introduced with the I-5 fix; supersedes the implicit
and incorrect "atomic flag = thread-safe" claim of v2.1.2).

---

## 1. The contract (Variant B: per-instance thread confinement)

Each encrypted-string instance **MUST be confined to a single thread of
execution.** Concurrent `decrypt()` / `reencrypt()` / `operator*()` /
`c_str()` / `unlock()` calls on the **same instance** from multiple
threads are a **data race — undefined behaviour**.

There is **no internal synchronisation** of the instance's `buffer[]` or
`encrypted[]` arrays. The `decrypted` flag is a plain `bool` used only to
make single-threaded lazy decrypt idempotent; it is **not** an atomic and
provides **no** cross-thread happens-before relationship.

### Safe usage

```cpp
// One instance per thread — always safe.
void worker() {
    auto key = S("API_KEY");          // local; confined to this thread
    use(*key);                        // decrypt() on this thread
    { auto g = key.unlock(); ... }    // reencrypt() on this thread
}
```

```cpp
// A function-local static is fine as long as only one thread calls the
// function (or the caller serialises calls). The static itself is
// constant-initialised (consteval ctor), so its initial encrypted state
// is shared/read-only; only the lazy decrypt mutates per-call state.
const char* get_secret() {
    static auto s = S("secret");      // consteval-init, no race on init
    return s;                         // racy only if called concurrently
}
```

### Unsafe usage (data race)

```cpp
auto shared = S("RACE");
std::thread a([&]{ for (...) (void)*shared; });   // UB: shared across threads
std::thread b([&]{ for (...) { auto g = shared.unlock(); } }); // UB
```

If you must share one logical secret across threads, give **each thread
its own instance** (re-invoke the macro in each thread) — the ciphertext
is constant-initialised and identical across instances, so this is cheap
and race-free.

---

## 2. Why Variant B (and not A or C)

The protected invariant is that `S("...")` / `SW(L"...")` stay
**constexpr-eligible** so the plaintext literal is consumed at translation
time and never lands in `.rodata` (verified by `tests/binary_scan.cmake`).
This requires the implementation structs to remain **literal types** with
a `consteval`/`constexpr` constructor.

| Variant | Mechanism | Literal type / `.rodata` elision | Cross-thread safe | API break | Chosen? |
|---|---|---|---|---|---|
| **A** | `std::mutex` per instance | **Lost** (mutex is non-literal) → literals leak | yes | no | no — breaks the central invariant |
| **B** | thread-local confinement contract | **Preserved** | no (UB if violated) | no | **yes** |
| **C** | per-call scratch buffer, `decrypt()` returns owned storage | preserved | yes | **yes** (`decrypt()` no longer returns `const char*` to shared storage) | no — ABI/API break for users |

**Variant B is the minimum-destructive choice:** it preserves the
`.rodata`-elision invariant, the literal-type property, the `consteval`
ctor, and the existing `S()/SW()/unlock()` API. Its cost is a documented
**responsibility shift** to the caller: do not share one instance across
threads. This is the same model used by comparable compile-time string
obfuscators (e.g. xorstr), whose instances are also short-lived locals.

The v2.1.2 code used GCC/Clang `__atomic_*` builtins on the `decrypted`
flag. That was **incorrect**: it fenced only the flag, not `buffer[]` /
`encrypted[]`, so it gave a false impression of thread safety while the
real races (concurrent `buffer[]` writes, decrypt-vs-reencrypt on
`encrypted[]`) remained. Variant B makes the non-guarantee explicit and
removes the non-portable builtins (which also blocked MSVC — see
AUDIT_v2.1.2 C-5).

---

## 3. Happens-before summary

- **Within one thread:** `decrypt()` (sets `decrypted=true` after writing
  `buffer[]`) happens-before a later `reencrypt()` (reads `decrypted`,
  restores `encrypted[]`, zeroes `buffer[]`, sets `decrypted=false`),
  which happens-before a subsequent `decrypt()`. This is normal
  program-order sequencing; no atomics are needed.
- **Across threads:** none. The library establishes **no**
  inter-thread happens-before edge for any instance. Cross-thread access
  to one instance has no defined ordering and is a data race.

---

## 4. Operations classified

| Operation | Single-thread | Same instance across threads |
|---|---|---|
| `S("...")` / `SW(L"...")` construction | safe (consteval, constant-init) | safe — construction is immutable; only later lazy state is per-instance |
| `operator const char*()` / `c_str()` / `operator*()` (lazy decrypt) | safe | **UB** (race on `buffer[]` / `decrypted`) |
| `unlock()` (decrypt + schedule reencrypt) | safe | **UB** |
| `reencrypt()` (via guard dtor) | safe | **UB** (race on `encrypted[]` / `buffer[]`) |
| `size()` (constexpr, reads `N` only) | safe | safe (no mutable access) |

`stealth::secure_string<MaxSize>`, the `encoding::*`, `memory::*`,
`hashes::*`, and `detail::sha256` helpers are stateless or operate on
caller-owned buffers; they are safe to call concurrently **on distinct
buffers**, and share no mutable state.

---

## 5. Reference test

`tests/test_concurrent_decrypt.cpp` is the reference for this contract.

- **Default (ctest / CI):** every thread owns its own `S(...)` instance
  plus a start-gun (`std::atomic<int> ready`) barrier for tight
  interleaving. There is no shared mutable state between threads, so
  ThreadSanitizer reports **zero** races. This is the harness run by the
  `linux-tsan` CI job (quickverify.sh runs ASan+UBSan, not TSan); it must
  stay race-free indefinitely.

- **Adversarial probe (`-DSTEALTH_ADVERSARIAL_RACE_PROBE`):** an opt-in
  (compiled out by default) block shares one instance across two threads
  with a start-gun. Under TSan this **is expected to report a race** on
  `buffer[]`/`encrypted[]` — it proves the contract is real (the
  forbidden pattern is detectable) and that the clean harness is not
  passing for the wrong reason. Enable it only for an explicit TSan
  validation run, never in the default ctest.

### How to run the TSan validation

```sh
clang++ -std=c++20 -O1 -fsanitize=thread -g \
  -DSTEALTH_BUILD_KEY=0xC0FFEE42DEADBEEFULL -I . \
  tests/test_concurrent_decrypt.cpp -o tsan_clean -lpthread
./tsan_clean            # expect: [OK] TSan-clean, exit 0

clang++ -std=c++20 -O1 -fsanitize=thread -g \
  -DSTEALTH_BUILD_KEY=0xC0FFEE42DEADBEEFULL -DSTEALTH_ADVERSARIAL_RACE_PROBE \
  -I . tests/test_concurrent_decrypt.cpp -o tsan_adv -lpthread
./tsan_adv              # expect: TSan race report (contract violation shown)
```
