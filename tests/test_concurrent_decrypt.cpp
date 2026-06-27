// tests/test_concurrent_decrypt.cpp
// -----------------------------------------------------------------
// Threading contract verification for encrypted_string (Variant B).
//
// Contract (docs/THREADING.md): each S("...")/SW(L"...") instance MUST
// be confined to a single thread. Concurrent decrypt()/reencrypt() on
// the SAME instance is a data race (UB). The harness below therefore
// gives every thread its OWN literal and uses a start-gun barrier so the
// inner loops interleave tightly; there is NO shared mutable state
// between threads, so ThreadSanitizer must report zero races. Run under
// -fsanitize=thread and expect a clean exit. On non-x86/non-pthread
// toolchains it still builds and runs as a correctness smoke test.
//
// Adversarial probe: compile with -DSTEALTH_ADVERSARIAL_RACE_PROBE to
// additionally exercise the FORBIDDEN pattern (one shared instance across
// two threads). Under TSan that probe is EXPECTED to report a race on
// buffer[]/encrypted[] -- it proves the contract is real and that the
// detector can see I-5. It is compiled out by default so ctest/CI stay
// green; enable it only for an explicit TSan validation run.
// -----------------------------------------------------------------
#include "stealthlib/stealth.hpp"

#include <atomic>
#include <cstdio>
#include <thread>
#include <vector>

int main() {
    constexpr std::size_t iters = 2000;
    std::atomic<int> errors{0};

    // Contract-respecting harness: per-thread instances + start-gun.
    std::atomic<int> ready{0};
    const std::size_t N = std::min<std::size_t>(8u,
        std::thread::hardware_concurrency() == 0 ? 1u
                                                 : std::thread::hardware_concurrency());
    std::vector<std::thread> ts;
    ts.reserve(N);
    for (std::size_t t = 0; t < N; ++t) {
        ts.emplace_back([&]() {
            auto lit = S("STEALTHLIB_THREAD_DECRYPT_RACE_PROBE_0001");
            while (ready.load(std::memory_order_acquire) == 0) {}
            for (std::size_t i = 0; i < iters; ++i) {
                const char* p = *lit;
                if (!p || p[0] == '\0') ++errors;
                // Periodically toggle decrypt/reencrypt on THIS thread's
                // own instance (never on a shared one).
                if ((i & 0x3F) == 0) { auto g = lit.unlock(); (void)g; }
            }
        });
    }
    ready.store(1, std::memory_order_release);
    for (auto& th : ts) th.join();

    if (errors.load() != 0) {
        std::fprintf(stderr, "[FAIL] concurrent decrypt saw %d invalid ptrs\n",
                     errors.load());
        return 1;
    }
    std::fprintf(stderr,
        "[OK] TSan-clean: %zu threads x %zu iters, per-thread decrypt+reencrypt\n",
        N, iters);

#ifdef STEALTH_ADVERSARIAL_RACE_PROBE
    // FORBIDDEN usage by design: one instance shared across two threads.
    // Under TSan this MUST race (I-5). We do not assert on the outcome --
    // TSan itself aborts the process with a race report, which is the
    // signal that the contract violation is observable.
    std::atomic<int> go{0};
    auto shared = S("RACE_PROBE_GUARDED_INTERLEAVE_LONG_ENOUGH_FOR_SSE2");
    std::thread a([&]{
        while (go.load(std::memory_order_acquire) == 0) {}
        for (int i = 0; i < 100000; ++i) { (void)*shared; }
    });
    std::thread b([&]{
        while (go.load(std::memory_order_acquire) == 0) {}
        for (int i = 0; i < 100000; ++i) { auto g = shared.unlock(); (void)g; }
    });
    go.store(1, std::memory_order_release);
    a.join();
    b.join();
    std::fprintf(stderr,
        "[ADVERSARIAL] shared-instance probe completed (race expected under TSan)\n");
#endif

    return 0;
}
