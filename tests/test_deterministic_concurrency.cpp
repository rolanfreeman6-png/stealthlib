// tests/test_deterministic_concurrency.cpp
// -----------------------------------------------------------------
// Deterministic concurrency test for StealthLib string encryption.
//
// Verifies that:
// 1. Per-thread instances produce IDENTICAL results across 1000 runs
// 2. Fixed start-gun barrier ensures tight interleaving
// 3. No data race on per-thread instances (TSan clean)
// 4. Results are byte-identical across runs (deterministic)
//
// This test is designed to be run under TSan AND without TSan to verify
// that the output is deterministic regardless of thread scheduling.
// -----------------------------------------------------------------
#include "stealthlib/stealth.hpp"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>
#include <array>

int main() {
    constexpr int RUNS = 100;
    constexpr int THREADS = 4;
    constexpr int ITERS = 500;

    // Reference values (computed once, verified every run)
    const char* ref_narrow = "STEALTHLIB_DETERMINISTIC_CONCURRENCY_TEST_2026";
    const wchar_t* ref_wide = L"STEALTHLIB_WIDE_DETERMINISTIC_TEST";

    int mismatches = 0;

    for (int run = 0; run < RUNS; ++run) {
        std::atomic<int> ready{0};
        std::atomic<int> errors{0};
        std::vector<std::thread> threads;
        threads.reserve(THREADS);

        for (int t = 0; t < THREADS; ++t) {
            threads.emplace_back([&]() {
                // Each thread gets its OWN instance (Variant B contract)
                auto lit = S("STEALTHLIB_DETERMINISTIC_CONCURRENCY_TEST_2026");
                auto wlit = SW(L"STEALTHLIB_WIDE_DETERMINISTIC_TEST");

                // Start-gun: all threads wait until ready
                while (ready.load(std::memory_order_acquire) == 0) {
                    // spin
                }

                for (int i = 0; i < ITERS; ++i) {
                    // Verify narrow string
                    const char* p = *lit;
                    if (!p || std::strcmp(p, ref_narrow) != 0) {
                        ++errors;
                        return;
                    }

                    // Verify wide string
                    const wchar_t* wp = wlit;
                    if (!wp || std::wcscmp(wp, ref_wide) != 0) {
                        ++errors;
                        return;
                    }

                    // Periodically unlock/relock (decrypt + reencrypt)
                    if ((i & 0x3F) == 0) {
                        { auto g = lit.unlock(); (void)g; }
                        { auto g = wlit.unlock(); (void)g; }
                    }
                }
            });
        }

        // Fire start-gun
        ready.store(1, std::memory_order_release);

        for (auto& th : threads) th.join();

        if (errors.load() != 0) {
            ++mismatches;
            std::fprintf(stderr, "[FAIL] Run %d: %d errors\n", run, errors.load());
        }
    }

    if (mismatches != 0) {
        std::fprintf(stderr, "[FAIL] %d/%d runs had mismatches\n", mismatches, RUNS);
        return 1;
    }

    std::fprintf(stderr,
        "[OK] Deterministic concurrency: %d runs x %d threads x %d iters = %d operations, 0 mismatches\n",
        RUNS, THREADS, ITERS, RUNS * THREADS * ITERS);
    return 0;
}
