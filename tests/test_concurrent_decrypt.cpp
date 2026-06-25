// tests/test_concurrent_decrypt.cpp
// -----------------------------------------------------------------
// Verifies Tier 1C -- concurrent decrypt()/reencrypt() on the same
// encrypted_string must not data-race. We compile this with -fsanitize=thread
// (TSan) and expect no warnings. On non-Linux it is skipped.
// Compiled only when CMAKE_SYSTEM_NAME STREQUAL "Linux" so ASan+UBSan-only
// CI configurations don't trip on missing pthread.
// -----------------------------------------------------------------
#include "stealthlib/stealth.hpp"

#include <atomic>
#include <cstdio>
#include <thread>
#include <vector>

int main() {
    auto lit = S("STEALTHLIB_THREAD_DECRYPT_RACE_PROBE_0001");
    constexpr std::size_t iters = 2000;

    // Probe 1: bomb the same encrypted literal from N threads in lockstep.
    // TSan must see no race on the internal `decrypted` flag.
    std::atomic<int> done{0};
    std::atomic<int> errors{0};
    const std::size_t N = std::min<std::size_t>(8u,
        std::thread::hardware_concurrency() == 0 ? 1u
                                                : std::thread::hardware_concurrency());
    std::vector<std::thread> ts;
    ts.reserve(N);
    for (std::size_t t = 0; t < N; ++t) {
        ts.emplace_back([&]() {
            for (std::size_t i = 0; i < iters; ++i) {
                const char* p = *lit;
                if (!p || p[0] == '\0') ++errors;
            }
            ++done;
        });
    }
    for (auto& th : ts) th.join();

    // Probe 2: alternating decrypt/reencrypt from two threads.
    std::thread tA([&]() {
        for (std::size_t i = 0; i < iters; ++i) (void)*lit;
    });
    std::thread tB([&]() {
        for (std::size_t i = 0; i < iters / 2; ++i) {
            auto g = lit.unlock();
            (void)g;
        }
    });
    tA.join();
    tB.join();

    if (errors.load() != 0) {
        std::fprintf(stderr, "[FAIL] concurrent decrypt saw %d invalid ptrs\n",
                     errors.load());
        return 1;
    }
    std::fprintf(stderr,
        "[OK] TSan-clean: %zu threads x %zu iters, decrypt+reencrypt\n",
        N, iters);
    return 0;
}
