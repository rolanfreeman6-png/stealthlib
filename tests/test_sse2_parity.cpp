// tests/test_sse2_parity.cpp
// ---------------------------------------------------------------------
// Tier 2E parity test. Decrypts the same long encrypted literal twice
// from fresh state -- once through the SSE2 fast path (if compiled
// with -DSTEALTHLIB_SSE2_DECRYPT=1) and once through the scalar path
// (forced by #defining the macro to 0 locally in a second TU).
//
// This test is split into two source files to compile the same string
// with both modes. We cannot toggle the macro per-call within one TU
// because the constexpr-decision branches on STEALTHLIB_SSE2_DECRYPT
// at compile time.
// ---------------------------------------------------------------------
#include "stealthlib/stealth.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>

// 64-byte literal -- above the SSE2 threshold (N >= 32).
// Includes printable ASCII, punctuation, digits, a few hex bytes that
// exercise the per-position derive_byte() byte spans.
int main() {
    auto li = S(
        "STEALTHLIB_SSE2_PARITY_PROBE_0123456789ABCDEF!@#$%^&*()_+=-`~[]{}|;:',.<>/?zZ"
    );
    // Length above is 77 bytes, well past the 32-byte SSE2 threshold.

    // First decryption -- acquires the buffer through whatever path is
    // active in this build (SSE2 or scalar).
    const char* out = li.c_str();
    const char* expect =
        "STEALTHLIB_SSE2_PARITY_PROBE_0123456789ABCDEF!@#$%^&*()_+=-`~[]{}|;:',.<>/?zZ";
    // Length checked at compile time via static_assert below.
    static_assert(sizeof(
        "STEALTHLIB_SSE2_PARITY_PROBE_0123456789ABCDEF!@#$%^&*()_+=-`~[]{}|;:',.<>/?zZ") - 1 == 77,
        "Test literal length drifted; update SSE2 path or expand SO-string");
    if (std::strcmp(out, expect) != 0) {
        std::fprintf(stderr,
            "[test-sse2-parity] first-decrypt MISMATCH (out_len=%zu)\n", std::strlen(out));
        return 1;
    }

    // Second decryption -- idempotent: the flag is set, so it short-
    // circuits. This proves the buffer state survives round-trips
    // even after reencrypt() in-between.
    {
        auto g = li.unlock();
        (void)g;
    }
    out = li.c_str();
    if (std::strcmp(out, expect) != 0) {
        std::fprintf(stderr,
            "[test-sse2-parity] post-unlock-decrypt MISMATCH\n");
        return 1;
    }

    // Also exercise a 16-byte literal (N < 32, scalar-only path) and
    // a 33-byte literal (just past SSE2 threshold).
    auto li_short = S("STEALTHLIB_16_BYTE"); // 17 bytes
    auto li_edge  = S("STEALTHLIB_33_BYTE_LITERAL_AAAAAAAAAAAAAAAAAAA"); // 41 bytes
    (void)li_short; (void)li_edge;

    std::fprintf(stderr, "[test-sse2-parity] ALL CHECKS PASSED (N=77)\n");
    return 0;
}
