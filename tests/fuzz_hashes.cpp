// libFuzzer harness for StealthLib public API.
#include "stealthlib/stealth.hpp"

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0 || size > 4096) return 0;

    // FNV vs DJB2 may equal on extremely short inputs by coincidence.
    // For inputs of size >= 2, they MUST differ.
    if (size >= 2) {
        uint64_t a = stealth::hashes::fnv(data, size);
        uint64_t b = stealth::hashes::djb2(data, size);
        if (a == b) {
            std::fprintf(stderr,
                "FNV/DJB2 collision on %zu bytes: 0x%016llx vs 0x%016llx\n",
                size, (unsigned long long)a, (unsigned long long)b);
            std::abort();
        }
    }

    // FNV/payload must equal FNV/(payload+NUL) IF payload is already NUL
    // terminated. We pad with NUL only when feasible (size+1 <= capacity).
    // The libc FNV runtime walks reads until it sees a zero; if the fuzz
    // input has no zero within the first `size` bytes, we must skip
    // the comparison to avoid a read-out-of-bounds.
    bool terminate_in_bounds = false;
    for (size_t i = 0; i < size; ++i) {
        if (data[i] == 0) { terminate_in_bounds = true; break; }
    }
    if (terminate_in_bounds) {
        uint64_t f1 = stealth::hashes::fnv(data, size);
        uint64_t f2 = stealth::hashes::runtime(reinterpret_cast<const char*>(data));
        if (f1 != f2) {
            std::fprintf(stderr,
                "fnv identity failure on %zu bytes: %016llx vs runtime %016llx\n",
                size, (unsigned long long)f1, (unsigned long long)f2);
            std::abort();
        }
    }

    // SHA-256 streaming boundary: feed 30 + 70 against one-shot of 100.
    if (size == 100) {
        uint8_t one_shot[32];
        stealth::detail::sha256_oneshot(data, 100, one_shot);
        stealth::detail::sha256 s;
        s.update(data, 30);
        s.update(data + 30, 70);
        uint8_t streamed[32];
        s.finalise(streamed);
        if (std::memcmp(one_shot, streamed, 32) != 0) {
            std::fprintf(stderr, "SHA-256 streaming parity failure\n");
            std::abort();
        }
    }
    return 0;
}

#ifndef STEALTH_LIBFUZZER_LINKED
int main() {
    // Each seed goes through with its actual byte count. We deliberately
    // include a seed with zero internal NUL to ensure the runtime-comparison
    // branch is *skipped* (not crashing).
    const uint8_t b_abc[]   = {'a','b','c', 0};
    const uint8_t b_the[]   = {'T','h','e',' ', 0};
    const uint8_t b_long[]  = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
        0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
        0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,
        0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
        0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,0x30,
    };
    struct seed_t { const uint8_t* p; std::size_t n; };
    const seed_t seeds[] = {
        { b_abc,   3 },     // no NUL in payload -> runtime branch skipped
        { b_the,   4 },     // ditto
        { b_long,  48 },    // ditto
    };
    int failures = 0;
    for (auto const& s : seeds) {
        int rc = LLVMFuzzerTestOneInput(s.p, s.n);
        if (rc != 0) ++failures;
    }
    return failures ? 1 : 0;
}
#endif
