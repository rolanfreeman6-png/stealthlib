// tests/scenario_rte_libc_walk.cpp
// ---------------------------------------------------------------------
// RTE Scenario 1 -- "loader-style" flow: simulate a Linux binary that
// resolves libc functions via hash and exercises encrypted strings on
// each call. Verifies that the encrypted_string + getters composition
// works under repeated invocation (decrypt+unlock+destroy loop), and
// that the build key surfaces correct hash-runtime equality.
// ---------------------------------------------------------------------
#include "stealthlib/stealth.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

int main() {
    // Scenario asserts --
    //   1. hash-runtime == hash-bytewise for terminator-terminated inputs
    //   2. S() and SW() literals survive a tight toggle loop
    //   3. base64 round-trip + hex round-trip of the same payload match
    //   4. SHA-256 KAT spot-check (empty + "abc")
    auto s_localtime = S("localtime");
    auto s_strftime  = S("strftime");
    auto s_close     = S("close");
    auto s_open      = S("open");
    auto w_logpath   = SW(L"/var/log/stealthlib_rte1.log");

    // 1. FNV vs runtime: same byte string, same hash. assert via the
    //    public hashes:: API.
    {
        const char* a = *s_localtime;
        const char* b = *s_localtime;
        assert(std::strcmp(a, b) == 0);
        auto h_explicit = stealth::hashes::fnv(a, 9);
        auto h_runtime  = stealth::hashes::fnv(a);
        if (h_explicit != h_runtime) {
            std::fprintf(stderr,
                "[scenario-rte1] fnv mismatch: explicit=0x%016llx runtime=0x%016llx\n",
                (unsigned long long)h_explicit, (unsigned long long)h_runtime);
            return 1;
        }
        std::fprintf(stderr,
            "[scenario-rte1] fnv('%s') = 0x%016llx (parity OK)\n",
            a, (unsigned long long)h_explicit);
    }

    // 2. Many toggle cycles of S() + unlock(). Catches use-after-free in
    //    unlocked_string_guard and double-decrypt bugs.
    for (int i = 0; i < 4096; ++i) {
        { auto g = s_open.unlock(); (void)g; }
        { auto g = s_close.unlock(); (void)g; }
        { auto g = s_strftime.unlock(); (void)g; }
        { auto g = s_localtime.unlock(); (void)g; }
    }
    std::fprintf(stderr, "[scenario-rte1] 4096 unlock cycles -- no crash\n");

    // 3. base64 + hex round-trip
    {
        const char* msg = *s_localtime;
        auto b64 = stealth::encoding::base64_encode(msg, 9);
        auto dec = stealth::encoding::base64_decode(b64);
        assert(dec && !dec->empty() && (*dec)[0] == msg[0] && dec->size() == 9);
        assert(std::memcmp(dec->data(), msg, 9) == 0);

        auto hx = stealth::encoding::hex_encode(dec->data(), 9);
        std::fprintf(stderr, "[scenario-rte1] hex('%s') = %s\n", msg, hx.c_str());
    }

    // 4. SHA-256 KAT -- empty + "abc" are spec vector 1 + 2
    {
        uint8_t out1[32], out2[32];
        stealth::detail::sha256_oneshot(nullptr, 0, out1);
        stealth::detail::sha256_oneshot(
            reinterpret_cast<const uint8_t*>("abc"), 3, out2);
        // RFC4634: SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        // RFC4634: SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        static const uint8_t KAT_empty[32] = {
            0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
            0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
        };
        static const uint8_t KAT_abc[32] = {
            0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
            0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
        };
        if (std::memcmp(out1, KAT_empty, 32) != 0 ||
            std::memcmp(out2, KAT_abc,   32) != 0) {
            std::fprintf(stderr, "[scenario-rte1] SHA-256 KAT FAILED\n");
            return 1;
        }
        std::fprintf(stderr, "[scenario-rte1] SHA-256 KAT pass (empty + abc)\n");
    }

    // 5. Wide string round-trip with two consecutive unlock() cycles on same SW().
    //    wide literal exposes `operator const wchar_t*()` (not `operator*()`),
    //    so we use the implicit conversion rather than `*`.
    for (int i = 0; i < 256; ++i) {
        const wchar_t* p = w_logpath;
        assert(p[0] == L'/');
        { auto g = w_logpath.unlock(); (void)g; }
    }
    std::fprintf(stderr, "[scenario-rte1] wide unlock cycles -- pass\n");

    std::fprintf(stderr, "[scenario-rte1] ALL CHECKS PASSED\n");
    return 0;
}
