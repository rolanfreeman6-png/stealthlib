#include "stealthlib/stealth.hpp"

#include <cassert>
#include <cstring>
#include <string>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

int main() {
    // Known-answer: base64
    assert(stealth::encoding::base64_encode("test") == "dGVzdA==");
    assert(stealth::encoding::base64_encode("Hello, World!") == "SGVsbG8sIFdvcmxkIQ==");
    assert(stealth::encoding::base64_encode("") == "");

    // Known-answer: hex
    assert(stealth::encoding::hex_encode("test") == "74657374");
    assert(stealth::encoding::hex_encode("ABC") == "414243");

    // Known-answer: rot13
    char rot_buf[16] = {};
    stealth::encoding::rot13_encode(rot_buf, "Hello", 5);
    rot_buf[5] = 0;
    assert(std::strcmp(rot_buf, "Uryyb") == 0);

    // Known-answer: secure_zero — verify actual zeroing
    char sz[8];
    std::memset(sz, 0xFF, 8);
    stealth::memory::secure_zero(sz, 8);
    for (int i = 0; i < 8; ++i) assert(sz[i] == 0);

    // Known-answer: compare_constant_time
    assert(stealth::memory::compare_constant_time("abc", "abc", 3));
    assert(!stealth::memory::compare_constant_time("abc", "abd", 3));
    assert(stealth::memory::compare_constant_time("abc", "abc", 0));
    assert(!stealth::memory::compare_constant_time(nullptr, "abc", 1));

    // Known-answer: FNV hashes
    assert(stealth::hashes::fnv("hello") == 0xa430d84680aabd0bULL);
    assert(stealth::hashes::fnv("test") == 0xf9e6e6ef197c2b25ULL);
    assert(stealth::hashes::fnv("") == 0xcbf29ce484222325ULL);
    assert(stealth::hashes::djb2("hello", 5) == 0x000000310f923099ULL);
    assert(stealth::hashes::runtime("hello") == 0xa430d84680aabd0bULL);

    // Known-answer: SHA-256 of empty string
    {
        uint8_t digest[32];
        stealth::detail::sha256_oneshot(nullptr, 0, digest);
        const uint8_t expected[] = {
            0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,
            0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
            0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
            0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
        };
        assert(std::memcmp(digest, expected, 32) == 0);
    }

    // Known-answer: xor_crypt specific output
    {
        stealth::encoding::xor_key<4> xkey("key");
        uint8_t xd[] = {0x41, 0x41, 0x41, 0x41};
        stealth::encoding::xor_encode(xd, 4, xkey);
        assert(xd[0] == 0x2a);
        assert(xd[1] == 0x24);
        assert(xd[2] == 0x38);
        assert(xd[3] == 0x2a);
    }

    {
        auto secret = S("portable_secret");
        assert(std::strcmp(secret, "portable_secret") == 0);
    }

    {
        auto encoded = stealth::encoding::base64_encode("portable");
        auto decoded = stealth::encoding::base64_decode(encoded);
        assert(decoded.has_value());
        assert(std::string(decoded->begin(), decoded->end()) == "portable");
    }

    {
        auto hex = stealth::encoding::hex_encode("ok");
        auto raw = stealth::encoding::hex_decode(hex);
        assert(raw.has_value());
        assert(raw->size() == 2);
        assert((*raw)[0] == 'o');
        assert((*raw)[1] == 'k');
    }

    assert(stealth::memory::compare_constant_time("aa", "aa", 2));
    assert(!stealth::memory::compare_constant_time("aa", "ab", 2));

    // Call detection but do not assert its return value
    // (a CI runner may or may not be traced).
#ifdef _WIN32
    (void)stealth::detection::is_debugger_present();
#else
    (void)false;
#endif
    return 0;
}
