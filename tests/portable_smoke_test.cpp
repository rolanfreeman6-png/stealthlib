#include "stealthlib/stealth.hpp"

#include <cassert>
#include <cstring>
#include <string>
#include <array>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

int main() {
    // Known-answer: base64
    assert(stealth::encoding::base64_encode("test") == "dGVzdA==");  // NOSONAR
    assert(stealth::encoding::base64_encode("Hello, World!") == "SGVsbG8sIFdvcmxkIQ==");  // NOSONAR
    assert(stealth::encoding::base64_encode("") == "");  // NOSONAR

    // Known-answer: hex
    assert(stealth::encoding::hex_encode("test") == "74657374");  // NOSONAR
    assert(stealth::encoding::hex_encode("ABC") == "414243");  // NOSONAR

    // Known-answer: rot13
    std::array<char, 16> rot_buf{};
    stealth::encoding::rot13_encode(rot_buf.data(), "Hello", 5);
    rot_buf[5] = 0;
    assert(std::strcmp(rot_buf.data(), "Uryyb") == 0);

    // Known-answer: secure_zero — verify actual zeroing
    std::array<char, 8> sz{};
    std::memset(sz.data(), 0xFF, 8);
    stealth::memory::secure_zero(sz.data(), 8);
    for (char c : sz) assert(c == 0);

    // Known-answer: compare_constant_time
    assert(stealth::memory::compare_constant_time("abc", "abc", 3));
    assert(!stealth::memory::compare_constant_time("abc", "abd", 3));
    assert(stealth::memory::compare_constant_time("abc", "abc", 0));
    assert(!stealth::memory::compare_constant_time(nullptr, "abc", 1));

    // Known-answer: FNV hashes
    static_assert(stealth::hashes::fnv("hello") == 0xa430d84680aabd0bULL);
    static_assert(stealth::hashes::fnv("test") == 0xf9e6e6ef197c2b25ULL);
    static_assert(stealth::hashes::fnv("") == 0xcbf29ce484222325ULL);
    static_assert(stealth::hashes::djb2("hello", 5) == 0x000000310f923099ULL);
    assert(stealth::hashes::runtime("hello") == 0xa430d84680aabd0bULL);

    // Known-answer: SHA-256 of empty string
    {
        std::array<uint8_t, 32> digest{};
        stealth::detail::sha256_oneshot(nullptr, 0, digest.data());
        constexpr std::array<uint8_t, 32> expected{
            0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,
            0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
            0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
            0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
        };
        assert(std::memcmp(digest.data(), expected.data(), 32) == 0);
    }

    // Known-answer: xor_crypt specific output
    {
        stealth::encoding::xor_key<4> xkey("key");
        std::array<uint8_t, 4> xd{0x41, 0x41, 0x41, 0x41};
        stealth::encoding::xor_encode(xd.data(), 4, xkey);
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
