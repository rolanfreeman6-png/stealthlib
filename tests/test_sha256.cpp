// Phase A2.5 — SHA-256 self-test against FIPS-180-4 known answer vectors.
// Empty string, "abc", and the longer NIST test vector must produce
// these exact 32-byte digests.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "stealthlib/stealth.hpp"

#include <cstdio>
#include <cstring>

namespace {

void hex(const uint8_t* d, char* out) {
    static const char hex_chars[] = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        out[i*2]   = hex_chars[(d[i] >> 4) & 0x0F];
        out[i*2+1] = hex_chars[d[i] & 0x0F];
    }
    out[64] = '\0';
}

} // namespace

TEST_CASE("SHA-256 self-test: empty string KAT") {
    uint8_t d[32];
    stealth::detail::sha256_oneshot(reinterpret_cast<const uint8_t*>(""), 0, d);
    char h[65];
    hex(d, h);
    CHECK(std::strcmp(h,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
}

TEST_CASE("SHA-256 self-test: \"abc\" KAT") {
    const char* msg = "abc";
    uint8_t d[32];
    stealth::detail::sha256_oneshot(
        reinterpret_cast<const uint8_t*>(msg), 3, d);
    char h[65];
    hex(d, h);
    CHECK(std::strcmp(h,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);
}

TEST_CASE("SHA-256 self-test: 448-bit NIST vector KAT") {
    // NIST SHA-256 long-message test vector.
    const char* msg =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    uint8_t d[32];
    stealth::detail::sha256_oneshot(
        reinterpret_cast<const uint8_t*>(msg), 56, d);
    char h[65];
    hex(d, h);
    CHECK(std::strcmp(h,
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0);
}

TEST_CASE("SHA-256 streaming matches one-shot for the same input") {
    const char* msg =
        "The quick brown fox jumps over the lazy dog"; // 43 bytes
    uint8_t one_shot[32], streamed[32];
    stealth::detail::sha256_oneshot(
        reinterpret_cast<const uint8_t*>(msg),
        std::strlen(msg), one_shot);

    stealth::detail::sha256 s;
    // Feed one byte at a time.
    for (std::size_t i = 0; i < std::strlen(msg); ++i) {
        uint8_t b = static_cast<uint8_t>(msg[i]);
        s.update(&b, 1);
    }
    s.finalise(streamed);

    CHECK(std::memcmp(one_shot, streamed, 32) == 0);
}

TEST_CASE("SHA-256 streaming boundary: update that crosses the 64-byte block") {
    // 100-byte input fed as 30 + 70 to exercise the buf_used boundary.
    std::vector<uint8_t> msg(100, 0xA5);
    uint8_t one_shot[32], streamed[32];
    stealth::detail::sha256_oneshot(msg.data(), msg.size(), one_shot);

    stealth::detail::sha256 s;
    s.update(msg.data(), 30);
    s.update(msg.data() + 30, 70);
    s.finalise(streamed);

    CHECK(std::memcmp(one_shot, streamed, 32) == 0);
}
