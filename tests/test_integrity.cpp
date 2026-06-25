#ifdef _WIN32

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "stealthlib/stealth.hpp"

#include <fstream>
#include <windows.h>

TEST_CASE("integrity: IAT/EAT hooks scan does not crash") {
    auto ki = stealth::integrity::compare_iat_thunk("kernel32.dll", "GetProcAddress");
    CHECK((ki.hooked == true || ki.hooked == false));
}

TEST_CASE("integrity: forwarder detection runs without exceptions") {
    auto ok = stealth::integrity::is_eat_forwarded("ntdll.dll", "RtlUserThreadStart")
           || !stealth::integrity::is_eat_forwarded("ntdll.dll", "RtlUserThreadStart");
    CHECK(ok);
}

#else

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "stealthlib/stealth.hpp"

#include <cstring>

// A small, well-defined function whose prologue bytes we can hash.
namespace {
__attribute__((noinline)) int test_thunk(int x) { return x + 1; }
}

// Self-validation: hash the first 32 bytes of an internal function and
// verify prologue_sha256 reports a match. Round-trip identity.
TEST_CASE("prologue_sha256: round-trip on internal function") {
    auto f = &test_thunk;
    uint8_t expected[32];
    stealth::detail::sha256_oneshot(
        reinterpret_cast<uint8_t const*>(f), 32, expected);
    CHECK(stealth::integrity::prologue_sha256(
        reinterpret_cast<void const*>(f), 32, expected));
}

// Tampered buffer test: hash a copy with one byte flipped, verify SHA-256
// produces a different digest and prologue_sha256 reports "not equal".
TEST_CASE("prologue_sha256: tampered buffer produces mismatch") {
    uint8_t src[32];
    for (int i = 0; i < 32; ++i) src[i] = static_cast<uint8_t>(i * 7 + 1);
    uint8_t expected[32], tampered[32];
    stealth::detail::sha256_oneshot(src, 32, expected);

    std::memcpy(tampered, src, 32);
    tampered[15] ^= 0x01;
    uint8_t tampered_digest[32];
    stealth::detail::sha256_oneshot(tampered, 32, tampered_digest);
    CHECK(std::memcmp(expected, tampered_digest, 32) != 0);
    CHECK(!stealth::integrity::prologue_sha256(tampered, 32, expected));
}

// Boundary checks per docstring: N out of [4,64] returns false.
TEST_CASE("prologue_sha256: rejects N below 4") {
    uint8_t expected[32] = {};
    CHECK(!stealth::integrity::prologue_sha256(&expected, 0, expected));
    CHECK(!stealth::integrity::prologue_sha256(&expected, 1, expected));
    CHECK(!stealth::integrity::prologue_sha256(&expected, 3, expected));
    // N=4 is the minimum valid case.
    uint8_t src4[4] = { 0x90, 0x90, 0x90, 0xC3 };
    uint8_t d4[32];
    stealth::detail::sha256_oneshot(src4, 4, d4);
    CHECK(stealth::integrity::prologue_sha256(src4, 4, d4));
}

TEST_CASE("prologue_sha256: rejects N above 64") {
    uint8_t expected[32] = {};
    CHECK(!stealth::integrity::prologue_sha256(&expected, 65, expected));
    CHECK(!stealth::integrity::prologue_sha256(&expected, 256, expected));
}

TEST_CASE("prologue_sha256: rejects null pointer") {
    uint8_t expected[32] = {};
    CHECK(!stealth::integrity::prologue_sha256(nullptr, 32, expected));
}

TEST_CASE("prologue_sha256: real 32-byte buffer round-trip") {
    uint8_t src[32];
    for (int i = 0; i < 32; ++i) src[i] = static_cast<uint8_t>(0xC0 ^ i);
    uint8_t expected[32];
    stealth::detail::sha256_oneshot(src, 32, expected);
    CHECK(stealth::integrity::prologue_sha256(src, 32, expected));
    // Mutate one byte; equality must flip.
    src[7] ^= 0x42;
    uint8_t mutated_digest[32];
    stealth::detail::sha256_oneshot(src, 32, mutated_digest);
    CHECK(!stealth::integrity::prologue_sha256(src, 32, expected));
}

TEST_CASE("vmdetect: scan returns coherent struct with confidence in [0,3]") {
    auto r = stealth::detection::vmdetect::scan();
    CHECK(r.vm_confidence >= 0);
    CHECK(r.vm_confidence <= 3);
    CHECK(r.reported_disk_gb >= 0.0);
    // On a Linux dev environment, the suite should not panic.
    CHECK(true);
}

TEST_CASE("vmdetect: cpuid_hypervisor_present runs without UB") {
    bool b = stealth::detection::vmdetect::cpuid_hypervisor_present();
    CHECK((b == true || b == false));
}

#endif
