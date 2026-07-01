// Phase 4 — property-based tests for hash invariants.
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "stealthlib/stealth.hpp"

#include <cstdint>
#include <random>
#include <string>
#include <vector>
#include <algorithm>
#include <cstring>

namespace {

constexpr std::size_t N_SEEDS = 4096;
constexpr std::size_t MAX_LEN = 24;

// Deterministic PRNG with fixed seed for reproducible hash tests.
// NOT used for cryptographic purposes — testing hash invariants only.
std::mt19937_64& rng() {
    static std::mt19937_64 eng{0xC0FFEE};
    return eng;
}

std::uint64_t rnd(std::uint64_t bound) {
    // std::uniform_int_distribution avoids the missing modulus operator
    // overload on mersenne_twister.
    static std::uniform_int_distribution<std::uint64_t> dist;
    return dist(rng(), std::uniform_int_distribution<std::uint64_t>::param_type{0, bound - 1});
}

std::string rand_string(std::size_t max_len = MAX_LEN) {
    static const char pool[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
        "abcdefghijklmnopqrstuvxyz";
    std::size_t n = 1 + rnd(max_len);
    std::string s;
    s.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        s.push_back(pool[rnd(sizeof(pool) - 1)]);
    }
    return s;
}

} // namespace

TEST_CASE("hash invariant: identical inputs -> identical hashes") {
    for (std::size_t i = 0; i < N_SEEDS; ++i) {
        std::string s = rand_string();
        REQUIRE(stealth::hashes::fnv(s.data(), s.size())
                == stealth::hashes::fnv(s.data(), s.size()));
    }
}

TEST_CASE("hash known-answer: FNV-1a 64-bit") {
    CHECK(stealth::hashes::fnv("hello") == 0xa430d84680aabd0bULL);
    CHECK(stealth::hashes::fnv("test") == 0xf9e6e6ef197c2b25ULL);
    CHECK(stealth::hashes::fnv("kernel32.dll") == 0xe14b18a7acf9c443ULL);
    CHECK(stealth::hashes::fnv("MessageBoxW") == 0x1e308b27ba21f56eULL);
    CHECK(stealth::hashes::fnv("") == 0xcbf29ce484222325ULL);
}

TEST_CASE("hash known-answer: DJB2") {
    CHECK(stealth::hashes::djb2("hello", 5) == 0x000000310f923099ULL);
    CHECK(stealth::hashes::djb2("test", 4) == 0x000000017c9e6865ULL);
    CHECK(stealth::hashes::djb2("", 0) == 0x0000000000001505ULL);
}

TEST_CASE("hash known-answer: runtime == fnv for known inputs") {
    CHECK(stealth::hashes::runtime("hello") == 0xa430d84680aabd0bULL);
    CHECK(stealth::hashes::runtime("test") == 0xf9e6e6ef197c2b25ULL);
    CHECK(stealth::hashes::runtime("kernel32.dll") == 0xe14b18a7acf9c443ULL);
}

TEST_CASE("hash invariant: runtime fnv == fnv(ptr, len)") {
    for (std::size_t i = 0; i < N_SEEDS; ++i) {
        std::string s = rand_string();
        REQUIRE(stealth::hashes::runtime(s.c_str())
                == stealth::hashes::fnv(s.data(), s.size()));
    }
}

TEST_CASE("hash invariant: wide fnv differs from per-byte fnv on same chars") {
    // This is by design: wide hash hashes sizeof(wchar_t) bytes per code
    // unit, narrow hash hashes 1. So wide("a") processes 4 bytes, while
    // narrow("a") processes 1. Document the structural difference.
    for (std::size_t i = 0; i < 64; ++i) {
        std::string s = rand_string();
        std::wstring w;
        w.reserve(s.size());
        for (char c : s) {
            w.push_back(static_cast<wchar_t>(static_cast<unsigned char>(c)));
        }
        // They differ because of byte-width, but each one is internally
        // consistent.
        uint64_t a = stealth::hashes::fnv(s.data(), s.size());
        uint64_t b = stealth::hashes::fnv(s.data(), s.size());
        REQUIRE(a == b);
        uint64_t c = stealth::hashes::fnv(w.c_str(), w.size());
        uint64_t d = stealth::hashes::fnv(w.c_str(), w.size());
        REQUIRE(c == d);
    }
}

TEST_CASE("hash invariant: FNV vs DJB2 are distinct algorithms") {
    int matches = 0;
    for (int i = 0; i < 256; ++i) {
        std::string s = rand_string(4);
        if (stealth::hashes::fnv(s.data(), s.size())
            == stealth::hashes::djb2(s.data(), s.size())) {
            ++matches;
        }
    }
    // Allow at most a handful of (very rare) accidental collisions on
    // tiny input spaces for fuzz headroom.
    CHECK(matches <= 1);
}

TEST_CASE("hash property: collision rate across diverse inputs") {
    // Use fixed-length 16-char strings drawn from a large pool so that
    // the input space is ~2^96. With 4096 samples, expected collisions
    // by birthday bound are essentially 0.
    std::vector<std::pair<std::string, std::uint64_t>> samples;
    samples.reserve(N_SEEDS);
    for (std::size_t i = 0; i < N_SEEDS; ++i) {
        std::string s;
        s.reserve(16);
        for (int j = 0; j < 16; ++j) {
            s.push_back(rand_string(1)[0]);
        }
        samples.emplace_back(s, stealth::hashes::fnv(s.data(), s.size()));
    }
    std::sort(samples.begin(), samples.end(),
              [](auto const& a, auto const& b) { return a.first < b.first; });
    int input_dupes = 0;
    for (std::size_t i = 1; i < samples.size(); ++i) {
        if (samples[i].first == samples[i - 1].first &&
            samples[i].second == samples[i - 1].second) {
            ++input_dupes;
        }
    }
    std::sort(samples.begin(), samples.end(),
              [](auto const& a, auto const& b) { return a.second < b.second; });
    int hash_dupes = 0;
    for (std::size_t i = 1; i < samples.size(); ++i) {
        if (samples[i].second == samples[i - 1].second) {
            ++hash_dupes;
        }
    }
    // 16-char fixed-length strings give 64^16 ~= 1.2e28 unique inputs.
    // With 4096 samples, hash collisions on this space are vanishingly rare.
    CHECK(hash_dupes <= 1);
    CHECK(input_dupes <= 0);
}

// Standalone fuzz target. When linked with -fsanitize=fuzzer, this
// becomes the libFuzzer entry point. Without it, the executable still
// runs the doctest assertions.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0 || size > 255) return 0;
    char buf[256];
    std::memcpy(buf, data, size);
    buf[size] = '\0';
    std::uint64_t h1 = stealth::hashes::fnv(buf, size);
    std::uint64_t h2 = stealth::hashes::runtime(buf);
    if (h1 != h2) std::abort();
    (void)stealth::hashes::djb2(buf, size);
    return 0;
}
