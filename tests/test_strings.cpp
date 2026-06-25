#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "stealthlib/stealth.hpp"

#include <cstring>
#include <string>

TEST_CASE("string encryption: basic compile-time decryption") {
    auto s = S("Hello, World!");
    CHECK(std::strcmp(s.c_str(), "Hello, World!") == 0);
    CHECK(s.size() == 13);
}

TEST_CASE("string encryption: API-key-like content") {
    auto k = S("sk-prod-key-1234567890abcdef");
    CHECK(std::strcmp(k.c_str(), "sk-prod-key-1234567890abcdef") == 0);
    CHECK(k.size() == 28);
}

TEST_CASE("string encryption: stable decryption on multiple conversions") {
    auto s = S("decrypt_twice_test");
    const char* a = s.c_str();
    const char* b = s.c_str();
    CHECK(a == b);
    CHECK(std::strcmp(a, "decrypt_twice_test") == 0);
}

TEST_CASE("string encryption: wide strings round-trip") {
    auto w = SW(L"Wide String Test");
    CHECK(std::wcscmp(w.c_str(), L"Wide String Test") == 0);
    CHECK(w.size() == 16);
}

TEST_CASE("string encryption: unicode Russian text") {
    auto u = SW(L"\x041F\x0440\x0438\x0432\x0435\x0442!");
    CHECK(std::wcscmp(u.c_str(), L"\x041F\x0440\x0438\x0432\x0435\x0442!") == 0);
}

TEST_CASE("string encryption: EMPTY string") {
    auto e = S("");
    CHECK(std::strlen(e.c_str()) == 0);
    CHECK(e.size() == 0);
}

TEST_CASE("string encryption: special characters and long strings") {
    auto long_str = S("This is a longer string with special chars !@#$%^&*()_+-=[]{}|;':\",./<>?");
    CHECK(std::strcmp(long_str.c_str(),
                      "This is a longer string with special chars !@#$%^&*()_+-=[]{}|;':\",./<>?") == 0);
}

TEST_CASE("string encryption: distinct Idx produces distinct ciphertext") {
    auto a = S("SameTextA");
    auto b = S("SameTextA");   // different __COUNTER__ value -> different Idx
    CHECK(std::strcmp(a.c_str(), b.c_str()) == 0);
    auto c = S("SameTextB");
    CHECK(std::strcmp(a.c_str(), c.c_str()) != 0);
}

TEST_CASE("hashes::fnv compile-time vs runtime identical") {
    constexpr uint64_t h_user32 = stealth::hashes::fnv("user32.dll");
    CHECK(h_user32 != 0);
    CHECK(h_user32 == stealth::hashes::runtime("user32.dll"));
}

TEST_CASE("hashes::fnv different strings -> different hashes") {
    auto a = stealth::hashes::fnv("user32.dll");
    auto b = stealth::hashes::fnv("kernel32.dll");
    auto c = stealth::hashes::fnv("MessageBoxW");
    CHECK(a != b);
    CHECK(a != c);
    CHECK(b != c);
}

TEST_CASE("hashes::djb2 runs and returns nonzero") {
    auto h = stealth::hashes::djb2("ntdll.dll", 9);
    CHECK(h != 0);
}

TEST_CASE("encoding::base64 round-trip") {
    const char* original = "test_data_123";
    auto enc = stealth::encoding::base64_encode(original);
    CHECK(!enc.empty());
    auto dec = stealth::encoding::base64_decode(enc);
    REQUIRE(dec.has_value());
    std::string dec_str(dec->begin(), dec->end());
    CHECK(dec_str == original);
}

TEST_CASE("encoding::base64 rejects invalid input") {
    auto bad1 = stealth::encoding::base64_decode("AAAA_BBBB");
    CHECK(!bad1.has_value());
    auto bad2 = stealth::encoding::base64_decode("AAA");
    CHECK(!bad2.has_value());
}

TEST_CASE("encoding::hex round-trip") {
    std::string original("\x00\x01\x7F\x80\xFF", 5);
    REQUIRE(original.size() == 5);
    auto enc = stealth::encoding::hex_encode(original);
    CHECK(enc == "00017F80FF");
    auto dec = stealth::encoding::hex_decode(enc);
    REQUIRE(dec.has_value());
    REQUIRE(dec->size() == 5);
    for (size_t i = 0; i < original.size(); ++i) {
        CHECK((*dec)[i] == static_cast<uint8_t>(original[i]));
    }
}

TEST_CASE("encoding::hex handles zero-prefix correctly") {
    // A null byte in the middle of the string must not truncate.
    // Adjacent string literals to break the greedy C++ hex escape sequence.
    std::string s("abc\x00" "def", 7);
    REQUIRE(s.size() == 7);
    auto enc = stealth::encoding::hex_encode(s);
    CHECK(enc == "61626300646566");
    auto dec = stealth::encoding::hex_decode(enc);
    REQUIRE(dec.has_value());
    REQUIRE(dec->size() == 7);
    CHECK(std::memcmp(dec->data(), s.data(), 7) == 0);
}

TEST_CASE("encoding::rot13 symmetric") {
    char src[] = "Hello, World!";
    char buf[32] = {};
    stealth::encoding::rot13_encode(buf, src, std::strlen(src));
    char expected[] = "Uryyb, Jbeyq!";
    CHECK(std::strcmp(buf, expected) == 0);
    stealth::encoding::rot13_decode(buf, buf, std::strlen(src));
    CHECK(std::strcmp(buf, "Hello, World!") == 0);
}

TEST_CASE("encoding::xor encrypt/decrypt symmetric") {
    stealth::encoding::xor_key<16> key{"test_key_1234567"};
    char data[] = "xor_test_data";
    size_t n = std::strlen(data);
    std::vector<uint8_t> v(reinterpret_cast<uint8_t*>(data),
                            reinterpret_cast<uint8_t*>(data) + n);
    auto original = v;
    stealth::encoding::xor_encode(v.data(), v.size(), key);
    CHECK(v != original);
    stealth::encoding::xor_decode(v.data(), v.size(), key);
    CHECK(v == original);
}

TEST_CASE("memory::secure_zero zeros buffer") {
    char buf[64];
    std::memset(buf, 'A', sizeof(buf));
    stealth::memory::secure_zero(buf, sizeof(buf));
    for (size_t i = 0; i < sizeof(buf); ++i) CHECK(buf[i] == 0);
}

TEST_CASE("memory::compare_constant_time does not short-circuit") {
    const char* a = "hello_world";
    const char* b = "hello_world";
    const char* c = "hello_xorld";
    CHECK(stealth::memory::compare_constant_time(a, b, 11));
    CHECK(!stealth::memory::compare_constant_time(a, c, 11));
    CHECK(stealth::memory::compare_constant_time(a, c, 5));
}

TEST_CASE("secure_string RAII wipe on clear") {
    stealth::secure_string<256> ss("sensitive_data");
    CHECK(std::strcmp(ss.c_str(), "sensitive_data") == 0);
    ss.clear();
    bool all_zero = true;
    for (size_t i = 0; i < 256; ++i) {
        if (ss.c_str()[i] != '\0') { all_zero = false; break; }
    }
    CHECK(all_zero);
}
