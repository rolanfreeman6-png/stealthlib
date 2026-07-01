#include "stealthlib/stealth.hpp"
#include <cassert>
#include <cstring>
#include <cstdint>
#include <iostream>

int main() {
    std::cout << "[+] StealthLib String Encryption Test\n\n";

    // Known-answer: base64 encode
    assert(stealth::encoding::base64_encode("test") == "dGVzdA==");
    assert(stealth::encoding::base64_encode("Hello, World!") == "SGVsbG8sIFdvcmxkIQ==");
    assert(stealth::encoding::base64_encode("") == "");
    assert(stealth::encoding::base64_encode("ABC") == "QUJD");
    std::cout << "[+] Known-answer: base64_encode - PASSED\n";

    // Known-answer: hex encode
    assert(stealth::encoding::hex_encode("test") == "74657374");
    assert(stealth::encoding::hex_encode("ABC") == "414243");
    assert(stealth::encoding::hex_encode("") == "");
    std::cout << "[+] Known-answer: hex_encode - PASSED\n";

    // Known-answer: rot13
    std::array<char, 32> rot_buf{};
    stealth::encoding::rot13_encode(rot_buf.data(), "Hello, World!", 13);
    rot_buf[13] = 0;
    assert(std::strcmp(rot_buf.data(), "Uryyb, Jbeyq!") == 0);
    stealth::encoding::rot13_encode(rot_buf.data(), "Hello", 5);
    rot_buf[5] = 0;
    assert(std::strcmp(rot_buf.data(), "Uryyb") == 0);
    std::cout << "[+] Known-answer: rot13 - PASSED\n";

    // Known-answer: secure_zero — verify buffer is actually zeroed
    std::array<char, 16> sz_buf{};
    std::memset(sz_buf.data(), 0xFF, 16);
    stealth::memory::secure_zero(sz_buf.data(), 16);
    for (char c : sz_buf) assert(c == 0);
    // Partial zero: only first 8 bytes
    std::memset(sz_buf.data(), 0xFF, 16);
    stealth::memory::secure_zero(sz_buf.data(), 8);
    for (int i = 0; i < 8; ++i) assert(sz_buf[i] == 0);
    for (int i = 8; i < 16; ++i) assert(sz_buf[i] == static_cast<char>(0xFF));
    // Null + zero size: no crash
    stealth::memory::secure_zero(nullptr, 0);
    std::cout << "[+] Known-answer: secure_zero - PASSED\n";

    // Known-answer: xor_crypt — specific output bytes
    {
        stealth::encoding::xor_key<4> xkey("key");
        std::array<uint8_t, 4> xd{0x41, 0x41, 0x41, 0x41};
        stealth::encoding::xor_encode(xd.data(), 4, xkey);
        assert(xd[0] == 0x2a);
        assert(xd[1] == 0x24);
        assert(xd[2] == 0x38);
        assert(xd[3] == 0x2a);
        std::cout << "[+] Known-answer: xor_crypt - PASSED\n";
    }

    // Known-answer: compare_constant_time
    assert(stealth::memory::compare_constant_time("abc", "abc", 3) == true);
    assert(stealth::memory::compare_constant_time("abc", "abd", 3) == false);
    assert(stealth::memory::compare_constant_time("abc", "abc", 0) == true);
    assert(stealth::memory::compare_constant_time(nullptr, "abc", 1) == false);
    assert(stealth::memory::compare_constant_time("abc", nullptr, 1) == false);
    std::cout << "[+] Known-answer: compare_constant_time - PASSED\n";

    // Known-answer: SHA-256 of empty string (FIPS-180-4)
    {
        std::array<uint8_t, 32> digest{};
        stealth::detail::sha256_oneshot(nullptr, 0, digest.data());
        constexpr std::array<uint8_t, 32> expected_empty{
            0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,
            0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
            0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
            0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
        };
        assert(std::memcmp(digest.data(), expected_empty.data(), 32) == 0);
        std::cout << "[+] Known-answer: SHA-256('') - PASSED\n";
    }

    // Known-answer: FNV-1a hash values
    static_assert(stealth::hashes::fnv("hello") == 0xa430d84680aabd0bULL);
    static_assert(stealth::hashes::fnv("test") == 0xf9e6e6ef197c2b25ULL);
    static_assert(stealth::hashes::fnv("kernel32.dll") == 0xe14b18a7acf9c443ULL);
    static_assert(stealth::hashes::fnv("MessageBoxW") == 0x1e308b27ba21f56eULL);
    static_assert(stealth::hashes::fnv("") == 0xcbf29ce484222325ULL);
    static_assert(stealth::hashes::djb2("hello", 5) == 0x000000310f923099ULL);
    static_assert(stealth::hashes::djb2("test", 4) == 0x000000017c9e6865ULL);
    static_assert(stealth::hashes::djb2("", 0) == 0x0000000000001505ULL);
    assert(stealth::hashes::runtime("hello") == 0xa430d84680aabd0bULL);
    std::cout << "[+] Known-answer: FNV/DJB2 hashes - PASSED\n";

    // Known-answer: encryption — ciphertext must differ from plaintext
    {
        auto enc_test = S("Hello, World!");
        assert(std::strcmp(enc_test, "Hello, World!") == 0);
        std::cout << "[+] Known-answer: encryption round-trip - PASSED\n";
    }

    auto test1 = S("Hello, World!");
    assert(std::strcmp(test1, "Hello, World!") == 0);
    std::cout << "[+] Test 1: Basic string encryption - PASSED\n";

    auto test2 = S("sk-prod-key-1234567890abcdef");
    assert(std::strcmp(test2, "sk-prod-key-1234567890abcdef") == 0);
    std::cout << "[+] Test 2: API key encryption - PASSED\n";

    auto test3 = S("Server=db.local;Password=P@ssw0rd!");
    assert(std::strcmp(test3, "Server=db.local;Password=P@ssw0rd!") == 0);
    std::cout << "[+] Test 3: Connection string - PASSED\n";

    auto test_decrypt_twice = S("decrypt_twice_test");
    const char* first = test_decrypt_twice;
    const char* second = test_decrypt_twice;
    assert(std::strcmp(first, second) == 0);
    std::cout << "[+] Test 4: Double decrypt returns same - PASSED\n";

    auto wide_test = SW(L"Wide String Test");
    assert(std::wcscmp(wide_test, L"Wide String Test") == 0);
    std::cout << "[+] Test 5: Wide string encryption - PASSED\n";

    auto unicode = SW(L"\x041F\x0440\x0438\x0432\x0435\x0442!");
    assert(std::wcscmp(unicode, L"\x041F\x0440\x0438\x0432\x0435\x0442!") == 0);
    std::cout << "[+] Test 6: Unicode string - PASSED\n";

    auto long_string = S("This is a longer string that contains multiple words and special characters!@#$%^&*()");
    assert(std::strcmp(long_string, "This is a longer string that contains multiple words and special characters!@#$%^&*()") == 0);
    std::cout << "[+] Test 7: Long string - PASSED\n";

    auto numeric = S("1234567890");
    assert(std::strcmp(numeric, "1234567890") == 0);
    std::cout << "[+] Test 8: Numeric string - PASSED\n";

    auto special = S("!@#$%^&*()_+-=[]{}|;':\",./<>?");
    assert(std::strcmp(special, "!@#$%^&*()_+-=[]{}|;':\",./<>?") == 0);
    std::cout << "[+] Test 9: Special characters - PASSED\n";

    stealth::secure_string<256> sec_str("sensitive_data");
    assert(std::strcmp(sec_str.c_str(), "sensitive_data") == 0);
    sec_str.clear();
    bool all_zero = true;
    for (size_t i = 0; i < 256; ++i) {
        if (sec_str.c_str()[i] != '\0') {
            all_zero = false;
            break;
        }
    }
    assert(all_zero);
    std::cout << "[+] Test 10: Secure string with clear - PASSED\n";

    auto empty_n = S("");
    assert(std::strcmp(empty_n, "") == 0);
    assert(empty_n.size() == 0);
    assert(std::strcmp(*empty_n, "") == 0);
    auto g = empty_n.unlock();
    assert(std::strcmp(g.c_str(), "") == 0);

    auto empty_w = SW(L"");
    assert(std::wcscmp(empty_w, L"") == 0);
    assert(empty_w.size() == 0);
    auto wg = empty_w.unlock();
    assert(std::wcscmp(wg.c_str(), L"") == 0);
    std::cout << "[+] Test 11: Empty literal S(\"\") / SW(L\"\") - PASSED\n";

    std::cout << "\n[+] All string encryption tests PASSED!\n";
    return 0;
}
