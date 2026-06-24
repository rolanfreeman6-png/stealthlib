#include "stealthlib/stealth.hpp"
#include <cassert>
#include <cstring>
#include <iostream>

int main() {
    std::cout << "[+] StealthLib String Encryption Test\n\n";

    auto test1 = stealth::S("Hello, World!");
    assert(std::strcmp(test1, "Hello, World!") == 0);
    std::cout << "[+] Test 1: Basic string encryption - PASSED\n";

    auto test2 = stealth::S("sk-prod-key-1234567890abcdef");
    assert(std::strcmp(test2, "sk-prod-key-1234567890abcdef") == 0);
    std::cout << "[+] Test 2: API key encryption - PASSED\n";

    auto test3 = stealth::S("Server=db.local;Password=P@ssw0rd!");
    assert(std::strcmp(test3, "Server=db.local;Password=P@ssw0rd!") == 0);
    std::cout << "[+] Test 3: Connection string - PASSED\n";

    auto test_decrypt_twice = stealth::S("decrypt_twice_test");
    const char* first = test_decrypt_twice;
    const char* second = test_decrypt_twice;
    assert(std::strcmp(first, second) == 0);
    std::cout << "[+] Test 4: Double decrypt returns same - PASSED\n";

    auto wide_test = stealth::SW(L"Wide String Test");
    assert(std::wcscmp(wide_test, L"Wide String Test") == 0);
    std::cout << "[+] Test 5: Wide string encryption - PASSED\n";

    auto unicode = stealth::SW(L"\x041F\x0440\x0438\x0432\x0435\x0442!");
    assert(std::wcscmp(unicode, L"\x041F\x0440\x0438\x0432\x0435\x0442!") == 0);
    std::cout << "[+] Test 6: Unicode string - PASSED\n";

    auto long_string = stealth::S("This is a longer string that contains multiple words and special characters!@#$%^&*()");
    assert(std::strcmp(long_string, "This is a longer string that contains multiple words and special characters!@#$%^&*()") == 0);
    std::cout << "[+] Test 7: Long string - PASSED\n";

    auto numeric = stealth::S("1234567890");
    assert(std::strcmp(numeric, "1234567890") == 0);
    std::cout << "[+] Test 8: Numeric string - PASSED\n";

    auto special = stealth::S("!@#$%^&*()_+-=[]{}|;':\",./<>?");
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

    std::cout << "\n[+] All string encryption tests PASSED!\n";
    return 0;
}
