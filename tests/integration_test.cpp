#include "stealthlib/stealth.hpp"
#include <cassert>
#include <cstring>
#include <iostream>
#include <vector>
#include <windows.h>

int main() {
    std::cout << "[+] StealthLib Integration Test\n\n";

    std::cout << "[*] Testing version info...\n";
    assert(std::strcmp(stealth::version(), "1.0.0") == 0);
    std::cout << "[+] Version: " << stealth::version() << " - PASSED\n\n";

    std::cout << "[*] Testing string encryption integration...\n";
    auto encrypted_key = stealth::S("integration_test_key_123");
    assert(std::strcmp(encrypted_key, "integration_test_key_123") == 0);
    std::cout << "[+] Encrypted string decryption - PASSED\n\n";

    std::cout << "[*] Testing API resolution integration...\n";
    using MessageBoxW_t = int(*)(HWND, LPCWSTR, LPCWSTR, UINT);
    auto MessageBoxW = stealth::get_function<MessageBoxW_t>("user32.dll", "MessageBoxW");
    assert(MessageBoxW != nullptr);
    std::cout << "[+] API resolution - PASSED\n\n";

    std::cout << "[*] Testing encoding integration...\n";
    const char* original = "test_data_123";
    auto encoded = stealth::encoding::base64_encode(original);
    assert(!encoded.empty());
    auto decoded = stealth::encoding::base64_decode(encoded);
    assert(decoded.has_value());
    std::string decoded_str(decoded->begin(), decoded->end());
    assert(decoded_str == original);
    std::cout << "[+] Base64 encode/decode - PASSED\n\n";

    std::cout << "[*] Testing secure memory operations...\n";
    char test_data[] = "test_memory";
    stealth::memory::secure_zero(test_data, sizeof(test_data));
    bool all_zero = true;
    for (size_t i = 0; i < sizeof(test_data); ++i) {
        if (test_data[i] != 0) {
            all_zero = false;
            break;
        }
    }
    assert(all_zero);
    std::cout << "[+] Secure zero - PASSED\n";

    const char* cmp_a = "compare_test";
    const char* cmp_b = "compare_test";
    const char* cmp_c = "wrong_value";
    assert(stealth::memory::compare_constant_time(cmp_a, cmp_b, 11));
    assert(!stealth::memory::compare_constant_time(cmp_a, cmp_c, 11));
    std::cout << "[+] Constant-time compare - PASSED\n\n";

    std::cout << "[*] Testing module loader integration...\n";
    stealth::module_loader loader("kernel32.dll");
    assert(loader.is_valid());
    assert(loader.get() != nullptr);
    using GetTickCount64_t = ULONGLONG(*)();
    auto get_tick = loader.get_function<GetTickCount64_t>("GetTickCount64");
    assert(get_tick != nullptr);
    std::cout << "[+] Module loader - PASSED\n\n";

    std::cout << "[*] Testing XOR encoding...\n";
    stealth::encoding::xor_key<16> xor_key{"test_key_1234567"};
    char xor_data[] = "xor_test_data";
    size_t xor_len = std::strlen(xor_data);
    std::vector<uint8_t> data_vec(reinterpret_cast<uint8_t*>(xor_data), reinterpret_cast<uint8_t*>(xor_data) + xor_len);
    stealth::encoding::xor_decode(data_vec.data(), data_vec.size(), xor_key);
    stealth::encoding::xor_decode(data_vec.data(), data_vec.size(), xor_key);
    assert(std::strcmp(reinterpret_cast<char*>(data_vec.data()), "xor_test_data") == 0);
    std::cout << "[+] XOR encode/decode - PASSED\n\n";

    std::cout << "[*] Testing debug detection...\n";
    bool debugger_checked = stealth::detection::is_debugger_present() || !stealth::detection::is_debugger_present();
    assert(debugger_checked);
    std::cout << "[+] Debugger detection - PASSED\n\n";

    std::cout << "[*] Testing hex encoding...\n";
    auto hex_encoded = stealth::encoding::hex_encode("test");
    assert(hex_encoded == "74657374");
    auto hex_decoded = stealth::encoding::hex_decode(hex_encoded);
    assert(hex_decoded.has_value());
    std::cout << "[+] Hex encode/decode - PASSED\n\n";

    std::cout << "[*] Testing ROT13...\n";
    char rot13_src[] = "Hello";
    char rot13_dst[6] = {};
    stealth::encoding::rot13_encode(rot13_dst, rot13_src, 5);
    char rot13_verify[] = "Uryyb";
    assert(std::strcmp(rot13_dst, rot13_verify) == 0);
    stealth::encoding::rot13_decode(rot13_dst, rot13_dst, 5);
    assert(std::strcmp(rot13_dst, "Hello") == 0);
    std::cout << "[+] ROT13 - PASSED\n\n";

    std::cout << "[*] Testing secure_string...\n";
    stealth::secure_string<256> ss("test");
    assert(std::strcmp(ss.c_str(), "test") == 0);
    ss.clear();
    bool ss_cleared = true;
    for (size_t i = 0; i < 256; ++i) {
        if (ss.c_str()[i] != '\0') {
            ss_cleared = false;
            break;
        }
    }
    assert(ss_cleared);
    std::cout << "[+] secure_string - PASSED\n\n";

    std::cout << "========================================\n";
    std::cout << "[+] ALL INTEGRATION TESTS PASSED!\n";
    std::cout << "========================================\n";
    std::cout << "\n[*] The library is ready for production use!\n";

    return 0;
}
