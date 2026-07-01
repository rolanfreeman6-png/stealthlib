// tests/differential/diff_test_xorstr.cpp
// Differential testing: xorstr — same strings as StealthLib, compare output
#include "../differential/xorstr.hpp"
#include <cstdio>
#include <cstring>

// Same sentinel strings as diff_test_stealth.cpp
constexpr const char* SENTINEL_1 = "STEALTH_DIFF_TEST_SECRET_12345";
constexpr const char* SENTINEL_2 = "another_secret_api_key_abc";
constexpr const char* SENTINEL_3 = "SuperSecretPassword!@#$%";

int main() {
    int errors = 0;

    // Test 1: Short string
    {
        auto xor_str = xorstr_("STEALTH_DIFF_TEST_SECRET_12345");
        const char* plain = xor_str;
        if (std::strcmp(plain, "STEALTH_DIFF_TEST_SECRET_12345") != 0) {
            std::fprintf(stderr, "FAIL: xorstr short string mismatch\n");
            ++errors;
        }
        std::printf("[xorstr] short: '%s' (len=%zu)\n", plain, std::strlen(plain));
    }

    // Test 2: Medium string
    {
        auto xor_str = xorstr_("another_secret_api_key_abc");
        const char* plain = xor_str;
        if (std::strcmp(plain, "another_secret_api_key_abc") != 0) {
            std::fprintf(stderr, "FAIL: xorstr medium string mismatch\n");
            ++errors;
        }
        std::printf("[xorstr] medium: '%s' (len=%zu)\n", plain, std::strlen(plain));
    }

    // Test 3: Special characters
    {
        auto xor_str = xorstr_("SuperSecretPassword!@#$%");
        const char* plain = xor_str;
        if (std::strcmp(plain, "SuperSecretPassword!@#$%") != 0) {
            std::fprintf(stderr, "FAIL: xorstr special chars mismatch\n");
            ++errors;
        }
        std::printf("[xorstr] special: '%s' (len=%zu)\n", plain, std::strlen(plain));
    }

    // Test 4: Empty string — xorstr doesn't support empty strings
    {
        std::printf("[xorstr] empty: NOT SUPPORTED (xorstr requires len >= 1)\n");
    }

    // Test 5: Wide string — xorstr doesn't support wide strings
    {
        std::printf("[xorstr] wide: NOT SUPPORTED (xorstr is narrow-only)\n");
    }

    // Test 6: RAII — xorstr decrypts on access, re-encrypts on destruction
    // but doesn't have explicit unlock() RAII guard
    {
        std::printf("[xorstr] RAII: NOT SUPPORTED (no explicit unlock/reencrypt guard)\n");
    }

    // Test 7: Multiple strings (batch)
    {
        auto s1 = xorstr_("batch_string_1");
        auto s2 = xorstr_("batch_string_2");
        auto s3 = xorstr_("batch_string_3");
        if (std::strcmp(s1, "batch_string_1") != 0 ||
            std::strcmp(s2, "batch_string_2") != 0 ||
            std::strcmp(s3, "batch_string_3") != 0) {
            std::fprintf(stderr, "FAIL: xorstr batch mismatch\n");
            ++errors;
        }
        std::printf("[xorstr] batch: 3/3 OK\n");
    }

    // Print sentinel markers for binary scan
    std::printf("SENTINEL_REF: %p %p %p\n",
        (void*)SENTINEL_1, (void*)SENTINEL_2, (void*)SENTINEL_3);

    if (errors == 0) {
        std::printf("\n[xorstr] ALL TESTS PASSED (3 supported, 3 not supported)\n");
    } else {
        std::printf("\n[xorstr] %d ERRORS\n", errors);
    }
    return errors;
}
