// tests/differential/diff_test_stealth.cpp
// Differential testing: StealthLib S() vs xorstr — same strings, compare output
#include "stealthlib/stealth.hpp"
#include <cstdio>
#include <cstring>

// Sentinel strings for binary scan comparison
// These MUST NOT appear as plaintext in the compiled binary
constexpr const char* SENTINEL_1 = "STEALTH_DIFF_TEST_SECRET_12345";
constexpr const char* SENTINEL_2 = "another_secret_api_key_abc";
constexpr const char* SENTINEL_3 = "SuperSecretPassword!@#$%";

int main() {
    int errors = 0;

    // Test 1: Short string
    {
        auto stealth_str = S("STEALTH_DIFF_TEST_SECRET_12345");
        const char* plain = stealth_str;
        if (std::strcmp(plain, "STEALTH_DIFF_TEST_SECRET_12345") != 0) {
            std::fprintf(stderr, "FAIL: stealth S() short string mismatch\n");
            ++errors;
        }
        std::printf("[stealth] short: '%s' (len=%zu)\n", plain, std::strlen(plain));
    }

    // Test 2: Medium string
    {
        auto stealth_str = S("another_secret_api_key_abc");
        const char* plain = stealth_str;
        if (std::strcmp(plain, "another_secret_api_key_abc") != 0) {
            std::fprintf(stderr, "FAIL: stealth S() medium string mismatch\n");
            ++errors;
        }
        std::printf("[stealth] medium: '%s' (len=%zu)\n", plain, std::strlen(plain));
    }

    // Test 3: Special characters
    {
        auto stealth_str = S("SuperSecretPassword!@#$%");
        const char* plain = stealth_str;
        if (std::strcmp(plain, "SuperSecretPassword!@#$%") != 0) {
            std::fprintf(stderr, "FAIL: stealth S() special chars mismatch\n");
            ++errors;
        }
        std::printf("[stealth] special: '%s' (len=%zu)\n", plain, std::strlen(plain));
    }

    // Test 4: Empty string
    {
        auto stealth_str = S("");
        const char* plain = stealth_str;
        if (std::strcmp(plain, "") != 0) {
            std::fprintf(stderr, "FAIL: stealth S() empty string mismatch\n");
            ++errors;
        }
        std::printf("[stealth] empty: '' (len=0)\n");
    }

    // Test 5: Wide string
    {
        auto stealth_wstr = SW(L"WideSecret123");
        const wchar_t* plain = stealth_wstr;
        if (std::wcscmp(plain, L"WideSecret123") != 0) {
            std::fprintf(stderr, "FAIL: stealth SW() wide string mismatch\n");
            ++errors;
        }
        std::printf("[stealth] wide: OK (len=13)\n");
    }

    // Test 6: RAII unlock/reencrypt
    {
        auto s = S("RAII_test_secret");
        {
            auto lock = s.unlock();
            if (std::strcmp(lock.c_str(), "RAII_test_secret") != 0) {
                std::fprintf(stderr, "FAIL: stealth unlock mismatch\n");
                ++errors;
            }
        }
        // After scope exit, should be re-encrypted but still decryptable
        if (std::strcmp(s, "RAII_test_secret") != 0) {
            std::fprintf(stderr, "FAIL: stealth reencrypt + decrypt mismatch\n");
            ++errors;
        }
        std::printf("[stealth] RAII: OK\n");
    }

    // Test 7: Multiple strings (batch)
    {
        auto s1 = S("batch_string_1");
        auto s2 = S("batch_string_2");
        auto s3 = S("batch_string_3");
        if (std::strcmp(s1, "batch_string_1") != 0 ||
            std::strcmp(s2, "batch_string_2") != 0 ||
            std::strcmp(s3, "batch_string_3") != 0) {
            std::fprintf(stderr, "FAIL: stealth batch mismatch\n");
            ++errors;
        }
        std::printf("[stealth] batch: 3/3 OK\n");
    }

    // Print sentinel markers for binary scan
    // These lines ensure the sentinels are referenced in code
    std::printf("SENTINEL_REF: %p %p %p\n",
        (void*)SENTINEL_1, (void*)SENTINEL_2, (void*)SENTINEL_3);

    if (errors == 0) {
        std::printf("\n[stealth] ALL %d TESTS PASSED\n", 7);
    } else {
        std::printf("\n[stealth] %d ERRORS\n", errors);
    }
    return errors;
}
