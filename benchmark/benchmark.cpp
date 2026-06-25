#include "stealthlib/stealth.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

#include <iostream>
#include <chrono>
#include <vector>
#include <string>

template<typename Func>
double benchmark(Func f, int iterations = 1000) {
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        f();
    }
    auto end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration<double, std::milli>(end - start).count() / iterations;
}

void benchmark_string_encryption() {
    std::cout << "[*] String Encryption Benchmark\n";

    auto time = benchmark([]() {
        auto s = S("benchmark_test_string_12345");
        volatile const char* p = s.c_str();
        (void)p;
    }, 10000);
    std::cout << "[+] S() macro: " << time << " ms per call\n";

    auto wide_time = benchmark([]() {
        auto s = SW(L"benchmark_wide_string_test");
        volatile const wchar_t* p = s.c_str();
        (void)p;
    }, 10000);
    std::cout << "[+] SW() macro: " << wide_time << " ms per call\n";

    auto unlock_time = benchmark([]() {
        for (int i = 0; i < 100; ++i) {
            auto lock = S("lock_string_test").unlock();
            volatile const char* p = lock.c_str();
            (void)p;
        }
    }, 1000);
    std::cout << "[+] S().unlock() (100x): " << unlock_time << " ms/call\n";
}

void benchmark_base64() {
    std::cout << "\n[*] Base64 Encoding Benchmark\n";

    std::vector<uint8_t> data(1024);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<uint8_t>(i % 256);
    }

    auto encode_time = benchmark([&]() {
        auto encoded = stealth::encoding::base64_encode(data.data(), data.size());
        volatile auto sz = encoded.size();
        (void)sz;
    }, 1000);
    std::cout << "[+] Base64 encode (1KB): " << encode_time << " ms\n";

    auto encoded = stealth::encoding::base64_encode(data.data(), data.size());
    auto decode_time = benchmark([&]() {
        auto decoded = stealth::encoding::base64_decode(encoded);
        volatile auto has = decoded.has_value();
        (void)has;
    }, 1000);
    std::cout << "[+] Base64 decode (1KB): " << decode_time << " ms\n";
}

void benchmark_hex() {
    std::cout << "\n[*] Hex Encoding Benchmark\n";

    std::vector<uint8_t> data(1024);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<uint8_t>(i % 256);
    }

    auto encode_time = benchmark([&]() {
        auto encoded = stealth::encoding::hex_encode(data.data(), data.size());
        volatile auto sz = encoded.size();
        (void)sz;
    }, 5000);
    std::cout << "[+] Hex encode (1KB): " << encode_time << " ms\n";

    auto encoded = stealth::encoding::hex_encode(data.data(), data.size());
    auto decode_time = benchmark([&]() {
        auto decoded = stealth::encoding::hex_decode(encoded);
        volatile auto has = decoded.has_value();
        (void)has;
    }, 5000);
    std::cout << "[+] Hex decode (1KB): " << decode_time << " ms\n";
}

void benchmark_xor() {
    std::cout << "\n[*] XOR Encoding Benchmark\n";

    std::vector<uint8_t> data(1024);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<uint8_t>(i % 256);
    }

    stealth::encoding::xor_key<16> key{"benchmark_key123"};

    auto enc_time = benchmark([&]() {
        std::vector<uint8_t> copy = data;
        stealth::encoding::xor_encode(copy.data(), copy.size(), key);
        volatile auto sz = copy.size();
        (void)sz;
    }, 5000);
    std::cout << "[+] XOR encode (1KB) (single pass, XOR is its own inverse): "
              << enc_time << " ms\n";
}

#ifdef _WIN32
void benchmark_api_resolution() {
    std::cout << "\n[*] API Resolution Benchmark (Windows only)\n";

    auto first_time = benchmark([]() {
        auto fn = stealth::get_function<int(*)()>("kernel32.dll", "GetLastError");
        volatile auto ptr = fn;
        (void)ptr;
    }, 1000);
    std::cout << "[+] get_function by name: " << first_time << " ms\n";

    auto hash_time = benchmark([]() {
        using GT_t = int(*)();
        auto fn = stealth::get_function_by_hash<GT_t>(
            stealth::hashes::fnv("kernel32.dll"),
            stealth::hashes::fnv("GetLastError"));
        volatile auto ptr = fn;
        (void)ptr;
    }, 1000);
    std::cout << "[+] get_function_by_hash: " << hash_time << " ms\n";

    auto module_time = benchmark([]() {
        stealth::module_loader loader("kernel32.dll");
        auto fn = loader.get_function<int(*)()>("GetLastError");
        volatile auto ptr = fn;
        (void)ptr;
    }, 1000);
    std::cout << "[+] module_loader + get_function: " << module_time << " ms\n";
}

void benchmark_stealth_api() {
    std::cout << "\n[*] stealth_api Template Benchmark\n";

    auto create_time = benchmark([]() {
        stealth::stealth_api<int()> fn("kernel32.dll", "GetLastError");
        volatile bool valid = fn.is_valid();
        (void)valid;
    }, 1000);
    std::cout << "[+] stealth_api by name construction: " << create_time << " ms\n";

    auto hash_time = benchmark([]() {
        stealth::stealth_api<int()> fn(stealth::hashes::fnv("kernel32.dll"),
                                       stealth::hashes::fnv("GetLastError"));
        volatile bool valid = fn.is_valid();
        (void)valid;
    }, 1000);
    std::cout << "[+] stealth_api by hash construction: " << hash_time << " ms\n";
}

void benchmark_detection_signals() {
    std::cout << "\n[*] Anti-Debug Signal Suite Benchmark (Windows only)\n";

    auto peb_time = benchmark([]() {
        volatile auto b = stealth::detection::is_debugger_present();
        (void)b;
    }, 10000);
    std::cout << "[+] is_debugger_present: " << peb_time << " ms\n";

    auto remote_time = benchmark([]() {
        volatile auto b = stealth::detection::check_remote_debugger();
        (void)b;
    }, 1000);
    std::cout << "[+] check_remote_debugger: " << remote_time << " ms\n";

    auto scan_time = benchmark([]() {
        auto s = stealth::detection::scan();
        volatile int n = s.hwbp_count;
        (void)n;
    }, 1000);
    std::cout << "[+] detection::scan (full suite): " << scan_time << " ms\n";
}
#endif

void benchmark_secure_memory() {
    std::cout << "\n[*] Secure Memory Benchmark\n";

    std::vector<uint8_t> data(1024);

    auto zero_time = benchmark([&]() {
        std::vector<uint8_t> copy = data;
        stealth::memory::secure_zero(copy.data(), copy.size());
        volatile auto sz = copy.size();
        (void)sz;
    }, 1000);
    std::cout << "[+] secure_zero (1KB): " << zero_time << " ms\n";

    const char* a = "benchmark_test_string_12345";
    const char* b = "benchmark_test_string_12345";
    auto cmp_time = benchmark([&]() {
        volatile bool r = stealth::memory::compare_constant_time(a, b, 30);
        (void)r;
    }, 10000);
    std::cout << "[+] compare_constant_time (30 bytes): " << cmp_time << " ms\n";
}

int main() {
    std::cout << "\nStealthLib Benchmark Suite v2.0.0\n";

    benchmark_string_encryption();
    benchmark_base64();
    benchmark_hex();
    benchmark_xor();
#ifdef _WIN32
    benchmark_api_resolution();
    benchmark_stealth_api();
    benchmark_detection_signals();
#endif
    benchmark_secure_memory();

    std::cout << "\n[+] All benchmarks completed.\n";
    return 0;
}
