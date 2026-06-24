#include "../stealthlib/stealth.hpp"
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
        auto s = stealth::S("benchmark_test_string_12345");
        volatile auto ptr = s;
    }, 10000);
    std::cout << "[+] S() macro: " << time << " ms per call\n";
    
    auto wide_time = benchmark([]() {
        auto s = stealth::SW(L"benchmark_wide_string_test");
        volatile auto ptr = s;
    }, 10000);
    std::cout << "[+] SW() macro: " << wide_time << " ms per call\n";
}

void benchmark_base64() {
    std::cout << "\n[*] Base64 Encoding Benchmark\n";
    
    std::vector<uint8_t> data(1024);
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<uint8_t>(i % 256);
    }
    
    auto encode_time = benchmark([&]() {
        auto encoded = stealth::encoding::base64_encode(data.data(), data.size());
        volatile auto& ref = encoded;
    }, 1000);
    std::cout << "[+] Base64 encode (1KB): " << encode_time << " ms\n";
    
    auto encoded = stealth::encoding::base64_encode(data.data(), data.size());
    auto decode_time = benchmark([&]() {
        auto decoded = stealth::encoding::base64_decode(encoded);
        volatile auto& ref = decoded;
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
        volatile auto& ref = encoded;
    }, 5000);
    std::cout << "[+] Hex encode (1KB): " << encode_time << " ms\n";
    
    auto encoded = stealth::encoding::hex_encode(data.data(), data.size());
    auto decode_time = benchmark([&]() {
        auto decoded = stealth::encoding::hex_decode(encoded);
        volatile auto& ref = decoded;
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
    
    auto time = benchmark([&]() {
        std::vector<uint8_t> copy = data;
        stealth::encoding::xor_encode(copy.data(), copy.size(), key);
        volatile auto& ref = copy;
    }, 5000);
    std::cout << "[+] XOR encode (1KB): " << time << " ms\n";
}

void benchmark_api_resolution() {
    std::cout << "\n[*] API Resolution Benchmark\n";
    
    auto first_time = benchmark([]() {
        auto fn = stealth::get_function<int(*)()>("kernel32.dll", "GetLastError");
        volatile auto ptr = fn;
    }, 1000);
    std::cout << "[+] First get_function: " << first_time << " ms\n";
    
    auto cached_time = benchmark([]() {
        auto fn = stealth::get_function<int(*)()>("kernel32.dll", "GetLastError");
        volatile auto ptr = fn;
    }, 10000);
    std::cout << "[+] Cached get_function: " << cached_time << " ms\n";
    
    auto module_time = benchmark([]() {
        stealth::module_loader loader("kernel32.dll");
        auto fn = loader.get_function<int(*)()>("GetLastError");
        volatile auto ptr = fn;
    }, 1000);
    std::cout << "[+] Module loader: " << module_time << " ms\n";
}

void benchmark_stealth_api() {
    std::cout << "\n[*] stealth_api Template Benchmark\n";
    
    auto create_time = benchmark([]() {
        auto fn = stealth::stealth_api<int()>("kernel32.dll", "GetLastError");
        volatile auto& ref = fn;
    }, 1000);
    std::cout << "[+] stealth_api construction: " << create_time << " ms\n";
    
    auto call_time = benchmark([]() {
        auto fn = stealth::stealth_api<int()>("kernel32.dll", "GetLastError");
        if (fn.is_valid()) volatile auto ptr = fn.get();
    }, 10000);
    std::cout << "[+] stealth_api get(): " << call_time << " ms\n";
}

void benchmark_debugger_check() {
    std::cout << "\n[*] Debugger Detection Benchmark\n";
    
    auto time = benchmark([]() {
        volatile auto result = stealth::detection::is_debugger_present();
    }, 10000);
    std::cout << "[+] is_debugger_present(): " << time << " ms\n";
    
    auto remote_time = benchmark([]() {
        volatile auto result = stealth::detection::check_remote_debugger();
    }, 1000);
    std::cout << "[+] check_remote_debugger(): " << remote_time << " ms\n";
}

void benchmark_secure_memory() {
    std::cout << "\n[*] Secure Memory Benchmark\n";
    
    std::vector<uint8_t> data(1024);
    
    auto zero_time = benchmark([&]() {
        std::vector<uint8_t> copy = data;
        stealth::memory::secure_zero(copy.data(), copy.size());
        volatile auto& ref = copy;
    }, 1000);
    std::cout << "[+] secure_zero (1KB): " << zero_time << " ms\n";
    
    const char* a = "benchmark_test_string_12345";
    const char* b = "benchmark_test_string_12345";
    auto cmp_time = benchmark([&]() {
        volatile auto result = stealth::memory::compare_constant_time(a, b, 30);
    }, 10000);
    std::cout << "[+] compare_constant_time (30 bytes): " << cmp_time << " ms\n";
}

int main() {
    std::cout << R"(
  ____  _____ ____ _____   _____   ____   _____ ____   ____   ___  ______   __
 |  _ \| ____| __ )_   _| | ____| |  _ \ / ____|  _ \ / __ \ / _ \|  ____/\ \ \
 | | | |  _| |  _ \ | |   |  _|   | |_) | |  _| | |_) | |  | | | | | |__  \ \ /
 | |_| | |___| |_) || |   | |___  |  _ <| |_| | |  _ <| |__| | |_| |  __|  \ V
 |____/|_____|____/ |_|   |_____| |_| \_\____|_|_| \_\____/ \___/|_|      \_)

                    Benchmark Suite v1.0.0
    )";

    std::cout << "[*] StealthLib Performance Benchmarks\n\n";
    
    benchmark_string_encryption();
    benchmark_base64();
    benchmark_hex();
    benchmark_xor();
    benchmark_api_resolution();
    benchmark_stealth_api();
    benchmark_debugger_check();
    benchmark_secure_memory();
    
    std::cout << "\n========================================\n";
    std::cout << "[+] All benchmarks completed!\n";
    std::cout << "========================================\n";
    
    return 0;
}
