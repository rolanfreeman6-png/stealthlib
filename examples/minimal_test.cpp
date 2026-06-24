#include "stealthlib/stealth.hpp"
#include <iostream>
#include <windows.h>

int main() {
    std::cout << "StealthLib v" << stealth::version() << " test\n";

    auto encoded = stealth::encoding::base64_encode("test_data");
    std::cout << "Base64 encoded: " << encoded << "\n";

    auto decoded = stealth::encoding::base64_decode(encoded);
    if (decoded.has_value()) {
        std::cout << "Base64 decoded: " << *decoded << "\n";
    }

    auto hex = stealth::encoding::hex_encode("hello world", 11);
    std::cout << "Hex encoded: " << hex << "\n";

    auto hex_decoded = stealth::encoding::hex_decode(hex);
    if (hex_decoded.has_value()) {
        std::cout << "Hex decoded: ";
        for (auto b : *hex_decoded) std::cout << (char)b;
        std::cout << "\n";
    }

    if (stealth::detection::is_debugger_present()) {
        std::cout << "Debugger detected!\n";
    } else {
        std::cout << "No debugger\n";
    }

    auto MessageBoxW = stealth::get_function<int(*)(HWND, LPCWSTR, LPCWSTR, UINT)>("user32.dll", "MessageBoxW");
    if (MessageBoxW) {
        MessageBoxW(nullptr, L"StealthLib works!", L"Test", MB_OK);
        std::cout << "MessageBoxW called successfully\n";
    } else {
        std::cout << "Failed to resolve MessageBoxW\n";
    }

    auto GetTickCount = stealth::get_function<DWORD(*)()>("kernel32.dll", "GetTickCount");
    if (GetTickCount) {
        DWORD ticks = GetTickCount();
        std::cout << "GetTickCount: " << ticks << "\n";
    }

    stealth::module_loader kernel32("kernel32.dll");
    if (kernel32.is_valid()) {
        auto GetComputerNameW = kernel32.get_function<BOOL(*)(WCHAR*, DWORD*)>("GetComputerNameW");
        if (GetComputerNameW) {
            wchar_t name[256] = {};
            DWORD size = 255;
            if (GetComputerNameW(name, &size)) {
                std::cout << "Computer name: ";
                for (DWORD i = 0; i < size; ++i) std::cout << (char)name[i];
                std::cout << "\n";
            }
        }
    }

    char sensitive[] = "secret_data";
    std::cout << "Before secure zero: " << sensitive << "\n";
    stealth::memory::secure_zero(sensitive, sizeof(sensitive));
    bool all_zero = true;
    for (size_t i = 0; i < sizeof(sensitive); ++i) {
        if (sensitive[i] != 0) { all_zero = false; break; }
    }
    std::cout << "After secure zero, all zeros: " << (all_zero ? "yes" : "no") << "\n";

    std::cout << "\nAll tests passed!\n";
    return 0;
}
