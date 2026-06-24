#include "stealthlib/stealth.hpp"
#include <iostream>
#include <vector>
#include <cstring>
#include <windows.h>

void print_separator(const char* title) {
    std::cout << "\n========================================\n";
    std::cout << title << "\n";
    std::cout << "========================================\n";
}

void demonstrate_string_encryption() {
    print_separator("COMPILE-TIME STRING ENCRYPTION");
    auto sensitive_api_key = S("sk-live-abc123def456ghi789jkl012");
    std::cout << "[+] Encrypted API Key: " << sensitive_api_key << "\n";
    std::cout << "[*] String length: " << std::strlen(sensitive_api_key) << "\n";
    auto connection_string = S("Server=prod.db.local;Password=Secret123!");
    std::cout << "[+] Connection String: " << connection_string << "\n";
    auto jwt_secret = S("JWT_SECRET_SUPER_LONG_KEY_FOR_PRODUCTION_ENVIRONMENT");
    std::cout << "[+] JWT Secret: " << jwt_secret << "\n";
    auto license_key = S("LICENSE-KEY-A1B2-C3D4-E5F6-G7H8");
    std::cout << "[+] License Key: " << license_key << "\n";
    auto admin_password = S("AdminP@ssw0rd!2024");
    std::cout << "[+] Admin Password: " << admin_password << "\n";
    std::cout << "\n[*] Wide string encryption:\n";
    auto wide_title = SW(L"StealthLib Wide String Test");
    auto wide_msg = SW(L"All sensitive strings are encrypted at compile-time!");
    std::wcout << L"[+] Wide Title: " << wide_title << L"\n";
    std::wcout << L"[+] Wide Message: " << wide_msg << L"\n";
}

void demonstrate_peb_resolution() {
    print_separator("PEB WALKING & DYNAMIC API RESOLUTION");
    std::cout << "[*] Resolving APIs without IAT entries...\n\n";
    using MessageBoxW_t = int(*)(HWND, LPCWSTR, LPCWSTR, UINT);
    auto MessageBoxW = stealth::get_function<MessageBoxW_t>("user32.dll", "MessageBoxW");
    if (MessageBoxW) std::cout << "[+] MessageBoxW resolved: " << reinterpret_cast<void*>(MessageBoxW) << "\n";
    using GetLastError_t = DWORD(*)();
    auto GetLastError = stealth::get_function<GetLastError_t>("kernel32.dll", "GetLastError");
    if (GetLastError) std::cout << "[+] GetLastError resolved: " << reinterpret_cast<void*>(GetLastError) << "\n";
    using SetLastError_t = void(*)(DWORD);
    auto SetLastError = stealth::get_function<SetLastError_t>("kernel32.dll", "SetLastError");
    if (SetLastError) std::cout << "[+] SetLastError resolved: " << reinterpret_cast<void*>(SetLastError) << "\n";
    using GetCurrentProcessId_t = DWORD(*)();
    auto GetCurrentProcessId = stealth::get_function<GetCurrentProcessId_t>("kernel32.dll", "GetCurrentProcessId");
    if (GetCurrentProcessId) std::cout << "[+] GetCurrentProcessId resolved, PID: " << GetCurrentProcessId() << "\n";
    using GetCurrentThreadId_t = DWORD(*)();
    auto GetCurrentThreadId = stealth::get_function<GetCurrentThreadId_t>("kernel32.dll", "GetCurrentThreadId");
    if (GetCurrentThreadId) std::cout << "[+] GetCurrentThreadId resolved, TID: " << GetCurrentThreadId() << "\n";
    using QueryPerformanceCounter_t = BOOL(*)(LARGE_INTEGER*);
    auto QueryPerformanceCounter = stealth::get_function<QueryPerformanceCounter_t>("kernel32.dll", "QueryPerformanceCounter");
    if (QueryPerformanceCounter) { LARGE_INTEGER counter; QueryPerformanceCounter(&counter); std::cout << "[+] QueryPerformanceCounter resolved, counter: " << counter.QuadPart << "\n"; }
    using GetTickCount64_t = ULONGLONG(*)();
    auto GetTickCount64 = stealth::get_function<GetTickCount64_t>("kernel32.dll", "GetTickCount64");
    if (GetTickCount64) std::cout << "[+] GetTickCount64 resolved, uptime: " << GetTickCount64() << "ms\n";
    void* ntdll_base = nullptr;
    if (stealth::get_module_base(L"ntdll.dll", &ntdll_base)) std::cout << "\n[*] NTDLL base: " << ntdll_base << "\n";
    void* kernel32_base = nullptr;
    if (stealth::get_module_base(L"kernel32.dll", &kernel32_base)) std::cout << "[*] KERNEL32 base: " << kernel32_base << "\n";
    void* user32_base = nullptr;
    if (stealth::get_module_base(L"user32.dll", &user32_base)) std::cout << "[*] USER32 base: " << user32_base << "\n";
}

void demonstrate_encoding() {
    print_separator("XOR & BASE64 ENCODING");
    std::cout << "[*] Testing Base64 encoding...\n";
    const char* original = "SensitiveData123!@#";
    auto encoded = stealth::encoding::base64_encode(original);
    std::cout << "[+] Original: " << original << "\n";
    std::cout << "[+] Base64 Encoded: " << encoded << "\n";
    auto decoded = stealth::encoding::base64_decode(encoded);
    if (decoded.has_value()) {
        std::cout << "[+] Base64 Decoded: ";
        for (auto b : decoded) std::cout << static_cast<char>(b);
        std::cout << "\n";
    }
    std::cout << "\n[*] Testing Hex encoding...\n";
    auto hex_encoded = stealth::encoding::hex_encode(original);
    std::cout << "[+] Hex Encoded: " << hex_encoded << "\n";
    std::cout << "\n[*] Testing XOR encoding...\n";
    stealth::encoding::xor_key<16> key{"MySecretKey123456"};
    std::vector<uint8_t> data(original, original + std::strlen(original));
    stealth::encoding::xor_decode(data.data(), data.size(), key);
    std::cout << "[+] XOR Encrypted (hex): ";
    for (auto b : data) std::cout << std::hex << static_cast<int>(b) << " ";
    std::cout << std::dec << "\n";
    stealth::encoding::xor_decode(data.data(), data.size(), key);
    std::cout << "[+] XOR Decrypted: ";
    for (auto b : data) std::cout << static_cast<char>(b);
    std::cout << "\n";
    std::cout << "\n[*] Testing ROT13...\n";
    std::vector<uint8_t> rot13_data(original, original + std::strlen(original));
    stealth::encoding::rot13_encode(rot13_data.data(), rot13_data.data(), rot13_data.size());
    std::cout << "[+] ROT13 Encoded: ";
    for (auto b : rot13_data) std::cout << static_cast<char>(b);
    std::cout << "\n";
    stealth::encoding::rot13_decode(rot13_data.data(), rot13_data.data(), rot13_data.size());
    std::cout << "[+] ROT13 Decoded: ";
    for (auto b : rot13_data) std::cout << static_cast<char>(b);
    std::cout << "\n";
}

void demonstrate_debugger_detection() {
    print_separator("DEBUGGER DETECTION");
    if (stealth::detection::is_debugger_present()) std::cout << "[!] PE BeingDebugged flag is set!\n";
    else std::cout << "[+] No debugger detected via PEB\n";
    if (stealth::detection::check_remote_debugger()) std::cout << "[!] Remote debugger detected!\n";
    else std::cout << "[+] No remote debugger detected\n";
}

void demonstrate_secure_memory() {
    print_separator("SECURE MEMORY OPERATIONS");
    char sensitive_data[] = "This is sensitive data that needs to be securely erased!";
    std::cout << "[*] Original data: " << sensitive_data << "\n";
    stealth::memory::secure_zero(sensitive_data, sizeof(sensitive_data));
    std::cout << "[+] Data after secure zero:\n    ";
    for (size_t i = 0; i < sizeof(sensitive_data); ++i) std::cout << static_cast<int>(static_cast<unsigned char>(sensitive_data[i])) << " ";
    std::cout << "\n";
    std::cout << "\n[*] Testing constant-time comparison...\n";
    const char* a = "test_password";
    const char* b = "test_password";
    const char* c = "wrong_password";
    std::cout << "[+] strcmp(a, b): " << (stealth::memory::compare_constant_time(a, b, 13) ? "EQUAL" : "NOT EQUAL") << "\n";
    std::cout << "[+] strcmp(a, c): " << (stealth::memory::compare_constant_time(a, c, 13) ? "EQUAL" : "NOT EQUAL") << "\n";
}

void demonstrate_stealth_api() {
    print_separator("stealth::stealth_api TEMPLATE");
    auto MessageBoxW_fn = stealth::stealth_api<int(HWND, LPCWSTR, LPCWSTR, UINT)>("user32.dll", "MessageBoxW");
    if (MessageBoxW_fn.is_valid()) {
        std::cout << "[+] stealth::stealth_api resolved MessageBoxW\n";
        auto title = SW(L"StealthLib Demo");
        auto msg = SW(L"stealth::stealth_api works perfectly!\nAll functions resolved dynamically.");
        MessageBoxW_fn.get()(nullptr, msg, title, MB_OK | MB_ICONINFORMATION);
    }
    auto GetTickCount64_fn = stealth::stealth_api<ULONGLONG()>("kernel32.dll", "GetTickCount64");
    if (GetTickCount64_fn.is_valid()) {
        std::cout << "[+] stealth::stealth_api resolved GetTickCount64\n";
        std::cout << "[*] System uptime: " << GetTickCount64_fn.get()() << " ms\n";
    }
    auto VirtualAlloc_fn = stealth::stealth_api<LPVOID(LPVOID, SIZE_T, DWORD, DWORD)>("kernel32.dll", "VirtualAlloc");
    if (VirtualAlloc_fn.is_valid()) {
        std::cout << "[+] stealth::stealth_api resolved VirtualAlloc\n";
        auto mem = VirtualAlloc_fn.get()(nullptr, 8192, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (mem) {
            std::cout << "[+] Allocated memory at: " << mem << "\n";
            auto VirtualFree_fn = stealth::stealth_api<BOOL(LPVOID, SIZE_T, DWORD)>("kernel32.dll", "VirtualFree");
            if (VirtualFree_fn.is_valid()) { VirtualFree_fn.get()(mem, 0, MEM_RELEASE); std::cout << "[+] Memory freed\n"; }
        }
    }
}

void demonstrate_module_loader() {
    print_separator("MODULE LOADER");
    stealth::module_loader kernel32("kernel32.dll");
    if (kernel32.is_valid()) {
        std::cout << "[+] kernel32.dll loaded\n";
        auto GetComputerNameW = kernel32.get_function<BOOL(*)(LPWSTR, LPDWORD)>("GetComputerNameW");
        if (GetComputerNameW) { wchar_t computer_name[256] = {}; DWORD size = 255; if (GetComputerNameW(computer_name, &size)) { std::cout << "[+] Computer Name: "; for (DWORD i = 0; i < size; ++i) std::cout << static_cast<char>(computer_name[i]); std::cout << "\n"; } }
        auto GetUserNameW = kernel32.get_function<BOOL(*)(LPWSTR, LPDWORD)>("GetUserNameW");
        if (GetUserNameW) { wchar_t user_name[256] = {}; DWORD size = 255; if (GetUserNameW(user_name, &size)) { std::cout << "[+] User Name: "; for (DWORD i = 0; i < size; ++i) std::cout << static_cast<char>(user_name[i]); std::cout << "\n"; } }
    }
    stealth::module_loader ntdll("ntdll.dll");
    if (ntdll.is_valid()) { std::cout << "[+] ntdll.dll loaded\n"; std::cout << "[*] Base address: " << ntdll.get() << "\n"; }
}

int main() {
    std::cout << "[*] StealthLib Full Demo - " << stealth::version() << "\n";
    std::cout << "[*] Binary obfuscation library for C++20\n";
    demonstrate_string_encryption();
    demonstrate_peb_resolution();
    demonstrate_encoding();
    demonstrate_debugger_detection();
    demonstrate_secure_memory();
    demonstrate_stealth_api();
    demonstrate_module_loader();
    print_separator("DEMO COMPLETE");
    std::cout << "[+] All StealthLib features demonstrated successfully!\n";
    return 0;
}
