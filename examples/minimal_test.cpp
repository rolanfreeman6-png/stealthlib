#include "stealthlib/stealth.hpp"
#include <iostream>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

int main() {
    std::cout << "StealthLib v" << stealth::version() << " (smoke test)\n";

    {
        auto s = S("Hello, World!");
        std::cout << "[+] S(\"Hello, World!\") = " << s.c_str() << " (len " << s.size() << ")\n";
    }

    {
        auto w = SW(L"Wide Hello");
        std::cout << "[+] SW wide decrypt = ";
        std::wcout << w.c_str() << L"\n";
    }

    {
        auto s = S("decrypt_twice");
        const char* a = s.c_str();
        const char* b = s.c_str();
        std::cout << "[+] stable c_str pointer: " << (a == b ? "yes" : "no") << "\n";
    }

    {
        auto lock = S("narrow-window").unlock();
        std::cout << "[+] RAII unlock plaintext inside scope: " << lock.c_str() << "\n";
    }

    {
        auto enc = stealth::encoding::base64_encode("hello");
        std::cout << "[+] base64_encode(\"hello\") = " << enc << "\n";
    }

    {
        std::cout << "[+] hashes fnv(\"kernel32.dll\") = 0x"
                  << std::hex << stealth::hashes::fnv("kernel32.dll")
                  << std::dec << "\n";
    }

#ifdef _WIN32
    std::cout << "[+] PEB pointer = " << stealth::get_peb_ptr() << "\n";
    std::cout << "[+] is_debugger_present = "
              << (stealth::detection::is_debugger_present() ? "true" : "false") << "\n";

    auto mb = stealth::get_function<int(*)(HWND, LPCWSTR, LPCWSTR, UINT)>("user32.dll", "MessageBoxW");
    if (mb) {
        std::cout << "[+] MessageBoxW resolved at "
                  << reinterpret_cast<void*>(mb)
                  << " (would normally display a dialog now)\n";
    } else {
        std::cout << "[!] MessageBoxW resolution failed\n";
    }

    stealth::module_loader k32("kernel32.dll");
    if (k32.is_valid()) {
        auto gt = k32.get_function<ULONGLONG(*)()>("GetTickCount64");
        if (gt) {
            std::cout << "[+] symbolic-free kernel32.GetTickCount64 resolved (uptime="
                      << gt() << "ms)\n";
        }
    }

    using GT_t = ULONGLONG(*)();
    auto gth = stealth::get_function_by_hash<GT_t>(
        stealth::hashes::fnv("kernel32.dll"),
        stealth::hashes::fnv("GetTickCount64"));
    if (gth) {
        std::cout << "[+] hash-based resolver returns same uptime: "
                  << gth() << "ms\n";
    }

    auto s = stealth::detection::scan();
    std::cout << "[+] signals: peb=" << s.peb_debug_flag
              << " remote=" << s.remote_debugger
              << " timing=" << s.timing_anomaly
              << " hwbp=" << s.hwbp_count << "\n";
#endif

    std::cout << "[+] smoke test complete\n";
    return 0;
}
