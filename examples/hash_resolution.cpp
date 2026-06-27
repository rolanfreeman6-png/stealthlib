// StealthLib v2.2.0 example: HASH-BASED API RESOLUTION
// ---------------------------------------------------------
// What you SEE in the source: hashes of API/module names.
// What you DO NOT see in the binary (NOT visible to `strings.exe`):
//   - "user32.dll"
//   - "kernel32.dll"
//   - "MessageBoxW"
//   - "GetTickCount64"
//   - "GetComputerNameW"
//
// In the compiled binary, the module names and function names are replaced
// with 64-bit FNV-1a hashes, computed at compile time. The resolution walks
// PEB -> LDR -> InLoadOrderModuleList -> export directory, hashing each
// candidate name until it matches. No symbols appear in .rdata, .strings,
// or any IAT entry that a static reverse engineer could grep for.
//
// Combined with `S("...")` macro for string literals (also compiled out of
// the .text section), this is the same "xorstr simplicity" pattern applied
// to API resolution. There are no third-party headers required.

#include "stealthlib/stealth.hpp"
#include <cstring>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#endif

int main() {
    std::cout << "[+] StealthLib v" << stealth::version()
              << ": hash-based API resolution demo\n";

    std::cout << "[*] Build key: 0x" << std::hex << stealth::build_key() << std::dec << "\n";

#ifdef _WIN32
    constexpr uint64_t h_user32     = stealth::hashes::fnv("user32.dll");
    constexpr uint64_t h_kernel32   = stealth::hashes::fnv("kernel32.dll");
    constexpr uint64_t h_msgbox_w   = stealth::hashes::fnv("MessageBoxW");
    constexpr uint64_t h_tick64     = stealth::hashes::fnv("GetTickCount64");
    constexpr uint64_t h_getpcnamew = stealth::hashes::fnv("GetComputerNameW");

    std::cout << "[*] module hash(user32.dll)   = 0x" << std::hex << h_user32 << "\n";
    std::cout << "[*] module hash(kernel32.dll) = 0x" << std::hex << h_kernel32 << "\n";
    std::cout << "[*] func   hash(MessageBoxW)  = 0x" << std::hex << h_msgbox_w << "\n";

    using MessageBoxW_t = int(*)(HWND, LPCWSTR, LPCWSTR, UINT);
    auto mb = stealth::get_function_by_hash<MessageBoxW_t>(h_user32, h_msgbox_w);
    if (mb) {
        std::cout << "[+] MessageBoxW resolved by hash at " << reinterpret_cast<void*>(mb) << "\n";
        (void)mb;
    } else {
        std::cout << "[!] Could not resolve MessageBoxW (environment-specific)\n";
    }

    using GetTickCount64_t = ULONGLONG();
    auto gt = stealth::stealth_api<GetTickCount64_t>(h_kernel32, h_tick64);
    if (gt.is_valid()) {
        std::cout << "[+] GetTickCount64 resolved by hash: uptime=" << gt.get()() << "ms\n";
    }

    stealth::module_loader k(h_kernel32);
    auto gcn = k.get_function_by_hash<BOOL(*)(LPWSTR, LPDWORD)>(h_getpcnamew);
    if (gcn) {
        wchar_t name[256] = {};
        DWORD sz = 255;
        if (gcn(name, &sz)) {
            std::cout << "[+] Computer name resolved by hash: ";
            for (DWORD i = 0; i < sz; ++i) std::cout << static_cast<char>(name[i]);
            std::cout << "\n";
        }
    }

    std::cout << "[+] Anti-debug signals scan:\n";
    auto s = stealth::detection::scan();
    std::cout << "    PEB BeingDebugged = " << (s.peb_debug_flag ? "true" : "false") << "\n";
    std::cout << "    Remote debugger  = " << (s.remote_debugger ? "true" : "false") << "\n";
    std::cout << "    Timing anomaly   = " << (s.timing_anomaly ? "true" : "false") << "\n";
    std::cout << "    HW breakpoints   = " << s.hwbp_count << "\n";

    std::cout << "\n[+] RAII unlock demo:\n";
    {
        auto lit = S("hi");
        auto lock = lit.unlock();
        std::cout << "    scope 1: decrypted = " << lock.c_str() << "\n";
        auto wlit = SW(L"hi wide");
        auto wlock = wlit.unlock();
        std::wcout << L"    scope 1: wide = " << wlock.c_str() << L"\n";
    }
    std::cout << "    scope exit: re-encrypted (string not visible in this dump)\n";
#else
    std::cout << "[*] Platform: non-Windows. Hash-based resolver is no-op here.\n";
    constexpr uint64_t h = stealth::hashes::fnv("user32.dll");
    std::cout << "[*] hash('user32.dll') = " << h << "\n";
#endif

    return 0;
}
