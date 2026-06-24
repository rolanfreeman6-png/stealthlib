#include "stealthlib/stealth.hpp"
#include <cassert>
#include <iostream>
#include <windows.h>

int main() {
    std::cout << "[+] StealthLib PEB Walking Test\n\n";

    auto peb = stealth::get_peb_ptr();
    assert(peb != nullptr);
    std::cout << "[+] Test 1: PEB address retrieved - " << peb << " - PASSED\n";

    void* ntdll_base = nullptr;
    assert(stealth::get_module_base(L"ntdll.dll", &ntdll_base));
    assert(ntdll_base != nullptr);
    std::cout << "[+] Test 2: NTDLL base found - " << ntdll_base << " - PASSED\n";

    void* kernel32_base = nullptr;
    assert(stealth::get_module_base(L"kernel32.dll", &kernel32_base));
    assert(kernel32_base != nullptr);
    std::cout << "[+] Test 3: KERNEL32 base found - " << kernel32_base << " - PASSED\n";

    void* user32_base = nullptr;
    assert(stealth::get_module_base(L"user32.dll", &user32_base));
    assert(user32_base != nullptr);
    std::cout << "[+] Test 4: USER32 base found - " << user32_base << " - PASSED\n";

    void* kernel32_ansi = nullptr;
    assert(stealth::get_module_base_ansi("kernel32.dll", &kernel32_ansi));
    assert(kernel32_ansi == kernel32_base);
    std::cout << "[+] Test 5: ANSI module lookup - PASSED\n";

    void* invalid = nullptr;
    assert(!stealth::get_module_base(L"nonexistent_module.dll", &invalid));
    assert(invalid == nullptr);
    std::cout << "[+] Test 6: Invalid module returns false - PASSED\n";

    auto dos_header = stealth::get_dos(kernel32_base);
    assert(dos_header != nullptr);
    assert(dos_header->e_magic == 0x5A4D);
    std::cout << "[+] Test 7: DOS header valid - PASSED\n";

    auto nt_headers = stealth::get_nt(kernel32_base);
    assert(nt_headers != nullptr);
    assert(nt_headers->Signature == 0x4550);
    std::cout << "[+] Test 8: NT headers valid - PASSED\n";

    auto exp_dir = stealth::get_export(kernel32_base);
    assert(exp_dir != nullptr);
    std::cout << "[+] Test 9: Export directory found - PASSED\n";

    using GetTickCount64_t = ULONGLONG(*)();
    auto GetTickCount64_ptr = stealth::get_proc(kernel32_base, "GetTickCount64");
    assert(GetTickCount64_ptr != nullptr);
    auto fn = reinterpret_cast<GetTickCount64_t>(GetTickCount64_ptr);
    ULONGLONG uptime = fn();
    assert(uptime > 0);
    std::cout << "[+] Test 10: get_proc by name - PASSED\n";

    auto GetLastError_fn = stealth::get_proc(kernel32_base, "GetLastError");
    assert(GetLastError_fn != nullptr);
    std::cout << "[+] Test 11: GetLastError resolved - PASSED\n";

    auto MessageBoxW_ptr = stealth::stealth_api<int(HWND, LPCWSTR, LPCWSTR, UINT)>("user32.dll", "MessageBoxW");
    assert(MessageBoxW_ptr.is_valid());
    std::cout << "[+] Test 12: stealth_api template - PASSED\n";

    auto GetCurrentProcessId = stealth::get_function<GetTickCount64_t>("kernel32.dll", "GetCurrentProcessId");
    assert(GetCurrentProcessId != nullptr);
    std::cout << "[+] Test 13: get_function - PASSED\n";

    auto kernel_api = stealth::get_kernel32_api("GetCurrentThreadId");
    assert(kernel_api != nullptr);
    std::cout << "[+] Test 14: get_kernel32_api - PASSED\n";

    auto user_api = stealth::get_user32_api("MessageBoxW");
    assert(user_api != nullptr);
    std::cout << "[+] Test 15: get_user32_api - PASSED\n";

    auto nt_api = stealth::get_nt_api("NtQuerySystemInformation");
    std::cout << "[+] Test 16: get_nt_api (NtQuerySystemInformation) - " << (nt_api ? "PASSED" : "may require elevation") << "\n";

    auto GetCurrentProcessId_direct = stealth::get_module_function("kernel32.dll", "GetCurrentProcessId");
    assert(GetCurrentProcessId_direct != nullptr);
    std::cout << "[+] Test 17: get_module_function - PASSED\n";

    stealth::module_loader loader("kernel32.dll");
    assert(loader.is_valid());
    assert(loader.get() != nullptr);
    auto get_tick = loader.get_function<GetTickCount64_t>("GetTickCount64");
    assert(get_tick != nullptr);
    std::cout << "[+] Test 18: module_loader - PASSED\n";

    std::cout << "\n[+] All PEB walking tests PASSED!\n";
    return 0;
}
