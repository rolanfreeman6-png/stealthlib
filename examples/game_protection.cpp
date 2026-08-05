#include "stealthlib/stealth.hpp"
#include <iostream>
#include <windows.h>

int main() {
    std::cout << "[+] StealthLib Game Protection Example\n";
    std::cout << "[*] Version: " << stealth::version() << "\n\n";

    auto api_key = S("EXAMPLE_API_KEY_PLACEHOLDER_NOT_REAL");
    std::cout << "[*] API key placeholder: " << api_key << "\n";

    auto game_server_ip = S("203.0.113.10:27015");
    std::cout << "[*] Game Server IP: " << game_server_ip << "\n";

    auto database_password = S("EXAMPLE_DATABASE_PASSWORD_PLACEHOLDER");
    std::cout << "[*] Database password placeholder: " << database_password << "\n";

    auto mod_api_secret = S("EXAMPLE_MOD_SECRET_PLACEHOLDER");
    std::cout << "[*] Mod API secret placeholder: " << mod_api_secret << "\n";

    auto telemetry_endpoint = S("https://telemetry.game-server.net/api/v2");
    std::cout << "[*] Telemetry Endpoint: " << telemetry_endpoint << "\n";

    auto encrypted_auth = stealth::encoding::base64_encode("example_player_auth_token");
    std::cout << "[*] Base64 Auth Token: " << encrypted_auth << "\n";

    using MessageBoxW_t = int(*)(HWND, LPCWSTR, LPCWSTR, UINT);
    auto MessageBoxW = stealth::get_function<MessageBoxW_t>("user32.dll", "MessageBoxW");
    if (MessageBoxW) {
        auto title = SW(L"StealthLib Demo");
        auto msg = SW(L"Selected demo literals were transformed.\nCheck the console for details.");
        MessageBoxW(nullptr, msg, title, MB_OK | MB_ICONINFORMATION);
    }

    if (stealth::detection::is_debugger_present()) {
        std::cout << "\n[!] WARNING: Debugger detected!\n";
    } else {
        std::cout << "\n[+] No debugger detected\n";
    }

    std::cout << "\n[+] Dynamic API Resolution Test:\n";
    using GetCurrentProcessId_t = DWORD(*)();
    auto GetCurrentProcessId = stealth::get_function<GetCurrentProcessId_t>("kernel32.dll", "GetCurrentProcessId");
    if (GetCurrentProcessId) {
        std::cout << "[*] Current Process ID: " << GetCurrentProcessId() << "\n";
    }

    using GetTickCount64_t = ULONGLONG(*)();
    auto GetTickCount64 = stealth::get_function<GetTickCount64_t>("kernel32.dll", "GetTickCount64");
    if (GetTickCount64) {
        std::cout << "[*] System Uptime: " << GetTickCount64() << " ms\n";
    }

    std::cout << "\n[+] Demonstration literals and selected API resolution completed.\n";
    std::cout << "[+] Example completed successfully.\n";

    return 0;
}
