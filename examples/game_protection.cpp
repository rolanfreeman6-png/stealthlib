#include "stealthlib/stealth.hpp"
#include <iostream>
#include <windows.h>

int main() {
    std::cout << "[+] StealthLib Game Protection Example\n";
    std::cout << "[*] Version: " << stealth::version() << "\n\n";

    auto api_key = stealth::S("sk-prod-a1b2c3d4e5f6g7h8i9j0");
    std::cout << "[*] Protected API Key: " << api_key << "\n";

    auto game_server_ip = stealth::S("192.168.1.100:27015");
    std::cout << "[*] Game Server IP: " << game_server_ip << "\n";

    auto database_password = stealth::S("P@ssw0rd!GameDB#2024");
    std::cout << "[*] Database Password: " << database_password << "\n";

    auto mod_api_secret = stealth::S("MOD_SECRET_KEY_ABC123");
    std::cout << "[*] Mod API Secret: " << mod_api_secret << "\n";

    auto telemetry_endpoint = stealth::S("https://telemetry.game-server.net/api/v2");
    std::cout << "[*] Telemetry Endpoint: " << telemetry_endpoint << "\n";

    auto encrypted_auth = stealth::encoding::base64_encode("player_auth_token_xyz789");
    std::cout << "[*] Base64 Auth Token: " << encrypted_auth << "\n";

    using MessageBoxW_t = int(*)(HWND, LPCWSTR, LPCWSTR, UINT);
    auto MessageBoxW = stealth::get_function<MessageBoxW_t>("user32.dll", "MessageBoxW");
    if (MessageBoxW) {
        auto title = stealth::SW(L"StealthLib Protected");
        auto msg = stealth::SW(L"Game sensitive data is protected!\nCheck the console for details.");
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

    std::cout << "\n[+] All sensitive strings and APIs resolved without IAT!\n";
    std::cout << "[+] Example completed successfully.\n";

    return 0;
}
