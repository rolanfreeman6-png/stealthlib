#include "stealthlib/stealth.hpp"
#include <iostream>
#include <cstring>
#include <windows.h>

int main() {
    std::cout << "[+] StealthLib Server Protection Example\n";
    std::cout << "[*] Version: " << stealth::version() << "\n\n";

    std::cout << "[*] Demonstrating server configuration literals...\n\n";

    // Example placeholder values — NOT real credentials. // NOSONAR
    // StealthLib transforms these at compile time; verify emitted binaries per target.
    auto db_connection = S("Server=EXAMPLE.local;Database=example_db;User=example_user;Password=EXAMPLE_PLACEHOLDER_NOT_REAL");  // NOSONAR — example placeholder
    std::cout << "[*] DB Connection String: " << db_connection << "\n";

    auto redis_password = S("example_placeholder_redis_token");
    std::cout << "[*] Redis placeholder: " << redis_password << "\n";

    auto jwt_secret = S("EXAMPLE_JWT_SECRET_PLACEHOLDER_123456789");
    std::cout << "[*] JWT placeholder: " << jwt_secret << "\n";

    auto aws_access_key = S("EXAMPLE_AWS_KEY_PLACEHOLDER_NOT_REAL");  // NOSONAR — placeholder
    std::cout << "[*] AWS Access Key: " << aws_access_key << "\n";

    auto aws_secret_key = S("EXAMPLE_PLACEHOLDER_SECRET_KEY_NOT_REAL");
    std::cout << "[*] AWS secret placeholder: " << aws_secret_key << "\n";

    auto internal_api_endpoint = S("https://internal-api.company.local/v2/");
    std::cout << "[*] Internal API Endpoint: " << internal_api_endpoint << "\n";

    auto encryption_key = S("EXAMPLE_ENCRYPTION_KEY_PLACEHOLDER");
    std::cout << "[*] Encryption Key: " << encryption_key << "\n";

    auto smtp_password = S("example_smtp_password_placeholder");
    std::cout << "[*] SMTP placeholder: " << smtp_password << "\n";

    std::cout << "\n[*] Encoding sensitive data...\n";
    auto encoded_db = stealth::encoding::base64_encode("db_connection_string_encoded");
    std::cout << "[*] Base64 Encoded: " << encoded_db << "\n";

    auto encoded_key = stealth::encoding::hex_encode(encryption_key, std::strlen(encryption_key));
    std::cout << "[*] Hex Encoded Key: " << encoded_key << "\n";

    std::cout << "\n[*] Testing dynamic API resolution for selected APIs...\n";

    using VirtualAlloc_t = LPVOID(*)(LPVOID, SIZE_T, DWORD, DWORD);
    auto VirtualAlloc = stealth::get_function<VirtualAlloc_t>("kernel32.dll", "VirtualAlloc");
    if (VirtualAlloc) {
        std::cout << "[+] VirtualAlloc resolved dynamically\n";
        auto mem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (mem) {
            std::cout << "[+] Memory allocated at: " << mem << "\n";
            using VirtualFree_t = BOOL(*)(LPVOID, SIZE_T, DWORD);
            auto VirtualFree = stealth::get_function<VirtualFree_t>("kernel32.dll", "VirtualFree");
            if (VirtualFree) {
                VirtualFree(mem, 0, MEM_RELEASE);
                std::cout << "[+] Memory freed successfully\n";
            }
        }
    }

    using CreateFileW_t = HANDLE(*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    auto CreateFileW = stealth::get_function<CreateFileW_t>("kernel32.dll", "CreateFileW");
    if (CreateFileW) {
        std::cout << "[+] CreateFileW resolved dynamically\n";
    }

    using RegOpenKeyExW_t = LONG(*)(HKEY, LPCWSTR, DWORD, DWORD, PHKEY);
    auto RegOpenKeyExW = stealth::get_function<RegOpenKeyExW_t>("advapi32.dll", "RegOpenKeyExW");
    if (RegOpenKeyExW) {
        std::cout << "[+] RegOpenKeyExW resolved dynamically\n";
    }

    std::cout << "\n[+] Demonstration placeholders processed.\n";
    std::cout << "[+] Selected APIs resolved through StealthLib helpers.\n";
    std::cout << "[+] Example completed successfully.\n";

    return 0;
}
