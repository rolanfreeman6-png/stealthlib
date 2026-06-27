#include "stealthlib/stealth.hpp"
#include <iostream>
#include <cstring>
#include <windows.h>

int main() {
    std::cout << "[+] StealthLib Server Protection Example\n";
    std::cout << "[*] Version: " << stealth::version() << "\n\n";

    std::cout << "[*] Protecting server configuration...\n\n";

    auto db_connection = S("Server=db.prod.internal;Database=users;User=admin;Password=P@ssw0rd123!");
    std::cout << "[*] DB Connection String: " << db_connection << "\n";

    auto redis_password = S("redis_prod_password_xyz789");
    std::cout << "[*] Redis Password: " << redis_password << "\n";

    auto jwt_secret = S("JWT_SECRET_KEY_SUPER_SECURE_123456789");
    std::cout << "[*] JWT Secret: " << jwt_secret << "\n";

    auto aws_access_key = S("AKIAIOSFODNN7EXAMPLE");
    std::cout << "[*] AWS Access Key: " << aws_access_key << "\n";

    auto aws_secret_key = S("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    std::cout << "[*] AWS Secret Key: " << aws_secret_key << "\n";

    auto internal_api_endpoint = S("https://internal-api.company.local/v2/");
    std::cout << "[*] Internal API Endpoint: " << internal_api_endpoint << "\n";

    auto encryption_key = S("ENCRYPT_KEY_AES256_PROD_2024");
    std::cout << "[*] Encryption Key: " << encryption_key << "\n";

    auto smtp_password = S("smtp_server_password_2024!");
    std::cout << "[*] SMTP Password: " << smtp_password << "\n";

    std::cout << "\n[*] Encoding sensitive data...\n";
    auto encoded_db = stealth::encoding::base64_encode("db_connection_string_encoded");
    std::cout << "[*] Base64 Encoded: " << encoded_db << "\n";

    auto encoded_key = stealth::encoding::hex_encode(encryption_key, std::strlen(encryption_key));
    std::cout << "[*] Hex Encoded Key: " << encoded_key << "\n";

    std::cout << "\n[*] Testing dynamic API resolution (no IAT)...\n";

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

    std::cout << "\n[+] Server sensitive data protected!\n";
    std::cout << "[+] All APIs resolved without IAT entries!\n";
    std::cout << "[+] Example completed successfully.\n";

    return 0;
}
