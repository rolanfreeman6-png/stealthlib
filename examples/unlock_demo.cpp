// StealthLib v2.2.2 example: RAII UNLOCK FOR ENCRYPTED STRINGS
// ---------------------------------------------------------
// Demonstrates the named-object `unlock()` RAII pattern:
//  - When unlock() is called, plaintext exposes via .c_str().
//  - When the returned guard object goes out of scope, the
//    underlying encrypted buffer is RE-encrypted and plaintext object
//    storage is wiped.
//
// This narrows, but does not eliminate, the plaintext lifetime window.
// The encrypted object must outlive the returned guard.

#include "stealthlib/stealth.hpp"
#include <iostream>

int main() {
    std::cout << "[+] StealthLib unlock demo v" << stealth::version() << "\n";

    auto api = S("EXAMPLE_TOKEN_PLACEHOLDER_NOT_REAL");

    {
        auto lock = api.unlock();
        std::cout << "[*] unlocked only within scope: " << lock.c_str() << "\n";
        std::cout << "[*] lock.size() = " << lock.size() << "\n";
    }
    std::cout << "[+] scope exited -> ciphertext restored\n";

    {
        auto wide_secret = SW(L"\x0421\x0435\x043A\x0440\x0435\x0442");
        auto wlock = wide_secret.unlock();
        std::wcout << L"[*] wide lock: " << wlock.c_str() << L"\n";
    }
    std::cout << "[+] all locks released\n";

    return 0;
}
