// StealthLib v2.1.2 example: RAII UNLOCK FOR ENCRYPTED STRINGS
// ---------------------------------------------------------
// Demonstrates the `S("...").unlock()` RAII pattern:
//  - When unlock() is called, plaintext exposes via .c_str().
//  - When the returned guard object goes out of scope, the
//    underlying encrypted buffer is RE-encrypted (volatile wipe
//    over XOR-decrypted bytes) so the decrypted text never
//    lingers in the heap.
//
// This narrows the window during which a memory-dump analysis
// can recover sensitive plaintext from your process.

#include "stealthlib/stealth.hpp"
#include <iostream>

int main() {
    std::cout << "[+] StealthLib unlock demo v" << stealth::version() << "\n";

    auto api = S("sk-live-very-sensitive-token-1234567890");
    std::cout << "[*] 'api' identity: " << api.c_str() << "\n";

    {
        auto lock = api.unlock();
        std::cout << "[*] locked within scope: " << lock.c_str() << "\n";
        std::cout << "[*] lock.size() = " << lock.size() << "\n";
    }
    std::cout << "[+] scope exited -> ciphertext restored\n";
    std::cout << "[*] still decryptable after re-encryption: " << api.c_str() << "\n";

    {
        auto wlock = SW(L"\x0421\x0435\x043A\x0440\x0435\x0442").unlock();
        std::wcout << L"[*] wide lock: " << wlock.c_str() << L"\n";
    }
    std::cout << "[+] all locks released\n";

    return 0;
}
