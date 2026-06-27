// libFuzzer harness for the StealthLib string subsystem.
//
// S()/SW() are consteval (compile-time only) so they cannot be fed random
// runtime input -- that is what preserves the .rodata plaintext-elision
// invariant. This harness therefore (a) fuzzes secure_string<> with random
// bytes (boundary, truncation, clear-zero) and (b) exercises the
// decrypt/reencrypt RAII round-trip across a fixed literal set under the
// harness so any asymmetry surfaces during fuzzing.
#include "stealthlib/stealth.hpp"

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;

    // (a) secure_string boundary + clear-zero with random bytes.
    size_t n = size > 255 ? 255 : size;
    char buf[256] = {};
    std::memcpy(buf, data, n);
    buf[n] = '\0';
    stealth::secure_string<256> s(buf);
    if (s.length() > 255) std::abort();
    // secure_string stores a NUL-terminated C string, so its length is
    // strlen(buf) (it stops at the first embedded NUL), not n.
    if (s.length() != std::strlen(buf)) std::abort();
    if (std::strcmp(s.c_str(), buf) != 0) std::abort();
    s.clear();
    for (size_t i = 0; i < 256; ++i)
        if (s.c_str()[i] != '\0') std::abort();

    // nullptr ctor must stay empty (fail-closed, no read of nullptr).
    stealth::secure_string<256> empty(nullptr);
    if (empty.length() != 0 || empty.c_str()[0] != '\0') std::abort();

    // (b) decrypt -> unlock(reencrypt) -> decrypt round-trip on fixed
    // literals. c_str() must always yield the plaintext; after the guard
    // scope the buffer is re-encrypted and decrypts back to the same text.
    auto check = [](auto& lit, const char* want) {
        if (std::strcmp(lit.c_str(), want) != 0) std::abort();
        { auto g = lit.unlock(); if (std::strcmp(g.c_str(), want) != 0) std::abort(); }
        if (std::strcmp(lit.c_str(), want) != 0) std::abort();
    };
    auto a = S("Hello, World!");                            check(a, "Hello, World!");
    auto b = S("sk-prod-key-1234567890abcdef");            check(b, "sk-prod-key-1234567890abcdef");
    auto c = S("A");                                       check(c, "A");
    auto d = S("!@#$%^&*()_+-=[]{}|;':\",./<>?");          check(d, "!@#$%^&*()_+-=[]{}|;':\",./<>?");
    auto e = S("");                                        check(e, "");
    auto w = SW(L"Wide Fuzz Probe");                       if (std::wcscmp(w.c_str(), L"Wide Fuzz Probe") != 0) std::abort();
    { auto g = w.unlock(); if (std::wcscmp(g.c_str(), L"Wide Fuzz Probe") != 0) std::abort(); }
    if (std::wcscmp(w.c_str(), L"Wide Fuzz Probe") != 0) std::abort();

    (void)data;
    return 0;
}

#ifndef STEALTH_LIBFUZZER_LINKED
int main() {
    const uint8_t seed[] = { 'f','u','z','z','_','s','e','e','d',0,
                             0x00,0x01,0xFF,0x7F,0x80,0x2E,0x5A };
    int failures = 0;
    if (LLVMFuzzerTestOneInput(seed, sizeof seed) != 0) ++failures;
    if (LLVMFuzzerTestOneInput(reinterpret_cast<const uint8_t*>(""), 0) != 0) ++failures;
    return failures ? 1 : 0;
}
#endif
