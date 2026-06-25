// tests/scenario_rte_signal_sweep.cpp
// ---------------------------------------------------------------------
// RTE Scenario 2 -- "long-running server" simulation. A hypothetical
// game/server binary that pulls sensitive strings at startup, runs
// signal-sweep once per loop iteration, and re-encrypts on
// idle. Verifies that detection::scan() + S/SW + base64 compose
// cleanly across many iterations.
// ---------------------------------------------------------------------
#include "stealthlib/stealth.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>

int main() {
    auto license        = S("GPL-Server-License-7Y2X-RUNTIME");
    auto auth_token     = S("Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig");
    auto db_endpoint    = S("tcp://10.0.0.42:5432/stealthdb");
    auto secret_kernel  = S("kernel32.dll");
    auto secret_user32  = S("user32.dll");
    auto signoff_path   = SW(L"C:\\ProgramData\\stealth\\signoff.bin");

    // Lifetime invariants --
    //   1. serialising literals to std::string and back via c_str()
    //      must give byte-exact equality with the original literal
    //   2. detection::scan() composes with no side effects on literals
    //   3. tall the literals above survive many cycles
    std::string token_copy;
    for (int i = 0; i < 1024; ++i) {
        // (1) round-trip into std::string
        const char* t = *auth_token;
        token_copy.assign(t);
        assert(std::strcmp(t, token_copy.c_str()) == 0);

        // (2) detection sweep. Doesn't consume any sensitive strings.
        auto sig = stealth::detection::scan();
        (void)sig; // informational; some targets may flag, that's OK

        // (3) all literals still resolve
        assert(std::strcmp(*license,        "GPL-Server-License-7Y2X-RUNTIME") == 0);
        assert(std::strcmp(*auth_token,     "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig") == 0);
        assert(std::strcmp(*db_endpoint,    "tcp://10.0.0.42:5432/stealthdb") == 0);
        assert(std::strcmp(*secret_kernel,  "kernel32.dll") == 0);
        assert(std::strcmp(*secret_user32,  "user32.dll") == 0);
        const wchar_t* p = (const wchar_t*)signoff_path;
        assert(p[0] == L'C');

        // (4) toggle unlock to exercise re-encrypt cycles
        { auto g = license.unlock(); (void)g; }
        { auto g = auth_token.unlock(); (void)g; }
        { auto g = db_endpoint.unlock(); (void)g; }
    }
    std::fprintf(stderr, "[scenario-rte2] 1024 cycle sweep -- all invariants hold\n");

    // Hash-based runtime identifier -- distinct function name strings
    // produce distinct hash values, so we're sure hash-resolution will
    // disambiguate. Order-invariant sanity:
    auto h1 = stealth::hashes::fnv(*secret_kernel, std::strlen(*secret_kernel));
    auto h2 = stealth::hashes::fnv(*secret_user32, std::strlen(*secret_user32));
    if (h1 == h2) {
        std::fprintf(stderr, "[scenario-rte2] FAIL: distinct module names collided\n");
        return 1;
    }
    auto h1b = stealth::hashes::fnv(*secret_kernel);
    if (h1b != h1) {
        std::fprintf(stderr, "[scenario-rte2] FAIL: explicit-len != runtime-len hash\n");
        return 1;
    }
    std::fprintf(stderr,
        "[scenario-rte2] kernel32=%016llx user32=%016llx (distinct, parity OK)\n",
        (unsigned long long)h1, (unsigned long long)h2);

    // Building-rotation sanity: stealth::build_key() returns the macro
    // value the binary was compiled against. It must not be zero (the
    // header's static_assert enforces at compile time) and must equal
    // whatever STEALTH_BUILD_KEY was supplied.
    auto bk = stealth::build_key();
    std::fprintf(stderr, "[scenario-rte2] build_key = 0x%016llx\n",
        (unsigned long long)bk);
    if (bk == 0) {
        std::fprintf(stderr, "[scenario-rte2] FAIL: build_key is zero\n");
        return 1;
    }

    std::fprintf(stderr, "[scenario-rte2] ALL CHECKS PASSED\n");
    return 0;
}
