#include "stealthlib/stealth.hpp"

#include <cassert>
#include <cstring>
#include <string>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

int main() {
    {
        auto secret = S("portable_secret");
        assert(std::strcmp(secret, "portable_secret") == 0);
    }

    {
        auto encoded = stealth::encoding::base64_encode("portable");
        auto decoded = stealth::encoding::base64_decode(encoded);
        assert(decoded.has_value());
        assert(std::string(decoded->begin(), decoded->end()) == "portable");
    }

    {
        auto hex = stealth::encoding::hex_encode("ok");
        auto raw = stealth::encoding::hex_decode(hex);
        assert(raw.has_value());
        assert(raw->size() == 2);
        assert((*raw)[0] == 'o');
        assert((*raw)[1] == 'k');
    }

    assert(stealth::memory::compare_constant_time("aa", "aa", 2));
    assert(!stealth::memory::compare_constant_time("aa", "ab", 2));

    // Call detection but do not assert its return value
    // (a CI runner may or may not be traced).
#ifdef _WIN32
    (void)stealth::detection::is_debugger_present();
#else
    (void)false;
#endif
    return 0;
}
