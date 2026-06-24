#include "stealthlib/stealth.hpp"

#include <cassert>
#include <cstring>
#include <string>

int main() {
    auto secret = S("portable_secret");
    assert(std::strcmp(secret, "portable_secret") == 0);

    auto encoded = stealth::encoding::base64_encode("portable");
    auto decoded = stealth::encoding::base64_decode<32>(encoded);
    assert(decoded.has_value());
    assert(std::string(reinterpret_cast<const char*>(decoded.data), decoded.len) == "portable");

    auto hex = stealth::encoding::hex_encode("ok");
    auto raw = stealth::encoding::hex_decode<8>(hex);
    assert(raw.has_value());
    assert(raw.len == 2);

    assert(stealth::memory::compare_constant_time("aa", "aa", 2));
    assert(!stealth::memory::compare_constant_time("aa", "ab", 2));
    assert(!stealth::detection::is_debugger_present());
    return 0;
}
