#include "stealthlib/stealth.hpp"

#include <cstring>

int main() {
    auto narrow = S("STEALTHLIB_BINARY_SCAN_SENTINEL_NARROW_9F13E2F0");
    auto wide = SW(L"STEALTHLIB_BINARY_SCAN_SENTINEL_WIDE_9F13E2F0");
    return std::strlen(narrow) == 0 || wide[0] == L'\0';
}
