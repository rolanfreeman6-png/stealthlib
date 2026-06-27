#include "stealthlib/stealth.hpp"

extern "C" const char* stealth_regression_from_a() {
    static auto lit = S("AAAA");
    return lit;
}
