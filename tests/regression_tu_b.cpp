#include "stealthlib/stealth.hpp"

extern "C" const char* stealth_regression_from_b() {
    static auto lit = S("BBBB");
    return lit;
}
