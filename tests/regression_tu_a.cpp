#include "stealthlib/stealth.hpp"

extern "C" const char* stealth_regression_from_a() {
    static auto lit = S("CROSS_TRANSLATION_UNIT_KEY_MATERIAL");
    return lit;
}

extern "C" void stealth_regression_cipher_from_a(unsigned char out[32]) {
    static auto lit = S("CROSS_TRANSLATION_UNIT_KEY_MATERIAL");
    for (size_t index = 0; index < 32; ++index) out[index] = static_cast<unsigned char>(lit.impl.encrypted[index]);
}
