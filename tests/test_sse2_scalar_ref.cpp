#ifdef STEALTHLIB_SSE2_DECRYPT
#undef STEALTHLIB_SSE2_DECRYPT
#endif
#define STEALTHLIB_SSE2_DECRYPT 0

#include "stealthlib/stealth.hpp"

extern "C" const char* stealthlib_sse2_scalar_reference() {
    static auto literal = S(
        "STEALTHLIB_SSE2_PARITY_PROBE_0123456789ABCDEF!@#$%^&*()_+=-`~[]{}|;:',.<>/?zZ"
    );
    return literal.c_str();
}
