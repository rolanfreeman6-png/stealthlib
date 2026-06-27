// libFuzzer harness for the StealthLib encoding decoders.
//
// Invariants under fuzz: base64/hex/xor/rot13 round-trip identity on
// random bytes, and base64_decode/hex_decode are fail-closed on arbitrary
// (garbage) input -- no crash, return nullopt or a valid value.
#include "stealthlib/stealth.hpp"

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>
#include <cstdio>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    std::string_view raw(reinterpret_cast<const char*>(data), size);

    // base64 round-trip.
    auto b64 = stealth::encoding::base64_encode(raw);
    auto bdec = stealth::encoding::base64_decode(b64);
    if (!bdec.has_value()) std::abort();
    if (bdec->size() != size || std::memcmp(bdec->data(), data, size) != 0) std::abort();

    // base64_decode on raw (likely invalid) bytes: must not crash.
    { auto r = stealth::encoding::base64_decode(raw); (void)r; }

    // hex round-trip.
    auto hx = stealth::encoding::hex_encode(raw);
    auto hdec = stealth::encoding::hex_decode(hx);
    if (!hdec.has_value()) std::abort();
    if (hdec->size() != size || std::memcmp(hdec->data(), data, size) != 0) std::abort();

    // hex_decode on garbage: must not crash.
    { auto r = stealth::encoding::hex_decode(raw); (void)r; }

    // xor round-trip with a key derived from the input.
    {
        uint8_t kbuf[16] = {};
        for (size_t i = 0; i < 16; ++i) kbuf[i] = data[(size - 1 - i) % size];
        stealth::encoding::xor_key<16> k(kbuf, 16);
        std::vector<uint8_t> v(data, data + size);
        auto original = v;
        stealth::encoding::xor_encode(v.data(), v.size(), k);
        stealth::encoding::xor_decode(v.data(), v.size(), k);
        if (v != original) std::abort();
    }

    // rot13 symmetry: in-place encode then decode == identity.
    {
        std::vector<uint8_t> v(data, data + size);
        auto original = v;
        stealth::encoding::rot13_encode(v.data(), v.data(), size);
        stealth::encoding::rot13_decode(v.data(), v.data(), size);
        if (v != original) std::abort();
    }

    return 0;
}

#ifndef STEALTH_LIBFUZZER_LINKED
int main() {
    const uint8_t seed[] = { 'A','B','C','D', 0, 0xFF, 0x2E, 'Z',
                             '=','=','!','@', 0x0D, 0x0A, 'z', 0x9A };
    int failures = 0;
    if (LLVMFuzzerTestOneInput(seed, sizeof seed) != 0) ++failures;
    // a deliberately malformed base64-ish blob (mid-stream padding)
    const uint8_t bad[] = { 'A','A','=','A','A','A','A','=','=','=','=' };
    if (LLVMFuzzerTestOneInput(bad, sizeof bad) != 0) ++failures;
    return failures ? 1 : 0;
}
#endif
