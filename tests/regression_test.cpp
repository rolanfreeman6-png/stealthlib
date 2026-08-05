#include "stealthlib/stealth.hpp"

#include <cassert>
#include <cstring>
#include <string>
#include <windows.h>

extern "C" const char* stealth_regression_from_a();
extern "C" const char* stealth_regression_from_b();
extern "C" void stealth_regression_cipher_from_a(unsigned char out[32]);
extern "C" void stealth_regression_cipher_from_b(unsigned char out[32]);

static void test_cross_translation_unit_strings() {
    const char* a = stealth_regression_from_a();
    const char* b = stealth_regression_from_b();
    assert(std::strcmp(a, "CROSS_TRANSLATION_UNIT_KEY_MATERIAL") == 0);
    assert(std::strcmp(b, "CROSS_TRANSLATION_UNIT_KEY_MATERIAL") == 0);
    assert(a != b);

    unsigned char cipher_a[32] = {};
    unsigned char cipher_b[32] = {};
    stealth_regression_cipher_from_a(cipher_a);
    stealth_regression_cipher_from_b(cipher_b);
    assert(std::memcmp(cipher_a, cipher_b, sizeof(cipher_a)) != 0);
}

static void test_decode_rejects_truncation_and_bad_padding() {
    std::string data(12, 'A');
    auto b64 = stealth::encoding::base64_encode(data);
    auto b64_round = stealth::encoding::base64_decode(b64);
    assert(b64_round.has_value() && *b64_round == data);

    auto hex = stealth::encoding::hex_encode(data);
    auto hex_round = stealth::encoding::hex_decode(hex);
    assert(hex_round.has_value());

    assert(!stealth::encoding::base64_decode("AA=A").has_value());       // mid-stream padding
    assert(!stealth::encoding::base64_decode("AAAA====").has_value());   // excess padding
    assert(!stealth::encoding::base64_decode("A").has_value());          // len % 4 != 0
    assert(!stealth::encoding::base64_decode("AAAA_BBBB").has_value());  // invalid char
    assert(!stealth::encoding::base64_decode("AB==").has_value());       // non-canonical one-byte pad bits
    assert(!stealth::encoding::base64_decode("AAB=").has_value());       // non-canonical two-byte pad bits
    assert(!stealth::encoding::hex_decode("ABC").has_value());           // odd length
    assert(!stealth::encoding::hex_decode("ZZ").has_value());            // invalid hex chars
}

static void test_null_inputs_fail_closed() {
    assert(!stealth::memory::compare_constant_time(nullptr, "x", 1));
    assert(stealth::memory::compare_constant_time(nullptr, nullptr, 0));
    assert(stealth::encoding::base64_encode(nullptr, 4).empty());
    assert(stealth::encoding::hex_encode(nullptr, 4).empty());
    stealth::encoding::xor_key<8> key{"key"};
    stealth::encoding::xor_encode(nullptr, 4, key);
    stealth::encoding::rot13_encode(nullptr, nullptr, 4);
}

static void test_forwarded_exports_resolve_to_loader_target() {
    void* kernel32 = nullptr;
    assert(stealth::get_module_base(L"kernel32.dll", &kernel32));
    auto heap_alloc = stealth::get_proc(kernel32, "HeapAlloc");
    assert(heap_alloc != nullptr);
    auto loader_result = reinterpret_cast<void*>(
        GetProcAddress(static_cast<HMODULE>(kernel32), "HeapAlloc"));
    assert(heap_alloc == loader_result);
}

static void test_stealth_api_callable_forms() {
    stealth::stealth_api<DWORD()> ptr_api("kernel32.dll", "GetTickCount");
    assert(ptr_api.is_valid());
    (void)ptr_api.get()();

    stealth::stealth_api<DWORD()> func_api("kernel32.dll", "GetTickCount");
    assert(func_api.is_valid());
    (void)func_api.get()();
}

int main() {
    test_cross_translation_unit_strings();
    test_decode_rejects_truncation_and_bad_padding();
    test_null_inputs_fail_closed();
    test_forwarded_exports_resolve_to_loader_target();
    test_stealth_api_callable_forms();
    return 0;
}
