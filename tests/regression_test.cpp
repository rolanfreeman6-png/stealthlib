#include "stealthlib/stealth.hpp"

#include <cassert>
#include <cstring>
#include <string>
#include <windows.h>

extern "C" const char* stealth_regression_from_a();
extern "C" const char* stealth_regression_from_b();

static void test_cross_translation_unit_strings() {
    const char* a = stealth_regression_from_a();
    const char* b = stealth_regression_from_b();
    assert(std::strcmp(a, "AAAA") == 0);
    assert(std::strcmp(b, "BBBB") == 0);
    assert(a != b);
}

static void test_decode_rejects_truncation_and_bad_padding() {
    std::string data(12, 'A');
    auto b64 = stealth::encoding::base64_encode(data);
    auto b64_small = stealth::encoding::base64_decode<4>(b64);
    assert(!b64_small.has_value());

    auto hex = stealth::encoding::hex_encode(data);
    auto hex_small = stealth::encoding::hex_decode<4>(hex);
    assert(!hex_small.has_value());

    assert(!stealth::encoding::base64_decode<16>("AA=A").has_value());
    assert(!stealth::encoding::base64_decode<16>("AAAA====").has_value());
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

static void test_forwarded_exports_resolve_to_code() {
    void* kernel32 = nullptr;
    assert(stealth::get_module_base(L"kernel32.dll", &kernel32));
    auto nt = stealth::get_nt(kernel32);
    assert(nt != nullptr);
    auto heap_alloc = stealth::get_proc(kernel32, "HeapAlloc");
    assert(heap_alloc != nullptr);
    auto rva = static_cast<unsigned long>(
        static_cast<char*>(heap_alloc) - static_cast<char*>(kernel32));
    auto export_rva = nt->DataDirectory[0];
    auto export_size = nt->DataDirectory[1];
    assert(!(rva >= export_rva && rva < export_rva + export_size));
}

static void test_stealth_api_callable_forms() {
    stealth::stealth_api<DWORD(*)()> ptr_api("kernel32.dll", "GetTickCount");
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
    test_forwarded_exports_resolve_to_code();
    test_stealth_api_callable_forms();
    return 0;
}
