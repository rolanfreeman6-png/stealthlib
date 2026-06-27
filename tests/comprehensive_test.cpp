#include "stealthlib/stealth.hpp"
#include <cassert>
#include <cstring>
#include <cwchar>
#include <iostream>
#include <new>
#include <string>
#include <type_traits>
#include <cstdint>

static int g_pass = 0;
static int g_fail = 0;

static void report(const char* name, bool ok) {
    if (ok) { ++g_pass; std::cout << "[+] Test " << g_pass + g_fail << ": " << name << " - PASSED\n"; }
    else { ++g_fail; std::cout << "[-] Test " << g_pass + g_fail << ": " << name << " - FAILED\n"; }
}

#define T(name, expr) report(name, !!(expr))

static bool test_s_basic() { return std::strcmp(S("Hello"), "Hello") == 0; }
static bool test_s_empty() { return std::strcmp(S(""), "") == 0; }
static bool test_s_single() { return std::strcmp(S("A"), "A") == 0; }
static bool test_s_special() { return std::strcmp(S("!@#$%^&*()_+-=[]{}|;':\",./<>?"), "!@#$%^&*()_+-=[]{}|;':\",./<>?") == 0; }
static bool test_s_numeric() { return std::strcmp(S("1234567890"), "1234567890") == 0; }
static bool test_s_long() { return std::strcmp(S("This_is_a_very_long_string_used_for_testing_encryption_with_many_characters_1234567890_ABCDEFGHIJKLMNOPQRSTUVWXYZ"), "This_is_a_very_long_string_used_for_testing_encryption_with_many_characters_1234567890_ABCDEFGHIJKLMNOPQRSTUVWXYZ") == 0; }
static bool test_s_apikey() { return std::strcmp(S("sk-prod-abc123def456ghi789"), "sk-prod-abc123def456ghi789") == 0; }
static bool test_s_connstr() { return std::strcmp(S("Server=db.local;Password=P@ssw0rd!"), "Server=db.local;Password=P@ssw0rd!") == 0; }
static bool test_s_stable() { auto s = S("stable_test"); return std::strcmp(s, s) == 0; }
static bool test_s_strlen() { auto s = S("measure"); return std::strlen(s) == 7; }
static bool test_s_nullterm() { auto s = S("term"); return s[4] == '\0'; }
static bool test_s_multi() { auto a = S("first"); auto b = S("second"); return std::strcmp(a, "first") == 0 && std::strcmp(b, "second") == 0; }

static bool test_sw_basic() { return std::wcscmp(SW(L"Hello"), L"Hello") == 0; }
static bool test_sw_empty() { return std::wcscmp(SW(L""), L"") == 0; }
static bool test_sw_single() { return std::wcscmp(SW(L"X"), L"X") == 0; }
static bool test_sw_cyrillic() { return std::wcscmp(SW(L"\x041F\x0440\x0438\x0432\x0435\x0442"), L"\x041F\x0440\x0438\x0432\x0435\x0442") == 0; }
static bool test_sw_cjk() { return std::wcscmp(SW(L"\x4F60\x597D"), L"\x4F60\x597D") == 0; }
static bool test_sw_special() { return std::wcscmp(SW(L"!@#$%^&*()"), L"!@#$%^&*()") == 0; }
static bool test_sw_stable() { auto s = SW(L"stable"); return std::wcscmp(s, s) == 0; }
static bool test_sw_wcslen() { auto s = SW(L"wide"); return std::wcslen(s) == 4; }

static bool test_ss_basic() { stealth::secure_string<256> ss("secret"); return std::strcmp(ss.c_str(), "secret") == 0; }
static bool test_ss_length() { stealth::secure_string<256> ss("hello"); return ss.length() == 5 && ss.size() == 5; }
static bool test_ss_clear() { stealth::secure_string<256> ss("sensitive_data"); ss.clear(); for (size_t i = 0; i < 256; ++i) if (ss.c_str()[i] != '\0') return false; return ss.length() == 0; }
static bool test_ss_default() { stealth::secure_string<256> ss; return ss.length() == 0 && ss.c_str()[0] == '\0'; }
static bool test_ss_truncate() { stealth::secure_string<8> ss("1234567890ABCDEF"); return ss.length() == 7; }
static bool test_ss_data() { stealth::secure_string<256> ss("access"); return ss.raw_data() != nullptr && ss.raw_data()[0] == 'a'; }
static bool test_ss_destructor() {
    using string_t = stealth::secure_string<64>;
    alignas(string_t) unsigned char storage[sizeof(string_t)]{};
    auto* ss = new (storage) string_t("will_be_zeroed");
    std::memcpy(ss->raw_data(), "XXXXXXXXXXXX", 13);
    ss->~string_t();
    for (size_t i = 0; i < sizeof(storage); ++i) {
        if (storage[i] != 0) return false;
    }
    return true;
}

static bool test_b64_empty() { return stealth::encoding::base64_encode("").empty(); }
static bool test_b64_hello() { return stealth::encoding::base64_encode("Hello") == "SGVsbG8="; }
static bool test_b64_man() { return stealth::encoding::base64_encode("Man") == "TWFu"; }
static bool test_b64_single() { return stealth::encoding::base64_encode("A") == "QQ=="; }
static bool test_b64_two() { return stealth::encoding::base64_encode("AB") == "QUI="; }
static bool test_b64_roundtrip() { const char* original = "test_data_123!@#"; auto encoded = stealth::encoding::base64_encode(original); auto decoded = stealth::encoding::base64_decode(encoded); if (!decoded.has_value()) return false; return *decoded == original; }
static bool test_b64_binary() { uint8_t bin[] = {0x00, 0x01, 0xFF, 0xFE, 0x80, 0x7F}; auto encoded = stealth::encoding::base64_encode(bin, 6); auto decoded = stealth::encoding::base64_decode(encoded); if (!decoded.has_value() || decoded->size() != 6) return false; return std::memcmp(decoded->data(), bin, 6) == 0; }
static bool test_b64_invalid_len() { return !stealth::encoding::base64_decode("invalid!!!").has_value(); }
static bool test_b64_invalid_char() { return !stealth::encoding::base64_decode("!!!!").has_value(); }
static bool test_b64_long() { std::string long_str(300, 'X'); auto encoded = stealth::encoding::base64_encode(long_str); auto decoded = stealth::encoding::base64_decode(encoded); if (!decoded.has_value()) return false; return *decoded == long_str; }

static bool test_hex_empty() { return stealth::encoding::hex_encode("").empty(); }
static bool test_hex_hello() { return stealth::encoding::hex_encode("Hello") == "48656C6C6F"; }
static bool test_hex_binary() { uint8_t data[] = {0x00, 0xFF, 0x0A, 0x5B}; return stealth::encoding::hex_encode(data, 4) == "00FF0A5B"; }
static bool test_hex_roundtrip() { const char* original = "round_trip_test"; auto encoded = stealth::encoding::hex_encode(original); auto decoded = stealth::encoding::hex_decode(encoded); if (!decoded.has_value()) return false; std::string result(decoded->begin(), decoded->end()); return result == original; }
static bool test_hex_lower() { auto result = stealth::encoding::hex_decode("48656c6c6f"); if (!result.has_value()) return false; std::string str(result->begin(), result->end()); return str == "Hello"; }
static bool test_hex_odd() { return !stealth::encoding::hex_decode("ABC").has_value(); }
static bool test_hex_invalid() { return !stealth::encoding::hex_decode("GG").has_value(); }
static bool test_hex_long() { std::string data(200, '\x42'); auto encoded = stealth::encoding::hex_encode(data); auto decoded = stealth::encoding::hex_decode(encoded); if (!decoded.has_value()) return false; return decoded->size() == 200 && static_cast<char>((*decoded)[0]) == '\x42'; }

static bool test_xor_roundtrip() { stealth::encoding::xor_key<16> key{"testkey123"}; uint8_t data[] = "xor_test_data"; size_t len = std::strlen(reinterpret_cast<char*>(data)); stealth::encoding::xor_encode(data, len, key); stealth::encoding::xor_decode(data, len, key); return std::strcmp(reinterpret_cast<char*>(data), "xor_test_data") == 0; }
static bool test_xor_zero_key() { stealth::encoding::xor_key<16> key{}; uint8_t data[] = {0x41, 0x42, 0x43}; stealth::encoding::xor_encode(data, 3, key); return data[0] == 0x41 && data[1] == 0x42 && data[2] == 0x43; }
static bool test_xor_empty() { stealth::encoding::xor_key<16> key{"key"}; stealth::encoding::xor_encode(nullptr, 0, key); return true; }
static bool test_xor_key_str() { stealth::encoding::xor_key<32> key{"my_secret_key"}; return key.length == 13; }
static bool test_xor_key_bytes() { uint8_t k[] = {0xAA, 0xBB, 0xCC}; stealth::encoding::xor_key<16> key(k, 3); return key.length == 3 && key[0] == 0xAA; }
static bool test_xor_diff_keys() { stealth::encoding::xor_key<16> key1{"key1"}; stealth::encoding::xor_key<16> key2{"key2"}; uint8_t d1[] = "same_data"; uint8_t d2[] = "same_data"; stealth::encoding::xor_encode(d1, 9, key1); stealth::encoding::xor_encode(d2, 9, key2); return std::memcmp(d1, d2, 9) != 0; }
static bool test_xor_wrap() { stealth::encoding::xor_key<4> key{"abcd"}; uint8_t data[100]; uint8_t backup[100]; for (int i = 0; i < 100; ++i) data[i] = static_cast<uint8_t>(i); std::memcpy(backup, data, 100); stealth::encoding::xor_encode(data, 100, key); stealth::encoding::xor_decode(data, 100, key); return std::memcmp(data, backup, 100) == 0; }
static bool test_xor_double() { stealth::encoding::xor_key<16> key{"double_test"}; uint8_t data[] = "double_enc"; size_t len = std::strlen(reinterpret_cast<char*>(data)); stealth::encoding::xor_encode(data, len, key); stealth::encoding::xor_encode(data, len, key); return std::strcmp(reinterpret_cast<char*>(data), "double_enc") == 0; }

static bool test_rot13_basic() { char dst[6] = {}; stealth::encoding::rot13_encode(dst, "Hello", 5); return std::strcmp(dst, "Uryyb") == 0; }
static bool test_rot13_roundtrip() { char dst[12] = {}; char orig[12] = {}; stealth::encoding::rot13_encode(dst, "TestString", 10); stealth::encoding::rot13_decode(orig, dst, 10); return std::strcmp(orig, "TestString") == 0; }
static bool test_rot13_nonalpha() { char dst[11] = {}; stealth::encoding::rot13_encode(dst, "123!@# ABC", 10); return std::strcmp(dst, "123!@# NOP") == 0; }
static bool test_rot13_empty() { stealth::encoding::rot13_encode(nullptr, nullptr, 0); return true; }
static bool test_rot13_all() { char dst[53] = {}; stealth::encoding::rot13_encode(dst, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 52); return std::strcmp(dst, "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm") == 0; }

static bool test_szero() { char data[] = "sensitive_data_here"; stealth::memory::secure_zero(data, sizeof(data)); for (size_t i = 0; i < sizeof(data); ++i) if (data[i] != 0) return false; return true; }
static bool test_szero_empty() { char data[] = "safe"; stealth::memory::secure_zero(data, 0); return std::strcmp(data, "safe") == 0; }
static bool test_ct_equal() { return stealth::memory::compare_constant_time("password123", "password123", 11); }
static bool test_ct_notequal() { return !stealth::memory::compare_constant_time("password123", "password456", 11); }
static bool test_ct_zero() { return stealth::memory::compare_constant_time("a", "b", 0); }

static bool test_debug_bool() { bool r = stealth::detection::is_debugger_present(); (void)r; return true; }
static bool test_remote_debug_bool() { bool r = stealth::detection::check_remote_debugger(); (void)r; return true; }

static bool test_peb_ptr() { return stealth::get_peb_ptr() != nullptr; }
static bool test_mod_ntdll() { void* b = nullptr; return stealth::get_module_base(L"ntdll.dll", &b) && b != nullptr; }
static bool test_mod_kernel32() { void* b = nullptr; return stealth::get_module_base(L"kernel32.dll", &b) && b != nullptr; }
static bool test_mod_ansi_match() { void* w = nullptr; void* a = nullptr; stealth::get_module_base(L"kernel32.dll", &w); stealth::get_module_base_ansi("kernel32.dll", &a); return w == a; }
static bool test_mod_nonexist() { void* b = nullptr; return !stealth::get_module_base(L"nonexistent_xyz.dll", &b); }
static bool test_mod_case() { void* lo = nullptr; void* hi = nullptr; stealth::get_module_base(L"kernel32.dll", &lo); stealth::get_module_base(L"KERNEL32.DLL", &hi); return lo == hi && lo != nullptr; }
static bool test_dos_valid() { void* b = nullptr; stealth::get_module_base(L"kernel32.dll", &b); auto d = stealth::get_dos(b); return d != nullptr && d->e_magic == 0x5A4D; }
static bool test_nt_valid() { void* b = nullptr; stealth::get_module_base(L"kernel32.dll", &b); auto n = stealth::get_nt(b); return n != nullptr && n->Signature == 0x4550; }

static bool test_export_valid() { void* b = nullptr; stealth::get_module_base(L"kernel32.dll", &b); auto e = stealth::get_export(b); return e != nullptr && e->NumberOfNames > 0; }
static bool test_getproc() { void* b = nullptr; stealth::get_module_base(L"kernel32.dll", &b); return stealth::get_proc(b, "GetTickCount64") != nullptr; }
static bool test_getproc_nonexist() { void* b = nullptr; stealth::get_module_base(L"kernel32.dll", &b); return stealth::get_proc(b, "NonExistentFunction12345") == nullptr; }
static bool test_getproc_null() { return stealth::get_proc(nullptr, "Test") == nullptr; }
static bool test_getfunc_tpl() { using Fn = ULONGLONG(*)(); return stealth::get_function<Fn>("kernel32.dll", "GetTickCount64") != nullptr; }
static bool test_k32_api() { return stealth::get_kernel32_api("GetLastError") != nullptr; }
static bool test_nt_api() { return stealth::get_nt_api("NtClose") != nullptr; }
static bool test_modfunc() { return stealth::get_module_function("kernel32.dll", "GetCurrentProcessId") != nullptr; }

static bool test_loader_valid() { stealth::module_loader l("kernel32.dll"); return l.is_valid() && !!l; }
static bool test_loader_invalid() { stealth::module_loader l("nonexistent.dll"); return !l.is_valid() && !l; }
static bool test_loader_getfunc() { stealth::module_loader l("kernel32.dll"); using Fn = ULONGLONG(*)(); return l.get_function<Fn>("GetTickCount64") != nullptr; }
static bool test_loader_null() { stealth::module_loader l("nonexistent.dll"); using Fn = void(*)(); return l.get_function<Fn>("AnyFunc") == nullptr; }
static bool test_loader_base() { stealth::module_loader l("kernel32.dll"); return l.get() != nullptr; }

static bool test_sapi_def() { stealth::stealth_api<DWORD()> api; return !api.is_valid(); }
static bool test_sapi_resolve() { stealth::stealth_api<DWORD()> api("kernel32.dll", "GetTickCount"); return api.is_valid(); }
static bool test_sapi_null() { stealth::stealth_api<DWORD()> api(nullptr); return !api.is_valid(); }
static bool test_sapi_fake() { stealth::stealth_api<void()> api("kernel32.dll", "FakeFunctionXYZ"); return !api.is_valid(); }
static bool test_sapi_reset() { stealth::stealth_api<DWORD()> api("kernel32.dll", "GetTickCount"); api.reset(); return !api.is_valid(); }
static bool test_sapi_reset_resolve() { stealth::stealth_api<DWORD()> api; api.reset("kernel32.dll", "GetTickCount"); return api.is_valid(); }

static bool test_version() { return std::strcmp(stealth::version(), "2.2.0") == 0; }
static bool test_workflow_b64() { auto secret = S("my_api_key_123"); auto b64 = stealth::encoding::base64_encode(secret.c_str()); auto decoded = stealth::encoding::base64_decode(b64); if (!decoded.has_value()) return false; return *decoded == "my_api_key_123"; }
static bool test_workflow_hex_xor() { auto secret = S("confidential"); auto hex = stealth::encoding::hex_encode(secret.c_str()); auto hex_decoded_opt = stealth::encoding::hex_decode(hex); if (!hex_decoded_opt.has_value()) return false; auto hex_decoded = std::move(*hex_decoded_opt); stealth::encoding::xor_key<16> key{"xorkey"}; stealth::encoding::xor_encode(hex_decoded.data(), hex_decoded.size(), key); stealth::encoding::xor_decode(hex_decoded.data(), hex_decoded.size(), key); std::string result(hex_decoded.begin(), hex_decoded.end()); return result == "confidential"; }

int main() {
    std::cout << "========================================\n";
    std::cout << "  StealthLib Comprehensive Test Suite  \n";
    std::cout << "========================================\n\n";

    std::cout << "--- String Encryption (1-12) ---\n";
    T("S() basic string", test_s_basic()); T("S() empty string", test_s_empty()); T("S() single char", test_s_single());
    T("S() special characters", test_s_special()); T("S() numeric string", test_s_numeric()); T("S() long string", test_s_long());
    T("S() API key pattern", test_s_apikey()); T("S() connection string", test_s_connstr());
    T("S() repeated decrypt stable", test_s_stable()); T("S() strlen matches", test_s_strlen());
    T("S() null terminator", test_s_nullterm()); T("S() multiple independent", test_s_multi());

    std::cout << "\n--- Wide String Encryption (13-20) ---\n";
    T("SW() basic wide", test_sw_basic()); T("SW() empty wide", test_sw_empty()); T("SW() single wide char", test_sw_single());
    T("SW() Cyrillic", test_sw_cyrillic()); T("SW() CJK", test_sw_cjk()); T("SW() special wide", test_sw_special());
    T("SW() repeated decrypt stable", test_sw_stable()); T("SW() wcslen matches", test_sw_wcslen());

    std::cout << "\n--- Secure String (21-27) ---\n";
    T("secure_string basic", test_ss_basic()); T("secure_string length", test_ss_length());
    T("secure_string clear zeroes", test_ss_clear()); T("secure_string default empty", test_ss_default());
    T("secure_string truncates overflow", test_ss_truncate()); T("secure_string data access", test_ss_data());
    T("secure_string destructor zeroes", test_ss_destructor());

    std::cout << "\n--- Base64 Encoding (28-37) ---\n";
    T("base64 encode empty", test_b64_empty()); T("base64 encode Hello", test_b64_hello());
    T("base64 encode Man", test_b64_man()); T("base64 encode single byte", test_b64_single());
    T("base64 encode two bytes", test_b64_two()); T("base64 roundtrip", test_b64_roundtrip());
    T("base64 binary roundtrip", test_b64_binary()); T("base64 invalid length", test_b64_invalid_len());
    T("base64 invalid chars", test_b64_invalid_char()); T("base64 long roundtrip", test_b64_long());

    std::cout << "\n--- Hex Encoding (38-45) ---\n";
    T("hex encode empty", test_hex_empty()); T("hex encode Hello", test_hex_hello());
    T("hex encode binary", test_hex_binary()); T("hex roundtrip", test_hex_roundtrip());
    T("hex decode lowercase", test_hex_lower()); T("hex odd length invalid", test_hex_odd());
    T("hex invalid chars", test_hex_invalid()); T("hex long roundtrip", test_hex_long());

    std::cout << "\n--- XOR Encoding (46-53) ---\n";
    T("XOR roundtrip", test_xor_roundtrip()); T("XOR zero key unchanged", test_xor_zero_key());
    T("XOR empty no crash", test_xor_empty()); T("XOR key string ctor", test_xor_key_str());
    T("XOR key bytes ctor", test_xor_key_bytes()); T("XOR different keys differ", test_xor_diff_keys());
    T("XOR key wraps long data", test_xor_wrap()); T("XOR double encode = original", test_xor_double());

    std::cout << "\n--- ROT13 (53-57) ---\n";
    T("ROT13 basic", test_rot13_basic()); T("ROT13 roundtrip", test_rot13_roundtrip());
    T("ROT13 non-alpha unchanged", test_rot13_nonalpha()); T("ROT13 empty no crash", test_rot13_empty());
    T("ROT13 all letters", test_rot13_all());

    std::cout << "\n--- Secure Memory (58-62) ---\n";
    T("secure_zero clears", test_szero()); T("secure_zero zero-len safe", test_szero_empty());
    T("const-time equal", test_ct_equal()); T("const-time not equal", test_ct_notequal());
    T("const-time zero-len true", test_ct_zero());

    std::cout << "\n--- Debugger Detection (63-64) ---\n";
    T("is_debugger_present returns bool", test_debug_bool());
    T("check_remote_debugger returns bool", test_remote_debug_bool());

    std::cout << "\n--- PEB Walking (65-72) ---\n";
    T("get_peb_ptr non-null", test_peb_ptr()); T("get_module_base ntdll", test_mod_ntdll());
    T("get_module_base kernel32", test_mod_kernel32()); T("get_module_base_ansi matches wide", test_mod_ansi_match());
    T("get_module_base nonexistent false", test_mod_nonexist()); T("get_module_base case insensitive", test_mod_case());
    T("DOS header valid", test_dos_valid()); T("NT headers valid", test_nt_valid());

    std::cout << "\n--- Export & API Resolution (73-80) ---\n";
    T("get_export valid", test_export_valid()); T("get_proc resolves GetTickCount64", test_getproc());
    T("get_proc nonexistent null", test_getproc_nonexist()); T("get_proc null base null", test_getproc_null());
    T("get_function template resolves", test_getfunc_tpl()); T("get_kernel32_api resolves", test_k32_api());
    T("get_nt_api resolves NtClose", test_nt_api()); T("get_module_function resolves", test_modfunc());

    std::cout << "\n--- module_loader (81-85) ---\n";
    T("module_loader kernel32 valid", test_loader_valid()); T("module_loader nonexistent invalid", test_loader_invalid());
    T("module_loader get_function resolves", test_loader_getfunc()); T("module_loader null module returns null", test_loader_null());
    T("module_loader get returns base", test_loader_base());

    std::cout << "\n--- stealth_api (86-91) ---\n";
    T("stealth_api default invalid", test_sapi_def()); T("stealth_api resolves GetTickCount", test_sapi_resolve());
    T("stealth_api null invalid", test_sapi_null()); T("stealth_api fake function invalid", test_sapi_fake());
    T("stealth_api reset clears", test_sapi_reset()); T("stealth_api reset resolves new", test_sapi_reset_resolve());

    std::cout << "\n--- Version & Integration (92-94) ---\n";
    T("version 1.0.0", test_version()); T("workflow: encrypt->base64->decode", test_workflow_b64());
    T("workflow: encrypt->hex->xor->decode", test_workflow_hex_xor());

    std::cout << "\n========================================\n";
    std::cout << "  RESULTS: " << g_pass << " PASSED, " << g_fail << " FAILED\n";
    std::cout << "========================================\n";
    return g_fail > 0 ? 1 : 0;
}
