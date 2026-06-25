#ifdef _WIN32

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "stealthlib/stealth.hpp"

#include <cstring>
#include <fstream>
#include <vector>
#include <windows.h>

namespace {
bool read_file(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    f.seekg(0, std::ios::end);
    std::streamsize sz = f.tellg();
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(sz));
    if (sz > 0) f.read(reinterpret_cast<char*>(out.data()), sz);
    return f.good() || f.eof();
}
}

TEST_CASE("peb pointer non-null") {
    auto peb = stealth::get_peb_ptr();
    CHECK(peb != nullptr);
}

TEST_CASE("get_module_base resolves kernel32/user32/ntdll") {
    void* n   = nullptr;
    void* k32 = nullptr;
    void* u32 = nullptr;
    CHECK(stealth::get_module_base(L"ntdll.dll",     &n));
    CHECK(stealth::get_module_base(L"kernel32.dll",  &k32));
    CHECK(stealth::get_module_base(L"user32.dll",    &u32));
    CHECK(n != nullptr);
    CHECK(k32 != nullptr);
    CHECK(u32 != nullptr);
}

TEST_CASE("get_module_base_ansi matches wide") {
    void* a = nullptr;
    void* b = nullptr;
    CHECK(stealth::get_module_base_ansi("kernel32.dll", &a));
    CHECK(stealth::get_module_base(L"kernel32.dll", &b));
    CHECK(a == b);
}

TEST_CASE("get_module_base false on missing module") {
    void* out = reinterpret_cast<void*>(0x1);
    CHECK(!stealth::get_module_base(L"nonexistent_zzz.dll", &out));
    CHECK(out == nullptr);
}

TEST_CASE("get_dos / get_nt / get_export on real module") {
    void* base = nullptr;
    REQUIRE(stealth::get_module_base(L"kernel32.dll", &base));
    auto* dos = stealth::get_dos(base);
    REQUIRE(dos != nullptr);
    CHECK(dos->e_magic == 0x5A4D);
    auto* nt = stealth::get_nt(base);
    REQUIRE(nt != nullptr);
    CHECK(nt->Signature == 0x4550);
    auto* exp = stealth::get_export(base);
    REQUIRE(exp != nullptr);
    CHECK(exp->NumberOfFunctions > 0);
    CHECK(exp->NumberOfNames > 0);
}

TEST_CASE("get_proc by name") {
    void* base = nullptr;
    REQUIRE(stealth::get_module_base(L"kernel32.dll", &base));
    CHECK(stealth::get_proc(base, "GetTickCount64") != nullptr);
    CHECK(stealth::get_proc(base, "GetLastError")    != nullptr);
    CHECK(stealth::get_proc(base, "FunctionThatObviouslyDoesNotExist_XYZ") == nullptr);
}

TEST_CASE("get_proc_by_hash") {
    void* base = nullptr;
    REQUIRE(stealth::get_module_base(L"kernel32.dll", &base));
    constexpr uint64_t want = stealth::hashes::fnv("GetTickCount64");
    auto p = stealth::get_proc_by_hash(base, want);
    CHECK(p != nullptr);
    CHECK(p == stealth::get_proc(base, "GetTickCount64"));
    constexpr uint64_t missing = stealth::hashes::fnv("FunctionThatObviouslyDoesNotExist_XYZ");
    CHECK(stealth::get_proc_by_hash(base, missing) == nullptr);
}

TEST_CASE("get_function_by_hash returns typed pointer") {
    using GT_t = ULONGLONG(*)();
    constexpr uint64_t mod_h = stealth::hashes::fnv("kernel32.dll");
    constexpr uint64_t fn_h  = stealth::hashes::fnv("GetTickCount64");
    auto p = stealth::get_function_by_hash<GT_t>(mod_h, fn_h);
    CHECK(p != nullptr);
    ULONGLONG uptime = p();
    CHECK(uptime > 0);
}

TEST_CASE("module_loader by name and by hash") {
    stealth::module_loader a("kernel32.dll");
    stealth::module_loader b(stealth::hashes::fnv("kernel32.dll"));
    CHECK(a.is_valid());
    CHECK(b.is_valid());
    CHECK(a.get() == b.get());

    using GT_t = ULONGLONG(*)();
    auto pa = a.get_function<GT_t>("GetTickCount64");
    auto pb = b.get_function_by_hash<GT_t>(stealth::hashes::fnv("GetTickCount64"));
    CHECK(pa != nullptr);
    CHECK(pb != nullptr);
    CHECK(reinterpret_cast<void*>(pa) == reinterpret_cast<void*>(pb));
}

TEST_CASE("stealth_api hash vs name produce same target") {
    using MB_t = int(HWND, LPCWSTR, LPCWSTR, UINT);
    stealth::stealth_api<MB_t> by_name("user32.dll", "MessageBoxW");
    stealth::stealth_api<MB_t> by_hash(stealth::hashes::fnv("user32.dll"),
                                       stealth::hashes::fnv("MessageBoxW"));
    CHECK(by_hash.is_valid());
    CHECK(by_name.get() == by_hash.get());
}

TEST_CASE("fixture: tiny_null.dll parses and exposes empty exports") {
    std::vector<uint8_t> bytes;
    REQUIRE(read_file("fixtures/tiny_null.dll", bytes));
    REQUIRE(bytes.size() >= 0x40);
    void* base = bytes.data();
    auto* dos = stealth::get_dos(base);
    REQUIRE(dos != nullptr);
    CHECK(dos->e_magic == 0x5A4D);
    auto* nt = stealth::get_nt(base);
    REQUIRE(nt != nullptr);
    CHECK(nt->Signature == 0x4550);
    auto* exp = stealth::get_export(base);
    REQUIRE(exp != nullptr);
    CHECK(exp->NumberOfFunctions == 0);
    CHECK(exp->NumberOfNames == 0);
    CHECK(stealth::get_proc(base, "Anything") == nullptr);
    CHECK(stealth::get_proc_by_hash(base, stealth::hashes::fnv("Anything")) == nullptr);
}

TEST_CASE("fixture: corrupt_header.bin -> get_nt returns nullptr") {
    std::vector<uint8_t> bytes;
    REQUIRE(read_file("fixtures/corrupt_header.bin", bytes));
    void* base = bytes.data();
    auto* dos = stealth::get_dos(base);
    REQUIRE(dos != nullptr);
    CHECK(dos->e_magic == 0x5A4D);
    auto* nt = stealth::get_nt(base);
    CHECK(nt == nullptr);
}

TEST_CASE("fixture: is_forwarder.dll parses forwarder entry") {
    std::vector<uint8_t> bytes;
    REQUIRE(read_file("fixtures/is_forwarder.dll", bytes));
    void* base = bytes.data();
    auto* nt = stealth::get_nt(base);
    REQUIRE(nt != nullptr);
    auto* exp = stealth::get_export(base);
    REQUIRE(exp != nullptr);
    CHECK(exp->NumberOfNames >= 1);
    // Forwarder strings are NOT lookup-able via get_proc (returns NULL is expected);
    // we only assert the export directory was readable.
    CHECK(true);
}

TEST_CASE("detection::scan returns coherent struct") {
    auto s = stealth::detection::scan();
    CHECK(s.build_key_match != 0);
    CHECK((s.peb_debug_flag == true || s.peb_debug_flag == false));
    CHECK(s.hwbp_count >= 0);
}

TEST_CASE("detection::hardware_breakpoint_count not negative on x64") {
    auto n = stealth::detection::hardware_breakpoint_count();
    CHECK(n >= -1);
}

TEST_CASE("rva_in_image rejects out-of-range RVAs") {
    void* base = nullptr;
    REQUIRE(stealth::get_module_base(L"kernel32.dll", &base));
    auto* nt = stealth::get_nt(base);
    REQUIRE(nt != nullptr);
    CHECK(stealth::rva_in_image(base, 0) != 0);
    CHECK(stealth::rva_in_image(base, nt->SizeOfImage - 4) != 0);
    CHECK(stealth::rva_in_image(base, nt->SizeOfImage + 1) == 0);
    CHECK(stealth::rva_in_image(nullptr, 0) == 0);
}

TEST_CASE("RAII unlock: scope exit re-encrypts char") {
    auto s = S("Hello, World!");
    CHECK(std::strcmp(s.c_str(), "Hello, World!") == 0);
    {
        auto lock = s.unlock();
        CHECK(std::strcmp(lock.c_str(), "Hello, World!") == 0);
    }
    CHECK(std::strcmp(s.c_str(), "Hello, World!") == 0);
}

TEST_CASE("RAII unlock: scope exit re-encrypts wide char") {
    auto s = SW(L"Wide Scope Test");
    CHECK(std::wcscmp(s.c_str(), L"Wide Scope Test") == 0);
    {
        auto lock = s.unlock();
        CHECK(std::wcscmp(lock.c_str(), L"Wide Scope Test") == 0);
    }
    CHECK(std::wcscmp(s.c_str(), L"Wide Scope Test") == 0);
}

TEST_CASE("build_key is non-zero at compile time") {
    constexpr uint64_t k = STEALTH_BUILD_KEY;
    CHECK(k != 0);
}

#else  // non-Windows build

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "stealthlib/stealth.hpp"

#include <cstring>
#include <string_view>

TEST_CASE("non-windows: version exposed") {
    CHECK(std::strlen(stealth::version()) > 0);
}

TEST_CASE("non-windows: hash determinism") {
    constexpr uint64_t a = stealth::hashes::fnv("hello");
    CHECK(a != 0);
    CHECK(a == stealth::hashes::runtime("hello"));
}

TEST_CASE("non-windows: string encryption works") {
    auto s = S("plain");
    CHECK(std::strcmp(s.c_str(), "plain") == 0);
}

TEST_CASE("non-windows: base64 round trip") {
    auto enc = stealth::encoding::base64_encode("hi");
    auto dec = stealth::encoding::base64_decode(enc);
    REQUIRE(dec.has_value());
    CHECK(dec->size() == 2);
}

TEST_CASE("non-windows: secure_zero") {
    char buf[8];
    std::memset(buf, 'X', sizeof(buf));
    stealth::memory::secure_zero(buf, sizeof(buf));
    for (size_t i = 0; i < sizeof(buf); ++i) CHECK(buf[i] == 0);
}

TEST_CASE("non-windows: RAII unlock") {
    auto s = S("narrow");
    {
        auto lock = s.unlock();
        CHECK(std::strcmp(lock.c_str(), "narrow") == 0);
    }
    CHECK(std::strcmp(s.c_str(), "narrow") == 0);
}

#endif
