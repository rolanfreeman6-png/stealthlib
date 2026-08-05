#ifdef _WIN32

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "stealthlib/stealth.hpp"

#include <cstring>
#include <windows.h>

namespace {

void** find_current_image_iat_slot(const char* function_name) {
    auto* base = reinterpret_cast<uint8_t*>(GetModuleHandleA(nullptr));
    if (!base) return nullptr;

    IMAGE_DATA_DIRECTORY imports{};
    if (!stealth::get_data_directory(base, IMAGE_DIRECTORY_ENTRY_IMPORT, &imports)) return nullptr;
    const bool is_pe64 = stealth::get_optional_header_magic(base) == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    const size_t entry_size = is_pe64 ? sizeof(uint64_t) : sizeof(uint32_t);
    const size_t descriptor_count = imports.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);

    for (size_t descriptor_index = 0; descriptor_index < descriptor_count; ++descriptor_index) {
        auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            base + imports.VirtualAddress + descriptor_index * sizeof(IMAGE_IMPORT_DESCRIPTOR));
        if (descriptor->OriginalFirstThunk == 0 && descriptor->FirstThunk == 0 && descriptor->Name == 0) break;
        if (descriptor->OriginalFirstThunk == 0 || descriptor->FirstThunk == 0) continue;

        for (size_t index = 0; ; ++index) {
            const size_t offset = index * entry_size;
            if (!stealth::rva_range_in_image(base, descriptor->OriginalFirstThunk, offset + entry_size) ||
                !stealth::rva_range_in_image(base, descriptor->FirstThunk, offset + entry_size)) {
                break;
            }
            const uint64_t original_value = is_pe64
                ? reinterpret_cast<const uint64_t*>(base + descriptor->OriginalFirstThunk)[index]
                : reinterpret_cast<const uint32_t*>(base + descriptor->OriginalFirstThunk)[index];
            if (original_value == 0) break;

            const uint64_t ordinal_flag = is_pe64 ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32;
            if ((original_value & ordinal_flag) != 0) continue;
            const char* imported_name = nullptr;
            if (!stealth::detail::bounded_image_string(
                    base,
                    static_cast<uint32_t>(original_value) + sizeof(uint16_t),
                    &imported_name)) {
                break;
            }
            if (std::strcmp(imported_name, function_name) == 0) {
                return reinterpret_cast<void**>(base + descriptor->FirstThunk + offset);
            }
        }
    }
    return nullptr;
}

class iat_slot_restore {
public:
    explicit iat_slot_restore(void** slot) : slot_(slot), original_(*slot), protection_(0), writable_(false) {
        writable_ = VirtualProtect(slot_, sizeof(*slot_), PAGE_READWRITE, &protection_) != FALSE;
    }

    ~iat_slot_restore() {
        if (!writable_) return;
        *slot_ = original_;
        DWORD ignored = 0;
        (void)VirtualProtect(slot_, sizeof(*slot_), protection_, &ignored);
        FlushInstructionCache(GetCurrentProcess(), slot_, sizeof(*slot_));
    }

    [[nodiscard]] bool writable() const noexcept { return writable_; }

private:
    void** slot_;
    void* original_;
    DWORD protection_;
    bool writable_;
};

} // namespace

TEST_CASE("integrity: normal named IAT import matches its resolved target") {
    char module_path[MAX_PATH] = {};
    REQUIRE(GetModuleFileNameA(nullptr, module_path, MAX_PATH) > 0);
    const char* module_name = std::strrchr(module_path, '\\');
    module_name = module_name ? module_name + 1 : module_path;

    auto info = stealth::integrity::compare_iat_thunk(module_name, "GetModuleFileNameA");
    REQUIRE(info.status == stealth::integrity::hook_status::clean);
    CHECK_FALSE(info.hooked);
    CHECK(info.expected != nullptr);
    CHECK(info.actual == info.expected);
    CHECK(info.deviation == 0);
}

TEST_CASE("integrity: forwarded exports resolve to the loader target") {
    auto kernel32 = GetModuleHandleA("kernel32.dll");
    REQUIRE(kernel32 != nullptr);
    auto library_result = stealth::get_proc(kernel32, "HeapAlloc");
    auto loader_result = reinterpret_cast<void*>(GetProcAddress(kernel32, "HeapAlloc"));
    REQUIRE(library_result != nullptr);
    REQUIRE(loader_result != nullptr);
    CHECK(library_result == loader_result);
    CHECK(stealth::integrity::is_eat_forwarded("kernel32.dll", "HeapAlloc"));

    using HeapAlloc_t = LPVOID(WINAPI*)(HANDLE, DWORD, SIZE_T);
    constexpr auto kernel32_hash = stealth::hashes::fnv("kernel32.dll");
    constexpr auto heap_alloc_hash = stealth::hashes::fnv("HeapAlloc");
    auto hash_result = stealth::get_function_by_hash<HeapAlloc_t>(kernel32_hash, heap_alloc_hash);
    CHECK(reinterpret_cast<void*>(hash_result) == loader_result);
}

TEST_CASE("integrity: patched named IAT entry is detected") {
    char module_path[MAX_PATH] = {};
    REQUIRE(GetModuleFileNameA(nullptr, module_path, MAX_PATH) > 0);
    const char* module_name = std::strrchr(module_path, '\\');
    module_name = module_name ? module_name + 1 : module_path;

    void** slot = find_current_image_iat_slot("GetModuleFileNameA");
    REQUIRE(slot != nullptr);
    iat_slot_restore restore(slot);
    REQUIRE(restore.writable());

    *slot = reinterpret_cast<void*>(GetCurrentProcessId);
    FlushInstructionCache(GetCurrentProcess(), slot, sizeof(*slot));

    auto info = stealth::integrity::compare_iat_thunk(module_name, "GetModuleFileNameA");
    CHECK(info.status == stealth::integrity::hook_status::hooked);
    CHECK(info.hooked);
    CHECK(info.expected != nullptr);
    CHECK(info.actual == reinterpret_cast<void*>(GetCurrentProcessId));
    CHECK(info.actual != info.expected);
    CHECK(info.deviation != 0);
}

#else

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "stealthlib/stealth.hpp"

#include <cstring>

// A small, well-defined function whose prologue bytes we can hash.
namespace {
__attribute__((noinline)) int test_thunk(int x) { return x + 1; }
}

// Self-validation: hash the first 32 bytes of an internal function and
// verify prologue_sha256 reports a match. Round-trip identity.
TEST_CASE("prologue_sha256: round-trip on internal function") {
    auto f = &test_thunk;
    uint8_t expected[32];
    stealth::detail::sha256_oneshot(
        reinterpret_cast<uint8_t const*>(f), 32, expected);
    CHECK(stealth::integrity::prologue_sha256(
        reinterpret_cast<void const*>(f), 32, expected));
}

// Tampered buffer test: hash a copy with one byte flipped, verify SHA-256
// produces a different digest and prologue_sha256 reports "not equal".
TEST_CASE("prologue_sha256: tampered buffer produces mismatch") {
    uint8_t src[32];
    for (int i = 0; i < 32; ++i) src[i] = static_cast<uint8_t>(i * 7 + 1);
    uint8_t expected[32], tampered[32];
    stealth::detail::sha256_oneshot(src, 32, expected);

    std::memcpy(tampered, src, 32);
    tampered[15] ^= 0x01;
    uint8_t tampered_digest[32];
    stealth::detail::sha256_oneshot(tampered, 32, tampered_digest);
    CHECK(std::memcmp(expected, tampered_digest, 32) != 0);
    CHECK(!stealth::integrity::prologue_sha256(tampered, 32, expected));
}

// Boundary checks per docstring: N out of [4,64] returns false.
TEST_CASE("prologue_sha256: rejects N below 4") {
    uint8_t expected[32] = {};
    CHECK(!stealth::integrity::prologue_sha256(&expected, 0, expected));
    CHECK(!stealth::integrity::prologue_sha256(&expected, 1, expected));
    CHECK(!stealth::integrity::prologue_sha256(&expected, 3, expected));
    // N=4 is the minimum valid case.
    uint8_t src4[4] = { 0x90, 0x90, 0x90, 0xC3 };
    uint8_t d4[32];
    stealth::detail::sha256_oneshot(src4, 4, d4);
    CHECK(stealth::integrity::prologue_sha256(src4, 4, d4));
}

TEST_CASE("prologue_sha256: rejects N above 64") {
    uint8_t expected[32] = {};
    CHECK(!stealth::integrity::prologue_sha256(&expected, 65, expected));
    CHECK(!stealth::integrity::prologue_sha256(&expected, 256, expected));
}

TEST_CASE("prologue_sha256: rejects null pointer") {
    uint8_t expected[32] = {};
    CHECK(!stealth::integrity::prologue_sha256(nullptr, 32, expected));
}

TEST_CASE("prologue_sha256: real 32-byte buffer round-trip") {
    uint8_t src[32];
    for (int i = 0; i < 32; ++i) src[i] = static_cast<uint8_t>(0xC0 ^ i);
    uint8_t expected[32];
    stealth::detail::sha256_oneshot(src, 32, expected);
    CHECK(stealth::integrity::prologue_sha256(src, 32, expected));
    // Mutate one byte; equality must flip.
    src[7] ^= 0x42;
    uint8_t mutated_digest[32];
    stealth::detail::sha256_oneshot(src, 32, mutated_digest);
    CHECK(!stealth::integrity::prologue_sha256(src, 32, expected));
}

TEST_CASE("vmdetect: scan returns coherent struct with confidence in [0,3]") {
    auto r = stealth::detection::vmdetect::scan();
    CHECK(r.vm_confidence >= 0);
    CHECK(r.vm_confidence <= 3);
    CHECK(r.reported_disk_gb >= 0.0);
}

TEST_CASE("vmdetect: vendor matching is ASCII case insensitive") {
    CHECK(stealth::detection::vmdetect::contains_vm_vendor_token("VMware, Inc."));
    CHECK(stealth::detection::vmdetect::contains_vm_vendor_token("virtualbox"));
    CHECK(stealth::detection::vmdetect::contains_vm_vendor_token("QEMU Standard PC"));
    CHECK(stealth::detection::vmdetect::contains_vm_vendor_token("Microsoft Corporation"));
    CHECK_FALSE(stealth::detection::vmdetect::contains_vm_vendor_token("Physical OEM"));
}

#endif
