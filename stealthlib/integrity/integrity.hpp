#pragma once
#ifndef STEALTH_INTEGRITY_INTEGRITY_HPP
#define STEALTH_INTEGRITY_INTEGRITY_HPP

#include <cstddef>
#include <cstdint>

#include "../detail/sha256.hpp"
#include "../detection/debug.hpp"

#ifdef _WIN32
#include <windows.h>
#include "../pe/pe_parser.hpp"

namespace stealth::integrity {

enum class hook_status : uint8_t {
    not_found,
    clean,
    hooked,
    unavailable,
};

struct hook_info {
    bool hooked = false;
    void* expected = nullptr;
    void* actual = nullptr;
    uintptr_t deviation = 0;
    hook_status status = hook_status::not_found;
};

inline uintptr_t get_section_rva_in_image(void* base, uint32_t rva) noexcept {
    return rva_in_image(base, rva);
}

inline bool ansi_case_equal(const char* left, const char* right) noexcept {
    if (!left || !right) return false;
    while (*left != '\0' && *right != '\0') {
        char a = *left++;
        char b = *right++;
        if (a >= 'A' && a <= 'Z') a = static_cast<char>(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z') b = static_cast<char>(b + ('a' - 'A'));
        if (a != b) return false;
    }
    return *left == '\0' && *right == '\0';
}

inline hook_info compare_iat_thunk(
    const char* importing_module,
    const char* imported_module,
    const char* function_name) noexcept {
    hook_info info{};
    if (!importing_module || !function_name) {
        info.status = hook_status::unavailable;
        return info;
    }

    auto* importing_base = reinterpret_cast<uint8_t*>(GetModuleHandleA(importing_module));
    if (!importing_base) {
        info.status = hook_status::unavailable;
        return info;
    }

    IMAGE_DATA_DIRECTORY import_data{};
    if (!get_data_directory(importing_base, IMAGE_DIRECTORY_ENTRY_IMPORT, &import_data)) {
        return info;
    }

    const bool is_pe64 = get_optional_header_magic(importing_base) == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    const size_t entry_size = is_pe64 ? sizeof(uint64_t) : sizeof(uint32_t);
    const size_t descriptor_count = import_data.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    bool metadata_unavailable = false;
    bool found_clean = false;
    hook_info clean_info{};

    for (size_t descriptor_index = 0; descriptor_index < descriptor_count; ++descriptor_index) {
        auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            importing_base + import_data.VirtualAddress + descriptor_index * sizeof(IMAGE_IMPORT_DESCRIPTOR));
        if (descriptor->OriginalFirstThunk == 0 && descriptor->FirstThunk == 0 && descriptor->Name == 0) {
            break;
        }
        if (descriptor->OriginalFirstThunk == 0 || descriptor->FirstThunk == 0) {
            metadata_unavailable = true;
            continue;
        }

        const char* dependency_name = nullptr;
        if (!detail::bounded_image_string(importing_base, descriptor->Name, &dependency_name)) {
            metadata_unavailable = true;
            continue;
        }
        if (imported_module && !ansi_case_equal(dependency_name, imported_module)) continue;

        void* dependency_base = nullptr;
        if (!get_module_base_ansi(dependency_name, &dependency_base)) {
            metadata_unavailable = true;
            continue;
        }

        const uint32_t image_size = get_image_size(importing_base);
        const size_t maximum_entries = image_size / entry_size;
        for (size_t index = 0; index < maximum_entries; ++index) {
            const size_t offset = index * entry_size;
            if (!rva_range_in_image(importing_base, descriptor->OriginalFirstThunk, offset + entry_size) ||
                !rva_range_in_image(importing_base, descriptor->FirstThunk, offset + entry_size)) {
                metadata_unavailable = true;
                break;
            }

            const uint64_t original_value = is_pe64
                ? reinterpret_cast<const uint64_t*>(importing_base + descriptor->OriginalFirstThunk)[index]
                : reinterpret_cast<const uint32_t*>(importing_base + descriptor->OriginalFirstThunk)[index];
            if (original_value == 0) break;

            const uint64_t ordinal_flag = is_pe64 ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32;
            if ((original_value & ordinal_flag) != 0) continue;

            const uint32_t import_by_name_rva = static_cast<uint32_t>(original_value);
            if (!rva_range_in_image(importing_base, import_by_name_rva, sizeof(uint16_t) + 1)) {
                metadata_unavailable = true;
                break;
            }
            const char* imported_name = nullptr;
            if (!detail::bounded_image_string(importing_base, import_by_name_rva + sizeof(uint16_t), &imported_name)) {
                metadata_unavailable = true;
                break;
            }
            if (!detail::export_name_equals(imported_name, function_name)) continue;

            void* expected = get_proc(dependency_base, imported_name);
            if (!expected) {
                info.status = hook_status::unavailable;
                return info;
            }
            const uintptr_t actual_value = is_pe64
                ? static_cast<uintptr_t>(reinterpret_cast<const uint64_t*>(importing_base + descriptor->FirstThunk)[index])
                : static_cast<uintptr_t>(reinterpret_cast<const uint32_t*>(importing_base + descriptor->FirstThunk)[index]);
            const uintptr_t expected_value = reinterpret_cast<uintptr_t>(expected);

            info.expected = expected;
            info.actual = reinterpret_cast<void*>(actual_value);
            info.deviation = actual_value >= expected_value
                ? actual_value - expected_value
                : expected_value - actual_value;
            info.hooked = actual_value != expected_value;
            info.status = info.hooked ? hook_status::hooked : hook_status::clean;
            if (info.hooked || imported_module != nullptr) return info;
            if (!found_clean) {
                clean_info = info;
                found_clean = true;
            }
            continue;
        }
    }

    if (found_clean) return clean_info;
    info.status = metadata_unavailable ? hook_status::unavailable : hook_status::not_found;
    return info;
}

inline hook_info compare_iat_thunk(const char* importing_module, const char* function_name) noexcept {
    return compare_iat_thunk(importing_module, nullptr, function_name);
}

inline hook_info compare_export_to_module(const char* module_name, const char* function_name) noexcept {
    hook_info info{};
    void* base = nullptr;
    if (!get_module_base_ansi(module_name, &base)) {
        info.status = hook_status::unavailable;
        return info;
    }
    void* procedure = get_proc(base, function_name);
    if (!procedure) return info;
    info.expected = procedure;
    info.actual = procedure;
    info.status = hook_status::clean;
    return info;
}

inline bool is_iat_hooked(const char* importing_module, const char* function_name) noexcept {
    return compare_iat_thunk(importing_module, function_name).hooked;
}

inline bool is_eat_forwarded(const char* module_name, const char* function_name) noexcept {
    if (!module_name || !function_name) return false;

    void* base = nullptr;
    if (!get_module_base_ansi(module_name, &base)) return false;

    IMAGE_EXPORT_DIRECTORY* directory = nullptr;
    IMAGE_DATA_DIRECTORY export_data{};
    uint32_t* functions = nullptr;
    uint32_t* names = nullptr;
    uint16_t* ordinals = nullptr;
    if (!detail::get_export_tables(base, &directory, &export_data, &functions, &names, &ordinals)) {
        return false;
    }

    for (uint32_t index = 0; index < directory->NumberOfNames; ++index) {
        const char* exported_name = nullptr;
        if (!detail::bounded_image_string(base, names[index], &exported_name)) return false;
        if (!detail::export_name_equals(exported_name, function_name)) continue;
        const uint16_t ordinal_index = ordinals[index];
        if (ordinal_index >= directory->NumberOfFunctions) return false;
        const uint32_t rva = functions[ordinal_index];
        return rva >= export_data.VirtualAddress && rva - export_data.VirtualAddress < export_data.Size;
    }
    return false;
}

inline bool prologue_sha256(
    const void* function_pointer,
    std::size_t length,
    const uint8_t expected[32]) noexcept {
    if (!function_pointer || !expected || length < 4 || length > 64) return false;
    uint8_t digest[32];
    detail::sha256_oneshot(static_cast<const uint8_t*>(function_pointer), length, digest);
    uint8_t difference = 0;
    for (size_t index = 0; index < sizeof(digest); ++index) difference |= digest[index] ^ expected[index];
    return difference == 0;
}

} // namespace stealth::integrity

#else

namespace stealth::integrity {

inline bool prologue_sha256(
    const void* function_pointer,
    std::size_t length,
    const uint8_t expected[32]) noexcept {
    if (!function_pointer || !expected || length < 4 || length > 64) return false;
    uint8_t digest[32];
    detail::sha256_oneshot(static_cast<const uint8_t*>(function_pointer), length, digest);
    uint8_t difference = 0;
    for (size_t index = 0; index < sizeof(digest); ++index) difference |= digest[index] ^ expected[index];
    return difference == 0;
}

} // namespace stealth::integrity

#endif // _WIN32
#endif // STEALTH_INTEGRITY_INTEGRITY_HPP
