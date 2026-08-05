#pragma once
#ifndef STEALTH_PE_PE_LAYOUT_HPP
#define STEALTH_PE_PE_LAYOUT_HPP

#include <cstddef>
#include <cstdint>

#ifdef _WIN32
#include <windows.h>
#if defined(_MSC_VER) || defined(__clang__)
#include <intrin.h>
#endif
#include "../detail/hashes.hpp"

namespace stealth {

// These offsets are defined by winnt.h (IMAGE_DOS_HEADER and
// IMAGE_EXPORT_DIRECTORY). Keeping the assertions makes any SDK-layout drift
// a compile-time failure rather than a silent PE parsing error.
static_assert(offsetof(IMAGE_DOS_HEADER, e_lfanew) == 0x3C);
static_assert(offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfFunctions) == 0x1C);
static_assert(offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfNames) == 0x20);
static_assert(offsetof(IMAGE_EXPORT_DIRECTORY, AddressOfNameOrdinals) == 0x24);
static_assert(offsetof(IMAGE_NT_HEADERS32, OptionalHeader.DataDirectory) == 0x78);
static_assert(offsetof(IMAGE_NT_HEADERS64, OptionalHeader.DataDirectory) == 0x88);

using DOS_HEADER_NT = IMAGE_DOS_HEADER;
using NT_HEADERS64_NT = IMAGE_NT_HEADERS;
using EXPORT_DIRECTORY_NT = IMAGE_EXPORT_DIRECTORY;

inline void* get_peb_ptr() noexcept {
#if defined(_M_X64) || defined(__x86_64__)
#if defined(_MSC_VER) || defined(__clang__)
    return reinterpret_cast<void*>(__readgsqword(0x60));
#elif defined(__GNUC__)
    void* peb = nullptr;
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(peb));
    return peb;
#else
    return nullptr;
#endif
#elif defined(_M_IX86) || defined(__i386__)
#if defined(_MSC_VER) || defined(__clang__)
    return reinterpret_cast<void*>(__readfsdword(0x30));
#elif defined(__GNUC__)
    void* peb = nullptr;
    __asm__ __volatile__("movl %%fs:0x30, %0" : "=r"(peb));
    return peb;
#else
    return nullptr;
#endif
#else
    return nullptr;
#endif
}

struct UNICODE_STRING_NT {
    uint16_t Length;
    uint16_t MaximumLength;
    wchar_t* Buffer;
};

struct LIST_ENTRY_NT {
    void* Flink;
    void* Blink;
};

struct LDR_ENTRY_NT {
    LIST_ENTRY_NT InLoadOrderLinks;
    LIST_ENTRY_NT InMemoryOrderLinks;
    LIST_ENTRY_NT InInitializationOrderLinks;
    void* DllBase;
    void* EntryPoint;
    uint32_t SizeOfImage;
    UNICODE_STRING_NT FullDllName;
    UNICODE_STRING_NT BaseDllName;
};

struct PEB_LDR_NT {
    uint32_t Length;
    uint8_t Initialized;
    void* SsHandle;
    LIST_ENTRY_NT InLoadOrderModuleList;
};

struct PEB_STRUCT_NT {
    uint8_t InheritedAddressSpace;
    uint8_t ReadImageFileExecOptions;
    uint8_t BeingDebugged;
    uint8_t BitField;
    void* Mutant;
    void* ImageBaseAddress;
    PEB_LDR_NT* Ldr;
};

inline bool equal_wide_ascii_case_insensitive(
    const wchar_t* left,
    const wchar_t* right,
    size_t length) noexcept {
    if (!left || !right) return false;
    for (size_t i = 0; i < length; ++i) {
        wchar_t a = left[i];
        wchar_t b = right[i];
        if (a >= L'A' && a <= L'Z') a = static_cast<wchar_t>(a + (L'a' - L'A'));
        if (b >= L'A' && b <= L'Z') b = static_cast<wchar_t>(b + (L'a' - L'A'));
        if (a != b) return false;
    }
    return true;
}

inline bool get_module_base(const wchar_t* name, void** out) noexcept {
    if (!out || !name) return false;
    *out = nullptr;

    auto* peb = static_cast<PEB_STRUCT_NT*>(get_peb_ptr());
    if (!peb || !peb->Ldr) return false;

    size_t length = 0;
    while (name[length] != L'\0') {
        if (length >= 0x7FFFu) return false;
        ++length;
    }

    auto* list = &peb->Ldr->InLoadOrderModuleList;
    auto* link = static_cast<LIST_ENTRY_NT*>(list->Flink);
    for (size_t entries = 0; link && link != list && entries < 4096; ++entries) {
        auto* entry = reinterpret_cast<LDR_ENTRY_NT*>(link);
        if (entry->BaseDllName.Buffer &&
            entry->BaseDllName.Length == static_cast<uint16_t>(length * sizeof(wchar_t)) &&
            equal_wide_ascii_case_insensitive(name, entry->BaseDllName.Buffer, length)) {
            *out = entry->DllBase;
            return true;
        }
        link = static_cast<LIST_ENTRY_NT*>(entry->InLoadOrderLinks.Flink);
    }
    return false;
}

inline bool get_module_base_ansi(const char* name, void** out) noexcept {
    if (!out || !name) return false;
    *out = nullptr;

    wchar_t wide[MAX_PATH] = {};
    size_t i = 0;
    while (name[i] != '\0' && i + 1 < MAX_PATH) {
        wide[i] = static_cast<wchar_t>(static_cast<unsigned char>(name[i]));
        ++i;
    }
    if (name[i] != '\0') return false;
    return get_module_base(wide, out);
}

inline bool get_module_base_by_hash(uint64_t hash, void** out) noexcept {
    if (!out) return false;
    *out = nullptr;

    auto* peb = static_cast<PEB_STRUCT_NT*>(get_peb_ptr());
    if (!peb || !peb->Ldr) return false;

    auto* list = &peb->Ldr->InLoadOrderModuleList;
    auto* link = static_cast<LIST_ENTRY_NT*>(list->Flink);
    for (size_t entries = 0; link && link != list && entries < 4096; ++entries) {
        auto* entry = reinterpret_cast<LDR_ENTRY_NT*>(link);
        if (entry->BaseDllName.Buffer) {
            const size_t characters = entry->BaseDllName.Length / sizeof(wchar_t);
            uint64_t current = detail::fnv1a_basis;
            for (size_t i = 0; i < characters; ++i) {
                uint8_t character = static_cast<uint8_t>(entry->BaseDllName.Buffer[i] & 0xFFu);
                if (character >= 'A' && character <= 'Z') {
                    character = static_cast<uint8_t>(character + ('a' - 'A'));
                }
                current ^= static_cast<uint64_t>(character);
                current *= detail::fnv1a_prime;
            }
            if (current == hash) {
                *out = entry->DllBase;
                return true;
            }
        }
        link = static_cast<LIST_ENTRY_NT*>(entry->InLoadOrderLinks.Flink);
    }
    return false;
}

inline DOS_HEADER_NT* get_dos(void* base) noexcept {
    if (!base) return nullptr;
    return static_cast<DOS_HEADER_NT*>(base);
}

inline bool readable_process_range(const void* address, size_t length) noexcept {
    if (!address || length == 0) return false;
    auto current = reinterpret_cast<uintptr_t>(address);
    const uintptr_t end = current + length;
    if (end < current) return false;

    while (current < end) {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQuery(reinterpret_cast<const void*>(current), &info, sizeof(info)) != sizeof(info)) {
            return false;
        }
        if (info.State != MEM_COMMIT || (info.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0) {
            return false;
        }
        const auto region_end = reinterpret_cast<uintptr_t>(info.BaseAddress) + info.RegionSize;
        if (region_end <= current) return false;
        current = region_end;
    }
    return true;
}

inline NT_HEADERS64_NT* get_nt(void* base) noexcept {
    if (!readable_process_range(base, sizeof(DOS_HEADER_NT))) return nullptr;
    auto* dos = get_dos(base);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return nullptr;
    const auto offset = static_cast<uint32_t>(dos->e_lfanew);
    const auto minimum_nt_size = sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) + sizeof(uint16_t);
    if (offset > static_cast<uint32_t>(-1) - minimum_nt_size ||
        !readable_process_range(static_cast<uint8_t*>(base) + offset, minimum_nt_size)) {
        return nullptr;
    }

    auto* nt = reinterpret_cast<NT_HEADERS64_NT*>(static_cast<uint8_t*>(base) + offset);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    const uint16_t magic = *reinterpret_cast<const uint16_t*>(
        static_cast<const uint8_t*>(base) + offset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER));
    if (magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return nullptr;
    }
    return nt;
}

inline uint16_t get_optional_header_magic(void* base) noexcept {
    auto* dos = get_dos(base);
    auto* nt = get_nt(base);
    if (!dos || !nt) return 0;
    const auto offset = static_cast<uint32_t>(dos->e_lfanew);
    return *reinterpret_cast<const uint16_t*>(
        static_cast<const uint8_t*>(base) + offset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER));
}

inline uint32_t get_image_size(void* base) noexcept {
    auto* dos = get_dos(base);
    if (!dos || !get_nt(base)) return 0;
    auto* raw = static_cast<uint8_t*>(base) + static_cast<uint32_t>(dos->e_lfanew);
    if (get_optional_header_magic(base) == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        constexpr size_t size_offset = offsetof(IMAGE_NT_HEADERS32, OptionalHeader) +
            offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfImage);
        if (!readable_process_range(raw + size_offset, sizeof(uint32_t))) return 0;
        return reinterpret_cast<const IMAGE_NT_HEADERS32*>(raw)->OptionalHeader.SizeOfImage;
    }
    constexpr size_t size_offset = offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
        offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfImage);
    if (!readable_process_range(raw + size_offset, sizeof(uint32_t))) return 0;
    return reinterpret_cast<const IMAGE_NT_HEADERS64*>(raw)->OptionalHeader.SizeOfImage;
}

inline bool rva_range_in_image(void* base, uint32_t rva, size_t length) noexcept {
    const uint32_t image_size = get_image_size(base);
    return image_size != 0 && rva <= image_size && length <= static_cast<size_t>(image_size - rva);
}

inline bool get_data_directory(
    void* base,
    uint32_t index,
    IMAGE_DATA_DIRECTORY* directory) noexcept {
    if (!directory || index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return false;
    auto* dos = get_dos(base);
    if (!dos || !get_nt(base)) return false;
    auto* raw = static_cast<uint8_t*>(base) + static_cast<uint32_t>(dos->e_lfanew);
    if (get_optional_header_magic(base) == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        constexpr size_t count_offset = offsetof(IMAGE_NT_HEADERS32, OptionalHeader) +
            offsetof(IMAGE_OPTIONAL_HEADER32, NumberOfRvaAndSizes);
        const size_t dir_offset = offsetof(IMAGE_NT_HEADERS32, OptionalHeader) +
            offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory) + index * sizeof(IMAGE_DATA_DIRECTORY);
        if (!readable_process_range(raw + count_offset, sizeof(uint32_t))) return false;
        auto* nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(raw);
        if (nt32->OptionalHeader.NumberOfRvaAndSizes <= index ||
            !readable_process_range(raw + dir_offset, sizeof(IMAGE_DATA_DIRECTORY))) return false;
        *directory = nt32->OptionalHeader.DataDirectory[index];
    } else {
        constexpr size_t count_offset = offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
            offsetof(IMAGE_OPTIONAL_HEADER64, NumberOfRvaAndSizes);
        const size_t dir_offset = offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
            offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) + index * sizeof(IMAGE_DATA_DIRECTORY);
        if (!readable_process_range(raw + count_offset, sizeof(uint32_t))) return false;
        auto* nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(raw);
        if (nt64->OptionalHeader.NumberOfRvaAndSizes <= index ||
            !readable_process_range(raw + dir_offset, sizeof(IMAGE_DATA_DIRECTORY))) return false;
        *directory = nt64->OptionalHeader.DataDirectory[index];
    }
    return directory->VirtualAddress != 0 &&
           rva_range_in_image(base, directory->VirtualAddress, directory->Size);
}

inline EXPORT_DIRECTORY_NT* get_export(void* base) noexcept {
    IMAGE_DATA_DIRECTORY directory{};
    if (!get_data_directory(base, IMAGE_DIRECTORY_ENTRY_EXPORT, &directory) ||
        directory.Size < sizeof(EXPORT_DIRECTORY_NT)) {
        return nullptr;
    }
    return reinterpret_cast<EXPORT_DIRECTORY_NT*>(
        static_cast<uint8_t*>(base) + directory.VirtualAddress);
}

inline size_t rva_in_image(void* base, uint32_t rva) noexcept {
    return rva_range_in_image(base, rva, 1) ? static_cast<size_t>(rva) : 0;
}

} // namespace stealth

#endif // _WIN32
#endif // STEALTH_PE_PE_LAYOUT_HPP
