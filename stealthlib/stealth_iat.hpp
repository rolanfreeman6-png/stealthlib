#pragma once
#ifndef STEALTH_IAT_HPP
#define STEALTH_IAT_HPP

#include <cstdint>
#include <cstddef>

#ifdef STEALTH_PLATFORM_WINDOWS
#include <windows.h>
#endif

namespace stealth {
namespace iat {

#ifdef STEALTH_PLATFORM_WINDOWS

namespace detail {

struct IMAGE_DOS_HEADER {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t e_lfanew;
};

struct IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct IMAGE_SECTION_HEADER {
    uint8_t Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct IMAGE_IMPORT_DESCRIPTOR {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
};

constexpr uint16_t IMAGE_DOS_SIGNATURE = 0x5A4D;
constexpr uint32_t IMAGE_NT_SIGNATURE = 0x00004550;

struct IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

struct IMAGE_NT_HEADERS64 {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

inline IMAGE_DOS_HEADER* get_dos_header(void* module_base) noexcept {
    return reinterpret_cast<IMAGE_DOS_HEADER*>(module_base);
}

inline IMAGE_NT_HEADERS64* get_nt_headers(void* module_base) noexcept {
    auto dos = get_dos_header(module_base);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    return reinterpret_cast<IMAGE_NT_HEADERS64*>(static_cast<char*>(module_base) + dos->e_lfanew);
}

inline IMAGE_SECTION_HEADER* get_section_headers(void* module_base) noexcept {
    auto nt = get_nt_headers(module_base);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    return reinterpret_cast<IMAGE_SECTION_HEADER*>(
        reinterpret_cast<char*>(&nt->OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader
    );
}

inline uint32_t rva_to_offset(void* module_base, uint32_t rva) noexcept {
    auto nt = get_nt_headers(module_base);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    auto sections = get_section_headers(module_base);
    if (!sections) return 0;

    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        auto& sec = sections[i];
        if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + sec.VirtualSize) {
            return sec.PointerToRawData + (rva - sec.VirtualAddress);
        }
    }
    return 0;
}

}

struct import_entry {
    const char* module_name;
    const char* function_name;
    uint16_t ordinal;
    void* address;
    bool is_ordinal;
};

class import_resolver {
public:
    static constexpr size_t MAX_IMPORTS = 256;

    import_resolver() noexcept = default;

    bool add_import(const char* module_name, const char* function_name) noexcept {
        if (count_ >= MAX_IMPORTS) return false;
        entries_[count_].module_name = module_name;
        entries_[count_].function_name = function_name;
        entries_[count_].ordinal = 0;
        entries_[count_].is_ordinal = false;
        entries_[count_].address = nullptr;
        ++count_;
        return true;
    }

    bool add_import(const char* module_name, uint16_t ordinal) noexcept {
        if (count_ >= MAX_IMPORTS) return false;
        entries_[count_].module_name = module_name;
        entries_[count_].function_name = nullptr;
        entries_[count_].ordinal = ordinal;
        entries_[count_].is_ordinal = true;
        entries_[count_].address = nullptr;
        ++count_;
        return true;
    }

    void resolve_all() noexcept {
        for (size_t i = 0; i < count_; ++i) {
            resolve_entry(entries_[i]);
        }
    }

    [[nodiscard]] void* get_address(const char* module_name, const char* function_name) const noexcept {
        for (size_t i = 0; i < count_; ++i) {
            if (!entries_[i].is_ordinal &&
                entries_[i].module_name &&
                entries_[i].function_name &&
                compare_strings_case_insensitive(entries_[i].module_name, module_name) &&
                compare_strings_case_insensitive(entries_[i].function_name, function_name)) {
                return entries_[i].address;
            }
        }
        return nullptr;
    }

    [[nodiscard]] void* get_address(const char* module_name, uint16_t ordinal) const noexcept {
        for (size_t i = 0; i < count_; ++i) {
            if (entries_[i].is_ordinal &&
                entries_[i].module_name &&
                entries_[i].ordinal == ordinal &&
                compare_strings_case_insensitive(entries_[i].module_name, module_name)) {
                return entries_[i].address;
            }
        }
        return nullptr;
    }

    [[nodiscard]] size_t count() const noexcept { return count_; }
    [[nodiscard]] const import_entry* entries() const noexcept { return entries_; }

private:
    import_entry entries_[MAX_IMPORTS];
    size_t count_ = 0;

    static bool compare_strings_case_insensitive(const char* a, const char* b) noexcept {
        while (*a && *b) {
            char ca = *a;
            char cb = *b;
            if (ca >= 'A' && ca <= 'Z') ca = ca - 'A' + 'a';
            if (cb >= 'A' && cb <= 'Z') cb = cb - 'A' + 'a';
            if (ca != cb) return false;
            ++a;
            ++b;
        }
        return *a == *b;
    }

    static void resolve_entry(import_entry& entry) noexcept {
        auto base = get_module_base(entry.module_name);
        if (!base) return;

        if (entry.is_ordinal) {
            entry.address = resolve_ordinal(base, entry.ordinal);
        } else {
            entry.address = resolve_name(base, entry.function_name);
        }
    }

    static void* get_module_base(const char* module_name) noexcept;
    static void* resolve_name(void* module_base, const char* function_name) noexcept;
    static void* resolve_ordinal(void* module_base, uint16_t ordinal) noexcept;
};

struct delayed_import {
    const char* module_name;
    const char** function_names;
    size_t function_count;
    void** addresses;
};

class delayed_loader {
public:
    static constexpr size_t MAX_MODULES = 32;
    static constexpr size_t MAX_FUNCTIONS_PER_MODULE = 128;

    delayed_loader() noexcept = default;

    bool add_module(const char* module_name, const char** function_names, size_t count, void** addresses) noexcept {
        if (module_count_ >= MAX_MODULES) return false;
        if (count > MAX_FUNCTIONS_PER_MODULE) return false;

        modules_[module_count_].module_name = module_name;
        modules_[module_count_].function_names = function_names;
        modules_[module_count_].function_count = count;
        modules_[module_count_].addresses = addresses;
        ++module_count_;
        return true;
    }

    void load_all() noexcept {
        for (size_t m = 0; m < module_count_; ++m) {
            auto& mod = modules_[m];
            auto base = get_module_base(mod.module_name);
            if (!base) continue;

            for (size_t f = 0; f < mod.function_count; ++f) {
                mod.addresses[f] = resolve_name(base, mod.function_names[f]);
            }
        }
    }

    void unload_all() noexcept {
        for (size_t m = 0; m < module_count_; ++m) {
            for (size_t f = 0; f < modules_[m].function_count; ++f) {
                modules_[m].addresses[f] = nullptr;
            }
        }
    }

private:
    delayed_import modules_[MAX_MODULES];
    size_t module_count_ = 0;

    static void* get_module_base(const char* module_name) noexcept;
    static void* resolve_name(void* module_base, const char* function_name) noexcept;
};

struct thunk_data {
    void* function_address;
    const char* module_name;
    const char* function_name;
    bool is_ordinal;
    uint16_t ordinal;
};

class thunk_manager {
public:
    static constexpr size_t MAX_THUNKS = 512;

    thunk_manager() noexcept = default;

    bool add_thunk(const char* module_name, const char* function_name) noexcept {
        if (count_ >= MAX_THUNKS) return false;
        thunks_[count_].module_name = module_name;
        thunks_[count_].function_name = function_name;
        thunks_[count_].function_address = nullptr;
        thunks_[count_].is_ordinal = false;
        thunks_[count_].ordinal = 0;
        ++count_;
        return true;
    }

    bool add_thunk(const char* module_name, uint16_t ordinal) noexcept {
        if (count_ >= MAX_THUNKS) return false;
        thunks_[count_].module_name = module_name;
        thunks_[count_].function_name = nullptr;
        thunks_[count_].function_address = nullptr;
        thunks_[count_].is_ordinal = true;
        thunks_[count_].ordinal = ordinal;
        ++count_;
        return true;
    }

    void resolve_all() noexcept {
        for (size_t i = 0; i < count_; ++i) {
            resolve_thunk(thunks_[i]);
        }
    }

    [[nodiscard]] void* get_thunk_address(const char* module_name, const char* function_name) const noexcept {
        for (size_t i = 0; i < count_; ++i) {
            if (!thunks_[i].is_ordinal &&
                thunks_[i].module_name &&
                thunks_[i].function_name &&
                compare_strings_case_insensitive(thunks_[i].module_name, module_name) &&
                compare_strings_case_insensitive(thunks_[i].function_name, function_name)) {
                return thunks_[i].function_address;
            }
        }
        return nullptr;
    }

    [[nodiscard]] size_t count() const noexcept { return count_; }
    [[nodiscard]] const thunk_data* thunks() const noexcept { return thunks_; }

private:
    thunk_data thunks_[MAX_THUNKS];
    size_t count_ = 0;

    static bool compare_strings_case_insensitive(const char* a, const char* b) noexcept {
        while (*a && *b) {
            char ca = *a;
            char cb = *b;
            if (ca >= 'A' && ca <= 'Z') ca = ca - 'A' + 'a';
            if (cb >= 'A' && cb <= 'Z') cb = cb - 'A' + 'a';
            if (ca != cb) return false;
            ++a;
            ++b;
        }
        return *a == *b;
    }

    static void resolve_thunk(thunk_data& thunk) noexcept;
};

inline bool scrub_import_directory(void* module_base) noexcept {
    auto dos = detail::get_dos_header(module_base);
    if (!dos || dos->e_magic != 0x5A4D) return false;

    auto nt = detail::get_nt_headers(module_base);
    if (!nt || nt->Signature != 0x4550) return false;

    auto& import_dir = nt->OptionalHeader.DataDirectory[1];
    if (import_dir.VirtualAddress == 0 || import_dir.Size == 0) return true;

    uint32_t offset = detail::rva_to_offset(module_base, import_dir.VirtualAddress);
    if (offset == 0) return false;

    auto desc = reinterpret_cast<detail::IMAGE_IMPORT_DESCRIPTOR*>(static_cast<char*>(module_base) + offset);

    while (desc->Name != 0) {
        uint32_t name_offset = detail::rva_to_offset(module_base, desc->Name);
        if (name_offset != 0) {
            auto name_ptr = reinterpret_cast<char*>(module_base) + name_offset;
            for (size_t i = 0; i < 256; ++i) {
                if (name_ptr[i] == '\0') break;
                name_ptr[i] = 0;
            }
        }
        ++desc;
    }

    import_dir.VirtualAddress = 0;
    import_dir.Size = 0;
    return true;
}

inline bool scrub_relocation_directory(void* module_base) noexcept {
    auto dos = detail::get_dos_header(module_base);
    if (!dos || dos->e_magic != 0x5A4D) return false;

    auto nt = detail::get_nt_headers(module_base);
    if (!nt || nt->Signature != 0x4550) return false;

    auto& reloc_dir = nt->OptionalHeader.DataDirectory[5];
    reloc_dir.VirtualAddress = 0;
    reloc_dir.Size = 0;
    return true;
}

inline bool remove_exports(void* module_base) noexcept {
    auto dos = detail::get_dos_header(module_base);
    if (!dos || dos->e_magic != 0x5A4D) return false;

    auto nt = detail::get_nt_headers(module_base);
    if (!nt || nt->Signature != 0x4550) return false;

    auto& exp_dir = nt->OptionalHeader.DataDirectory[0];
    exp_dir.VirtualAddress = 0;
    exp_dir.Size = 0;
    return true;
}

#endif

namespace detail {
    inline void* get_module_by_name(const char* name) noexcept;
    inline void* find_function_by_name(void* module, const char* name) noexcept;
    inline void* find_function_by_ordinal(void* module, uint16_t ordinal) noexcept;
}

}

}

#endif