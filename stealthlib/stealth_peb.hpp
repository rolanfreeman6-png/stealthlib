#pragma once
#ifndef STEALTH_PEB_HPP
#define STEALTH_PEB_HPP

#include <cstdint>
#include <cstddef>
#include <cstring>

#ifdef STEALTH_PLATFORM_WINDOWS
#include <windows.h>
#endif

namespace stealth {
namespace peb {

#if defined(_M_X64) || defined(__x86_64__)
inline void* get_peb_ptr() noexcept {
    return reinterpret_cast<void*>(__readgsqword(0x60));
}
#elif defined(_M_IX86) || defined(__i386__)
inline void* get_peb_ptr() noexcept {
    return reinterpret_cast<void*>(__readfsdword(0x30));
}
#else
inline void* get_peb_ptr() noexcept { return nullptr; }
#endif

inline bool get_module_base_by_name(const wchar_t* module_name, void** out_base) noexcept;

}

namespace image {

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

struct IMAGE_EXPORT_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
};

constexpr uint16_t IMAGE_DOS_SIGNATURE_VAL = 0x5A4D;
constexpr uint32_t IMAGE_NT_SIGNATURE_VAL = 0x00004550;

struct IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

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
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE_VAL) return nullptr;
    return reinterpret_cast<IMAGE_NT_HEADERS64*>(static_cast<char*>(module_base) + dos->e_lfanew);
}

inline IMAGE_EXPORT_DIRECTORY* get_export_directory(void* module_base) noexcept {
    auto nt = get_nt_headers(module_base);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE_VAL) return nullptr;
    auto& dir = nt->OptionalHeader.DataDirectory[0];
    if (dir.VirtualAddress == 0 || dir.Size == 0) return nullptr;
    return reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(static_cast<char*>(module_base) + dir.VirtualAddress);
}

inline void* get_proc_address_internal(void* module_base, const char* function_name) noexcept {
    auto exp = get_export_directory(module_base);
    if (!exp || exp->NumberOfNames == 0 || exp->NumberOfFunctions == 0) return nullptr;

    auto names = reinterpret_cast<uint32_t*>(static_cast<char*>(module_base) + exp->AddressOfNames);
    auto ordinals = reinterpret_cast<uint16_t*>(static_cast<char*>(module_base) + exp->AddressOfNameOrdinals);
    auto functions = reinterpret_cast<uint32_t*>(static_cast<char*>(module_base) + exp->AddressOfFunctions);

    for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
        const char* name = reinterpret_cast<const char*>(module_base) + names[i];
        bool match = true;
        const char* a = function_name;
        const char* b = name;
        while (*a && *b) {
            unsigned char ca = *a;
            unsigned char cb = *b;
            if (ca >= 'A' && ca <= 'Z') ca = ca - 'A' + 'a';
            if (cb >= 'A' && cb <= 'Z') cb = cb - 'A' + 'a';
            if (ca != cb) {
                match = false;
                break;
            }
            ++a;
            ++b;
        }
        if (match && *a == '\0' && *b == '\0') {
            uint16_t ordinal = ordinals[i];
            if (ordinal >= exp->NumberOfFunctions) return nullptr;
            return static_cast<char*>(module_base) + functions[ordinal];
        }
    }
    return nullptr;
}

}

namespace peb {

inline bool get_module_base_by_name(const wchar_t* module_name, void** out_base) noexcept {
    struct UNICODE_STRING {
        uint16_t Length;
        uint16_t MaximumLength;
        wchar_t* Buffer;
    };
    struct LIST_ENTRY {
        void* Flink;
        void* Blink;
    };
    struct LDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        void* DllBase;
        void* EntryPoint;
        uint32_t SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        uint32_t Flags;
        uint16_t LoadCount;
        uint16_t TlsIndex;
        LIST_ENTRY HashLinks;
        void* SectionPointer;
        uint32_t CheckSum;
        void* LoadedImports;
        void* EntryPointActivationContext;
        void* PatchInformation;
        LIST_ENTRY ForwarderLinks;
        LIST_ENTRY ServiceTagLinks;
        LIST_ENTRY StaticLinks;
        void* ContextInformation;
        void* OriginalBase;
        int64_t LoadTime;
    };
    struct PEB_LDR_DATA {
        uint32_t Length;
        uint8_t Initialized;
        void* SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
        void* EntryInProgress;
        uint8_t ShutdownInProgress;
        void* ShutdownThreadId;
    };
    struct PEB {
        uint8_t InheritedAddressSpace;
        uint8_t ReadImageFileExecOptions;
        uint8_t BeingDebugged;
        uint8_t BitField;
        void* Mutant;
        void* ImageBaseAddress;
        PEB_LDR_DATA* Ldr;
        void* ProcessParameters;
    };

    auto peb = get_peb_ptr();
    if (!peb) return false;
    auto pPEB = reinterpret_cast<PEB*>(peb);
    if (!pPEB->Ldr) return false;

    size_t name_len = 0;
    while (module_name[name_len] != L'\0') ++name_len;

    auto entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(pPEB->Ldr->InLoadOrderModuleList.Flink);
    while (entry && entry->BaseDllName.Buffer) {
        if (entry->DllBase) {
            if (entry->BaseDllName.Length == static_cast<uint16_t>(name_len * sizeof(wchar_t))) {
                bool match = true;
                for (size_t i = 0; i < name_len; ++i) {
                    wchar_t a = module_name[i];
                    wchar_t b = entry->BaseDllName.Buffer[i];
                    if (a >= L'A' && a <= L'Z') a = a - L'A' + L'a';
                    if (b >= L'A' && b <= L'Z') b = b - L'A' + L'a';
                    if (a != b) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    *out_base = entry->DllBase;
                    return true;
                }
            }
        }
        entry = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(entry->InLoadOrderLinks.Flink);
        if (!entry) break;
    }
    return false;
}

inline bool get_module_base_ansi(const char* module_name, void** out_base) noexcept {
    wchar_t wide_name[260];
    size_t i = 0;
    while (module_name[i] && i < 259) {
        wide_name[i] = static_cast<wchar_t>(static_cast<unsigned char>(module_name[i]));
        ++i;
    }
    wide_name[i] = L'\0';
    return get_module_base_by_name(wide_name, out_base);
}

}

template<typename FuncT>
class stealth_api {
public:
    using func_type = FuncT;

private:
    FuncT* func_ptr;

public:
    stealth_api() noexcept : func_ptr(nullptr) {}
    stealth_api(nullptr_t) noexcept : func_ptr(nullptr) {}

    stealth_api(const char* module_name, const char* function_name) noexcept {
        func_ptr = resolve(module_name, function_name);
    }

    stealth_api(void* module_base, const char* function_name) noexcept {
        if (module_base) {
            func_ptr = reinterpret_cast<FuncT*>(image::get_proc_address_internal(module_base, function_name));
        } else {
            func_ptr = nullptr;
        }
    }

    [[nodiscard]] FuncT* get() const noexcept { return func_ptr; }
    [[nodiscard]] FuncT* operator->() const noexcept { return func_ptr; }
    [[nodiscard]] explicit operator bool() const noexcept { return func_ptr != nullptr; }
    [[nodiscard]] explicit operator FuncT*() const noexcept { return func_ptr; }
    [[nodiscard]] bool is_valid() const noexcept { return func_ptr != nullptr; }
    [[nodiscard]] void* get_raw() const noexcept { return reinterpret_cast<void*>(func_ptr); }

    void reset() noexcept { func_ptr = nullptr; }

    void reset(const char* module_name, const char* function_name) noexcept {
        func_ptr = resolve(module_name, function_name);
    }

private:
    static FuncT* resolve(const char* module_name, const char* function_name) noexcept {
        void* base = nullptr;
        if (peb::get_module_base_ansi(module_name, &base)) {
            return reinterpret_cast<FuncT*>(image::get_proc_address_internal(base, function_name));
        }
        return nullptr;
    }
};

namespace api {

template<typename T>
T get_function(const char* module_name, const char* function_name) noexcept {
    void* base = nullptr;
    if (peb::get_module_base_ansi(module_name, &base)) {
        return reinterpret_cast<T>(image::get_proc_address_internal(base, function_name));
    }
    return nullptr;
}

}

inline void* get_nt_api(const char* name) noexcept {
    void* base = nullptr;
    if (peb::get_module_base_by_name(L"ntdll.dll", &base)) {
        return image::get_proc_address_internal(base, name);
    }
    return nullptr;
}

inline void* get_kernel32_api(const char* name) noexcept {
    void* base = nullptr;
    if (peb::get_module_base_by_name(L"kernel32.dll", &base)) {
        return image::get_proc_address_internal(base, name);
    }
    return nullptr;
}

inline void* get_user32_api(const char* name) noexcept {
    void* base = nullptr;
    if (peb::get_module_base_by_name(L"user32.dll", &base)) {
        return image::get_proc_address_internal(base, name);
    }
    return nullptr;
}

inline void* get_module_function(const char* module_name, const char* function_name) noexcept {
    void* base = nullptr;
    if (peb::get_module_base_ansi(module_name, &base)) {
        return image::get_proc_address_internal(base, function_name);
    }
    return nullptr;
}

inline void* get_ntdll() noexcept {
    void* base = nullptr;
    peb::get_module_base_by_name(L"ntdll.dll", &base);
    return base;
}

inline void* get_kernel32() noexcept {
    void* base = nullptr;
    peb::get_module_base_by_name(L"kernel32.dll", &base);
    return base;
}

inline void* get_user32() noexcept {
    void* base = nullptr;
    peb::get_module_base_by_name(L"user32.dll", &base);
    return base;
}

namespace detection {

inline bool is_debugger_present() noexcept {
    struct PEB {
        uint8_t InheritedAddressSpace;
        uint8_t ReadImageFileExecOptions;
        uint8_t BeingDebugged;
    };
    auto peb = reinterpret_cast<PEB*>(peb::get_peb_ptr());
    return peb && peb->BeingDebugged != 0;
}

inline bool check_remote_debugger() noexcept;

}

}

#endif