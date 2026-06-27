#pragma once
#ifndef STEALTH_PE_PE_LAYOUT_HPP
#define STEALTH_PE_PE_LAYOUT_HPP

#include <cstdint>
#include <cstddef>
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#ifdef _WIN32
#include <windows.h>
#include "../detail/hashes.hpp"

namespace stealth {

#if defined(_M_X64) || defined(__x86_64__)
inline void* get_peb_ptr() noexcept { return reinterpret_cast<void*>(__readgsqword(0x60)); }
#elif defined(_M_IX86)
inline void* get_peb_ptr() noexcept { return reinterpret_cast<void*>(__readfsdword(0x30)); }
#else
inline void* get_peb_ptr() noexcept { return nullptr; }
#endif

struct UNICODE_STRING_NT { uint16_t Length; uint16_t MaximumLength; wchar_t* Buffer; };
struct LIST_ENTRY_NT { void* Flink; void* Blink; };
struct LDR_ENTRY_NT { LIST_ENTRY_NT InLoadOrderLinks; LIST_ENTRY_NT InMemoryOrderLinks; LIST_ENTRY_NT InInitializationOrderLinks; void* DllBase; void* EntryPoint; uint32_t SizeOfImage; UNICODE_STRING_NT FullDllName; UNICODE_STRING_NT BaseDllName; };
struct PEB_LDR_NT { uint32_t Length; uint8_t Initialized; void* SsHandle; LIST_ENTRY_NT InLoadOrderModuleList; };
struct PEB_STRUCT_NT { uint8_t InheritedAddressSpace; uint8_t ReadImageFileExecOptions; uint8_t BeingDebugged; uint8_t BitField; void* Mutant; void* ImageBaseAddress; PEB_LDR_NT* Ldr; };

inline bool get_module_base(const wchar_t* name, void** out) noexcept {
    if (!out || !name) return false;
    *out = nullptr;
    auto peb = reinterpret_cast<PEB_STRUCT_NT*>(get_peb_ptr());
    if (!peb || !peb->Ldr) return false;
    size_t len = 0;
    while (name[len]) ++len;
    auto entry = reinterpret_cast<LDR_ENTRY_NT*>(peb->Ldr->InLoadOrderModuleList.Flink);
    while (entry && entry->BaseDllName.Buffer) {
        if (entry->BaseDllName.Length == static_cast<uint16_t>(len * 2)) {
            bool match = true;
            for (size_t i = 0; i < len; ++i) {
                wchar_t a = name[i], b = entry->BaseDllName.Buffer[i];
                if (a >= L'A' && a <= L'Z') a += 32;
                if (b >= L'A' && b <= L'Z') b += 32;
                if (a != b) { match = false; break; }
            }
            if (match) { *out = entry->DllBase; return true; }
        }
        entry = reinterpret_cast<LDR_ENTRY_NT*>(entry->InLoadOrderLinks.Flink);
    }
    return false;
}

inline bool get_module_base_ansi(const char* name, void** out) noexcept {
    wchar_t wide[260] = {};
    size_t i = 0;
    while (name[i] && i < 259) { wide[i] = static_cast<wchar_t>(static_cast<unsigned char>(name[i])); ++i; }
    return get_module_base(wide, out);
}

inline bool get_module_base_by_hash(uint64_t hash, void** out) noexcept {
    if (!out) return false;
    *out = nullptr;
    auto peb = reinterpret_cast<PEB_STRUCT_NT*>(get_peb_ptr());
    if (!peb || !peb->Ldr) return false;
    auto entry = reinterpret_cast<LDR_ENTRY_NT*>(peb->Ldr->InLoadOrderModuleList.Flink);
    while (entry && entry->BaseDllName.Buffer) {
        size_t chrs = entry->BaseDllName.Length / 2;
        uint64_t h = detail::fnv1a_basis;
        for (size_t i = 0; i < chrs; ++i) {
            uint8_t c = static_cast<uint8_t>(entry->BaseDllName.Buffer[i] & 0xFFu);
            if (c >= 'A' && c <= 'Z') c = static_cast<uint8_t>(c + 32);
            h ^= static_cast<uint64_t>(c);
            h *= detail::fnv1a_prime;
        }
        if (h == hash) { *out = entry->DllBase; return true; }
        entry = reinterpret_cast<LDR_ENTRY_NT*>(entry->InLoadOrderLinks.Flink);
    }
    return false;
}

struct DOS_HEADER_NT { uint16_t e_magic; uint8_t pad[0x3A]; int32_t e_lfanew; };
struct NT_HEADERS64_NT { uint32_t Signature; uint16_t Machine; uint16_t NumberOfSections; uint32_t TimeDateStamp; uint32_t PointerToSymbolTable; uint32_t NumberOfSymbols; uint16_t SizeOfOptionalHeader; uint16_t Characteristics; uint16_t Magic; uint8_t MajorLinkerVersion; uint8_t MinorLinkerVersion; uint32_t SizeOfCode; uint32_t SizeOfInitializedData; uint32_t SizeOfUninitializedData; uint32_t AddressOfEntryPoint; uint32_t BaseOfCode; uint64_t ImageBase; uint32_t SectionAlignment; uint32_t FileAlignment; uint16_t MajorOperatingSystemVersion; uint16_t MinorOperatingSystemVersion; uint16_t MajorImageVersion; uint16_t MinorImageVersion; uint16_t MajorSubsystemVersion; uint16_t MinorSubsystemVersion; uint32_t Win32VersionValue; uint32_t SizeOfImage; uint32_t SizeOfHeaders; uint32_t CheckSum; uint16_t Subsystem; uint16_t DllCharacteristics; uint64_t SizeOfStackReserve; uint64_t SizeOfStackCommit; uint64_t SizeOfHeapReserve; uint64_t SizeOfHeapCommit; uint32_t LoaderFlags; uint32_t NumberOfRvaAndSizes; uint32_t DataDirectory[32]; };
struct EXPORT_DIRECTORY_NT { uint32_t Characteristics; uint32_t TimeDateStamp; uint16_t MajorVersion; uint16_t MinorVersion; uint32_t Name; uint32_t Base; uint32_t NumberOfFunctions; uint32_t NumberOfNames; uint32_t AddressOfFunctions; uint32_t AddressOfNames; uint32_t AddressOfNameOrdinals; };

inline DOS_HEADER_NT* get_dos(void* base) noexcept {
    if (!base) return nullptr;
    return static_cast<DOS_HEADER_NT*>(base);
}
inline NT_HEADERS64_NT* get_nt(void* base) noexcept {
    auto dos = get_dos(base);
    if (!dos || dos->e_magic != 0x5A4D) return nullptr;
    if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x10000000) return nullptr;
    return reinterpret_cast<NT_HEADERS64_NT*>(static_cast<char*>(base) + dos->e_lfanew);
}
inline EXPORT_DIRECTORY_NT* get_export(void* base) noexcept {
    auto nt = get_nt(base);
    if (!nt || nt->Signature != 0x4550) return nullptr;
    uint32_t rva = nt->DataDirectory[0];
    if (!rva) return nullptr;
    return reinterpret_cast<EXPORT_DIRECTORY_NT*>(static_cast<char*>(base) + rva);
}
inline size_t rva_in_image(void* base, uint32_t rva) noexcept {
    if (!base) return 0;
    auto nt = get_nt(base);
    if (!nt) return 0;
    if (rva >= nt->SizeOfImage) return 0;
    return static_cast<size_t>(rva);
}

} // namespace stealth

#endif // _WIN32
#endif // STEALTH_PE_PE_LAYOUT_HPP
