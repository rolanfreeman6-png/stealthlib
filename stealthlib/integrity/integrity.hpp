#pragma once
#ifndef STEALTH_INTEGRITY_INTEGRITY_HPP
#define STEALTH_INTEGRITY_INTEGRITY_HPP

#include <cstdint>
#include <cstddef>
#include <cstring>
#include "../detail/sha256.hpp"

#ifdef _WIN32
#include <windows.h>
#include "../pe/pe_parser.hpp"

namespace stealth::integrity {

inline uintptr_t get_section_rva_in_image(void* base, uint32_t rva) noexcept {
    if (!base) return 0;
    auto nt = stealth::get_nt(base);
    if (!nt) return 0;
    if (rva >= nt->SizeOfImage) return 0;
    return rva;
}

struct hook_info {
    bool hooked = false;
    void* expected = nullptr;
    void* actual = nullptr;
    uintptr_t deviation = 0;
};

inline hook_info compare_iat_thunk(const char* module_name, const char* func_name) noexcept {
    hook_info info{};
    HMODULE mod = GetModuleHandleA(module_name);
    if (!mod) return info;
    auto dos = reinterpret_cast<uint8_t*>(mod);
    auto pe = reinterpret_cast<uint8_t*>(mod) + *reinterpret_cast<uint32_t*>(dos + 0x3C);
    uint16_t magic = *reinterpret_cast<uint16_t*>(pe + 0x18);
    std::size_t import_dd_offset = (magic == 0x20b) ? 0x90 : 0x80;
    auto importRva = *reinterpret_cast<uint32_t*>(pe + import_dd_offset);
    if (!importRva) return info;
    auto importDesc = reinterpret_cast<uint8_t*>(mod) + importRva;
    while (true) {
        auto origFirstThunk = *reinterpret_cast<uint32_t*>(importDesc + 0x00);
        auto name_rva = *reinterpret_cast<uint32_t*>(importDesc + 0x0C);
        auto firstThunk = *reinterpret_cast<uint32_t*>(importDesc + 0x10);
        if (!origFirstThunk && !name_rva && !firstThunk) break;
        auto thunk = reinterpret_cast<uintptr_t*>(reinterpret_cast<uint8_t*>(mod) + firstThunk);
        auto orig = origFirstThunk ? reinterpret_cast<uintptr_t*>(reinterpret_cast<uint8_t*>(mod) + origFirstThunk) : thunk;
        if (orig != nullptr) {
#if defined(_WIN64)
            static constexpr uintptr_t ORDINAL_FLAG = 0x8000000000000000ULL;
#else
            static constexpr uintptr_t ORDINAL_FLAG = 0x80000000ULL;
#endif
            for (size_t idx = 0; ; ++idx) {
                uintptr_t thunk_val = orig[idx];
                if (thunk_val == 0) break;
                if ((thunk_val & ORDINAL_FLAG) == 0) {
                    auto hintNameRva = static_cast<uint32_t>(thunk_val & 0x7FFFFFFFu);
                    auto fname = reinterpret_cast<const char*>(mod) + hintNameRva + 2;
                    if (std::strcmp(fname, func_name) == 0) {
                        uintptr_t iat_value = thunk[idx];
                        uintptr_t int_value = orig[idx];
                        info.expected = reinterpret_cast<void*>(int_value);
                        info.actual = reinterpret_cast<void*>(iat_value);
                        info.deviation = static_cast<uintptr_t>(iat_value >= int_value ? iat_value - int_value : int_value - iat_value);
                        info.hooked = (iat_value != int_value);
                        return info;
                    }
                }
            }
        }
        importDesc += 20;
    }
    return info;
}

inline hook_info compare_export_to_module(const char* module_name, const char* func_name) noexcept {
    hook_info info{};
    void* base = nullptr;
    if (!get_module_base_ansi(module_name, &base)) return info;
    void* proc = get_proc(base, func_name);
    if (!proc) return info;
    HMODULE mod = GetModuleHandleA(module_name);
    if (!mod || reinterpret_cast<void*>(mod) != base) return info;
    info.expected = proc; info.actual = proc;
    return info;
}

inline bool is_iat_hooked(const char* module_name, const char* func_name) noexcept {
    return compare_iat_thunk(module_name, func_name).hooked;
}

inline bool is_eat_forwarded(const char* module_name, const char* func_name) noexcept {
    void* base = nullptr;
    if (!get_module_base_ansi(module_name, &base)) return false;
    auto nt8 = reinterpret_cast<uint8_t*>(stealth::get_nt(base));
    if (!nt8) return false;
    uint16_t magic = *reinterpret_cast<uint16_t*>(nt8 + 0x18);
    std::size_t dd_off = (magic == 0x20b) ? 0x88u : 0x78u;
    uint32_t exp_rva = *reinterpret_cast<uint32_t*>(nt8 + dd_off);
    uint32_t exp_size = *reinterpret_cast<uint32_t*>(nt8 + dd_off + 4);
    if (!exp_rva) return false;
    auto base8 = reinterpret_cast<uint8_t*>(base);
    auto exp_dir = base8 + exp_rva;
    auto funcs = reinterpret_cast<uint32_t*>(base8 + *reinterpret_cast<uint32_t*>(exp_dir + 0x1C));
    auto ordinals = reinterpret_cast<uint16_t*>(base8 + *reinterpret_cast<uint32_t*>(exp_dir + 0x24));
    auto names = reinterpret_cast<uint32_t*>(base8 + *reinterpret_cast<uint32_t*>(exp_dir + 0x20));
    auto n = *reinterpret_cast<uint32_t*>(exp_dir + 0x18);
    for (uint32_t i = 0; i < n; ++i) {
        const char* n_name = reinterpret_cast<const char*>(base) + names[i];
        if (std::strcmp(n_name, func_name) == 0) {
            if (ordinals[i] >= *reinterpret_cast<uint32_t*>(exp_dir + 0x14)) return false;
            uint32_t rva = funcs[ordinals[i]];
            return rva >= exp_rva && rva < exp_rva + exp_size;
        }
    }
    return false;
}

inline bool prologue_sha256(void const* func_ptr, std::size_t n, uint8_t const expected[32]) noexcept {
    if (!func_ptr || n < 4 || n > 64) return false;
    uint8_t digest[32];
    detail::sha256_oneshot(reinterpret_cast<uint8_t const*>(func_ptr), n, digest);
    uint8_t diff = 0;
    for (int i = 0; i < 32; ++i) diff |= digest[i] ^ expected[i];
    return diff == 0;
}

} // namespace stealth::integrity

#endif // _WIN32

// Cross-platform helpers (non-Windows)
#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
namespace stealth::integrity {
inline bool hardware_breakpoint_register_nonzero() noexcept {
    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &ctx)) return false;
    return (ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3) != 0;
}
} // namespace stealth::integrity
#else
namespace stealth::integrity {
inline bool hardware_breakpoint_register_nonzero() noexcept { return false; }
} // namespace stealth::integrity
#endif

#ifndef _WIN32
namespace stealth::integrity {
inline bool prologue_sha256(void const* func_ptr, std::size_t n, uint8_t const expected[32]) noexcept {
    if (!func_ptr || n < 4 || n > 64) return false;
    uint8_t digest[32];
    detail::sha256_oneshot(reinterpret_cast<uint8_t const*>(func_ptr), n, digest);
    uint8_t diff = 0;
    for (int i = 0; i < 32; ++i) diff |= digest[i] ^ expected[i];
    return diff == 0;
}
} // namespace stealth::integrity
#endif

#endif // STEALTH_INTEGRITY_INTEGRITY_HPP
