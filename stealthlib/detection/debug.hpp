#pragma once
#ifndef STEALTH_DETECTION_DEBUG_HPP
#define STEALTH_DETECTION_DEBUG_HPP

#include <cstdint>
#include <cstddef>
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#ifdef _WIN32
#include <windows.h>
#endif

namespace stealth::detection {

inline bool is_debugger_present() noexcept {
#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
    auto peb = reinterpret_cast<uint8_t*>(__readgsqword(0x60));
    if (!peb) return false;
    return peb[2] != 0;
#elif defined(_WIN32) && defined(_M_IX86)
    auto peb = reinterpret_cast<uint8_t*>(__readfsdword(0x30));
    if (!peb) return false;
    return peb[2] != 0;
#else
    return false;
#endif
}

inline bool check_remote_debugger() noexcept {
#ifdef _WIN32
    typedef LONG(NTAPI* NtQIP_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    void* ntdll = nullptr;
    {
        auto peb = reinterpret_cast<uint8_t*>(__readgsqword(0x60));
        if (!peb) return false;
        auto pebLdr = *reinterpret_cast<uintptr_t*>(peb + 0x18);
        auto entry = *reinterpret_cast<uintptr_t*>(pebLdr + 0x10);
        const wchar_t* want = L"ntdll.dll";
        while (entry != pebLdr) {
            auto base = *reinterpret_cast<uintptr_t*>(entry + 0x30);
            auto buf = *reinterpret_cast<wchar_t**>(entry + 0x60);
            auto len = *reinterpret_cast<uint16_t*>(entry + 0x58);
            size_t chrs = len / 2;
            if (chrs == 9) {
                bool match = true;
                for (size_t i = 0; i < 9; ++i) {
                    wchar_t a = want[i], b = buf[i];
                    if (a >= L'A' && a <= L'Z') a += 32;
                    if (b >= L'A' && b <= L'Z') b += 32;
                    if (a != b) { match = false; break; }
                }
                if (match) { ntdll = reinterpret_cast<void*>(base); break; }
            }
            entry = *reinterpret_cast<uintptr_t*>(entry);
        }
    }
    if (!ntdll) return false;
    auto dos = reinterpret_cast<uint8_t*>(ntdll);
    auto pe_off = *reinterpret_cast<uint32_t*>(dos + 0x3C);
    auto nt8 = dos + pe_off;
    uint16_t magic = *reinterpret_cast<uint16_t*>(nt8 + 0x18);
    std::size_t dd_offset = (magic == 0x20b) ? 0x88 : 0x78;
    uint32_t export_rva = *reinterpret_cast<uint32_t*>(nt8 + dd_offset);
    if (!export_rva) return false;
    auto exp = dos + export_rva;
    auto names = reinterpret_cast<uint32_t*>(dos + *reinterpret_cast<uint32_t*>(exp + 0x20));
    auto ordinals = reinterpret_cast<uint16_t*>(dos + *reinterpret_cast<uint32_t*>(exp + 0x24));
    auto funcs = reinterpret_cast<uint32_t*>(dos + *reinterpret_cast<uint32_t*>(exp + 0x1C));
    auto n_names = *reinterpret_cast<uint32_t*>(exp + 0x18);
    NtQIP_t NtQIP = nullptr;
    const char target[] = "NtQueryInformationProcess";
    for (uint32_t i = 0; i < n_names; ++i) {
        const char* name = reinterpret_cast<const char*>(ntdll) + names[i];
        size_t j = 0; bool match = true;
        for (; name[j] && target[j]; ++j) {
            char a = name[j], b = target[j];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) { match = false; break; }
        }
        if (match && name[j] == '\0' && target[j] == '\0') {
            NtQIP = reinterpret_cast<NtQIP_t>(dos + funcs[ordinals[i]]);
            break;
        }
    }
    if (!NtQIP) return false;
    struct DebugInfo { LONG DebugPort; LONG DebugFlags; LONG DebugMask; LONG Unknown; } dbg{};
    LONG status = NtQIP(GetCurrentProcess(), 7, &dbg, sizeof(dbg), nullptr);
    return (status == 0 && dbg.DebugPort != 0);
#else
    return false;
#endif
}

inline uint64_t rdtsc() noexcept {
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
    return __rdtsc();
#elif defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
    unsigned int lo = 0, hi = 0;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return (static_cast<uint64_t>(hi) << 32) | lo;
#else
    return 0;
#endif
}

inline bool check_timing_anomaly() noexcept {
#if defined(_M_X64) || defined(__x86_64__) || defined(_M_IX86)
    uint64_t a = rdtsc();
    uint64_t acc = 0;
    for (uint64_t i = 0; i < 1024; ++i) acc += i * 0xA5A5A5A5ULL;
    volatile uint64_t sink = acc;
    (void)sink;
    uint64_t b = rdtsc();
    uint64_t delta = b - a;
    return delta < 64 || delta > 100000000ULL;
#else
    return false;
#endif
}

inline int hardware_breakpoint_count() noexcept {
#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &ctx)) return -1;
    int n = 0;
    if (ctx.Dr0) ++n; if (ctx.Dr1) ++n; if (ctx.Dr2) ++n; if (ctx.Dr3) ++n;
    return n;
#else
    return -1;
#endif
}

inline bool has_hardware_breakpoints() noexcept {
    return hardware_breakpoint_count() > 0;
}

} // namespace stealth::detection

#endif // STEALTH_DETECTION_DEBUG_HPP
