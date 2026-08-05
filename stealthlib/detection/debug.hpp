#pragma once
#ifndef STEALTH_DETECTION_DEBUG_HPP
#define STEALTH_DETECTION_DEBUG_HPP

#include <cstdint>
#include <cstddef>
#include <cstring>
#if defined(_MSC_VER)
#include <intrin.h>
#endif
#ifdef _WIN32
#include <windows.h>
#endif

namespace stealth::detection {

inline bool is_debugger_present() noexcept {
#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
#if defined(_MSC_VER)
    auto peb = reinterpret_cast<uint8_t*>(__readgsqword(0x60));
#elif defined(__GNUC__) || defined(__clang__)
    void* peb_address = nullptr;
    __asm__ __volatile__("movq %%gs:0x60, %0" : "=r"(peb_address));
    auto peb = static_cast<uint8_t*>(peb_address);
#else
    return false;
#endif
    if (!peb) return false;
    return peb[2] != 0;
#elif defined(_WIN32) && (defined(_M_IX86) || defined(__i386__))
#if defined(_MSC_VER)
    auto peb = reinterpret_cast<uint8_t*>(__readfsdword(0x30));
#elif defined(__GNUC__) || defined(__clang__)
    void* peb_address = nullptr;
    __asm__ __volatile__("movl %%fs:0x30, %0" : "=r"(peb_address));
    auto peb = static_cast<uint8_t*>(peb_address);
#else
    return false;
#endif
    if (!peb) return false;
    return peb[2] != 0;
#else
    return false;
#endif
}

inline bool check_remote_debugger() noexcept {
#ifdef _WIN32
    typedef LONG(NTAPI* NtQIP_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    // ProcessDebugPort is documented by NT internals as information class 7.
    // It returns a pointer-sized value, so ULONG_PTR is required on x64.
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return false;
    const FARPROC raw_nt_query_information_process =
        GetProcAddress(ntdll, "NtQueryInformationProcess");
    NtQIP_t nt_query_information_process = nullptr;
    static_assert(sizeof(nt_query_information_process) == sizeof(raw_nt_query_information_process));
    std::memcpy(
        &nt_query_information_process,
        &raw_nt_query_information_process,
        sizeof(nt_query_information_process));
    if (!nt_query_information_process) return false;
    ULONG_PTR debug_port = 0;
    const LONG status = nt_query_information_process(
        GetCurrentProcess(), 7, &debug_port, sizeof(debug_port), nullptr);
    return status >= 0 && debug_port != 0;
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
#if defined(_M_X64) || defined(__x86_64__) || defined(_M_IX86) || defined(__i386__)
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

// DR7 local/global enable bits are documented by Intel SDM Vol. 3, §18.2.2.
// A CONTEXT belongs to a suspended thread; the current running thread has no
// valid GetThreadContext snapshot.
#ifdef _WIN32
inline int hardware_breakpoint_count_from_context(const CONTEXT& context) noexcept {
    int count = 0;
    for (unsigned int index = 0; index < 4; ++index) {
        const DWORD_PTR enable_mask = static_cast<DWORD_PTR>(3u) << (index * 2u);
        if ((context.Dr7 & enable_mask) != 0) ++count;
    }
    return count;
}

inline int hardware_breakpoint_count_for_suspended_thread(HANDLE thread) noexcept {
    if (!thread || thread == GetCurrentThread()) return -1;
    CONTEXT context{};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    return GetThreadContext(thread, &context)
        ? hardware_breakpoint_count_from_context(context)
        : -1;
}
#endif

inline int hardware_breakpoint_count() noexcept {
    // GetThreadContext cannot obtain a valid context for the currently
    // executing thread. Returning -1 preserves "unknown", not "clean".
    return -1;
}

} // namespace stealth::detection

#endif // STEALTH_DETECTION_DEBUG_HPP
