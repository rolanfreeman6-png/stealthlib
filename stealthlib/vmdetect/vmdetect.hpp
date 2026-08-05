#pragma once
#ifndef STEALTH_VMDETECT_VMDETECT_HPP
#define STEALTH_VMDETECT_VMDETECT_HPP

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#if defined(_MSC_VER)
#include <intrin.h>
#elif (defined(__GNUC__) || defined(__clang__)) && (defined(__x86_64__) || defined(__i386__))
#include <cpuid.h>
#endif
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/statvfs.h>
#endif

namespace stealth::detection::vmdetect {

inline char ascii_lower(char value) noexcept {
    return value >= 'A' && value <= 'Z' ? static_cast<char>(value + ('a' - 'A')) : value;
}

inline bool contains_vm_vendor_token(const char* value) noexcept {
    if (!value) return false;
    static constexpr const char* patterns[] = {
        "vmware", "virtualbox", "qemu", "innotek", "xen", "hyper-v", "microsoft corporation"
    };
    for (const char* pattern : patterns) {
        for (const char* candidate = value; *candidate; ++candidate) {
            const char* left = candidate;
            const char* right = pattern;
            while (*left && *right && ascii_lower(*left) == *right) {
                ++left;
                ++right;
            }
            if (*right == '\0') return true;
        }
    }
    return false;
}

inline bool cpuid_hypervisor_present() noexcept {
#if defined(_M_X64) || defined(__x86_64__) || defined(_M_IX86) || defined(__i386__)
    uint32_t a = 0, b = 0, c = 0, d = 0;
    const uint32_t leaf = 1;
#if defined(_MSC_VER)
    int regs[4]; __cpuid(regs, static_cast<int>(leaf));
    a = static_cast<uint32_t>(regs[0]); b = static_cast<uint32_t>(regs[1]);
    c = static_cast<uint32_t>(regs[2]); d = static_cast<uint32_t>(regs[3]);
#elif defined(__GNUC__) || defined(__clang__)
    if (!__get_cpuid(leaf, &a, &b, &c, &d)) return false;
#else
    return false;
#endif
    (void)a; (void)b; (void)d;
    return (c & (1u << 31)) != 0;
#else
    return false;
#endif
}

inline bool registry_or_dmi_vm_vendor() noexcept {
#ifdef _WIN32
    HKEY key{};
    LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &key);
    if (rc != ERROR_SUCCESS) return false;
    char buf[256] = {};
    DWORD sz = 0;
    bool hit = false;
    for (char const* valname : { "SystemManufacturer", "SystemProductName", "BIOSVendor" }) {
        DWORD type = 0;
        sz = sizeof(buf) - 1;
        std::memset(buf, 0, sizeof(buf));
        if (RegQueryValueExA(key, valname, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &sz) == ERROR_SUCCESS &&
            (type == REG_SZ || type == REG_EXPAND_SZ)) {
            buf[sz < sizeof(buf) ? sz : sizeof(buf) - 1] = '\0';
            if (contains_vm_vendor_token(buf)) { hit = true; break; }
        }
    }
    RegCloseKey(key);
    return hit;
#else
    auto read_first_line = [](char const* path, char* out, std::size_t cap) -> bool {
        if (!path || !out || cap < 2 || path[0] != '/' || std::strstr(path, "..") != nullptr) return false;
        std::FILE* f = std::fopen(path, "r");
        if (!f) return false;
        if (!std::fgets(out, static_cast<int>(cap), f)) { std::fclose(f); return false; }
        std::fclose(f); return true;
    };
    char buf[256] = {};
    if (read_first_line("/sys/class/dmi/id/sys_vendor", buf, sizeof(buf)) && contains_vm_vendor_token(buf)) return true;
    std::memset(buf, 0, sizeof(buf));
    if (read_first_line("/sys/class/dmi/id/product_name", buf, sizeof(buf)) && contains_vm_vendor_token(buf)) return true;
    std::memset(buf, 0, sizeof(buf));
    if (read_first_line("/sys/class/dmi/id/bios_vendor", buf, sizeof(buf)) && contains_vm_vendor_token(buf)) return true;
    return false;
#endif
}

inline bool small_disk_heuristic_gb(double min_gb) noexcept {
#ifdef _WIN32
    ULARGE_INTEGER total_bytes{};
    if (!GetDiskFreeSpaceExA("C:\\", nullptr, &total_bytes, nullptr)) return false;
    constexpr double GB = 1024.0 * 1024.0 * 1024.0;
    return static_cast<double>(total_bytes.QuadPart) / GB < min_gb;
#else
    struct statvfs v{};
    if (statvfs("/", &v) != 0) return false;
    constexpr double GB = 1024.0 * 1024.0 * 1024.0;
    double total_gb = static_cast<double>(v.f_blocks) * static_cast<double>(v.f_frsize) / GB;
    return total_gb < min_gb;
#endif
}

struct scan_result {
    bool cpuid_hypervisor_bit; bool vendor_strings; bool small_disk;
    double reported_disk_gb; int vm_confidence;
    [[nodiscard]] bool any() const noexcept { return vm_confidence > 0; }
};

inline scan_result scan() noexcept {
    scan_result r{};
    r.cpuid_hypervisor_bit = cpuid_hypervisor_present();
    r.vendor_strings = registry_or_dmi_vm_vendor();
    r.small_disk = small_disk_heuristic_gb(80.0);
    r.reported_disk_gb = [&]() -> double {
        double d = 0.0;
#ifdef _WIN32
        ULARGE_INTEGER total{};
        if (GetDiskFreeSpaceExA("C:\\", nullptr, &total, nullptr)) { constexpr double GB = 1024.0*1024.0*1024.0; d = static_cast<double>(total.QuadPart)/GB; }
#else
        struct statvfs v{};
        if (statvfs("/", &v) == 0) { constexpr double GB = 1024.0*1024.0*1024.0; d = static_cast<double>(v.f_blocks)*static_cast<double>(v.f_frsize)/GB; }
#endif
        return d;
    }();
    r.vm_confidence = (r.cpuid_hypervisor_bit?1:0) + (r.vendor_strings?1:0) + (r.small_disk?1:0);
    return r;
}

} // namespace stealth::detection::vmdetect

#endif // STEALTH_VMDETECT_VMDETECT_HPP
