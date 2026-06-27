#pragma once
#ifndef STEALTH_PE_PE_PARSER_HPP
#define STEALTH_PE_PE_PARSER_HPP

#ifdef _WIN32
#include "pe_layout.hpp"
#include "../detail/hashes.hpp"
#include <cstring>

namespace stealth {

inline void* get_proc(void* base, const char* name) noexcept {
    auto exp = get_export(base);
    if (!exp || !exp->NumberOfNames) return nullptr;
    auto names = reinterpret_cast<uint32_t*>(static_cast<char*>(base) + rva_in_image(base, exp->AddressOfNames));
    if (!rva_in_image(base, exp->AddressOfNames)) return nullptr;
    auto ordinals = reinterpret_cast<uint16_t*>(static_cast<char*>(base) + rva_in_image(base, exp->AddressOfNameOrdinals));
    if (!rva_in_image(base, exp->AddressOfNameOrdinals)) return nullptr;
    auto funcs = reinterpret_cast<uint32_t*>(static_cast<char*>(base) + rva_in_image(base, exp->AddressOfFunctions));
    if (!rva_in_image(base, exp->AddressOfFunctions)) return nullptr;
    for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
        if (!rva_in_image(base, names[i])) return nullptr;
        const char* n = reinterpret_cast<const char*>(base) + names[i];
        bool match = true; size_t j = 0;
        for (; n[j] && name[j]; ++j) {
            char a = n[j], b = name[j];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) { match = false; break; }
        }
        if (match && n[j] == '\0' && name[j] == '\0') {
            if (ordinals[i] >= exp->NumberOfFunctions) return nullptr;
            uint32_t f_rva = funcs[ordinals[i]];
            if (!rva_in_image(base, f_rva)) return nullptr;
            return static_cast<char*>(base) + f_rva;
        }
    }
    return nullptr;
}

inline void* get_proc_by_hash(void* base, uint64_t hash) noexcept {
    auto exp = get_export(base);
    if (!exp || !exp->NumberOfNames) return nullptr;
    if (!rva_in_image(base, exp->AddressOfNames)) return nullptr;
    if (!rva_in_image(base, exp->AddressOfNameOrdinals)) return nullptr;
    if (!rva_in_image(base, exp->AddressOfFunctions)) return nullptr;
    auto names = reinterpret_cast<uint32_t*>(static_cast<char*>(base) + exp->AddressOfNames);
    auto ordinals = reinterpret_cast<uint16_t*>(static_cast<char*>(base) + exp->AddressOfNameOrdinals);
    auto funcs = reinterpret_cast<uint32_t*>(static_cast<char*>(base) + exp->AddressOfFunctions);
    for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
        const char* n = reinterpret_cast<const char*>(base) + names[i];
        std::size_t bounded_len = 0;
        while (bounded_len < 256 && n[bounded_len] != '\0') ++bounded_len;
        uint64_t h = hashes::fnv(n, bounded_len);
        if (h == hash) {
            uint32_t f_rva = funcs[ordinals[i]];
            if (!rva_in_image(base, f_rva)) return nullptr;
            return static_cast<char*>(base) + f_rva;
        }
    }
    return nullptr;
}

template<typename T> T get_function(const char* module, const char* func) noexcept {
    void* base = nullptr;
    if (!get_module_base_ansi(module, &base)) return nullptr;
    return reinterpret_cast<T>(get_proc(base, func));
}
template<typename T> T get_function_by_hash(uint64_t module_hash, uint64_t func_hash) noexcept {
    void* base = nullptr;
    if (!get_module_base_by_hash(module_hash, &base)) return nullptr;
    return reinterpret_cast<T>(get_proc_by_hash(base, func_hash));
}
inline void* get_module_function(const char* module, const char* func) noexcept {
    void* base = nullptr;
    if (get_module_base_ansi(module, &base)) return get_proc(base, func);
    return nullptr;
}
inline void* get_module_function_by_hash(uint64_t module_hash, uint64_t func_hash) noexcept {
    void* base = nullptr;
    if (get_module_base_by_hash(module_hash, &base)) return get_proc_by_hash(base, func_hash);
    return nullptr;
}
inline void* get_nt_api(const char* name) noexcept {
    void* base = nullptr;
    if (get_module_base(L"ntdll.dll", &base)) return get_proc(base, name);
    return nullptr;
}
inline void* get_kernel32_api(const char* name) noexcept {
    void* base = nullptr;
    if (get_module_base(L"kernel32.dll", &base)) return get_proc(base, name);
    return nullptr;
}
inline void* get_user32_api(const char* name) noexcept {
    void* base = nullptr;
    if (get_module_base(L"user32.dll", &base)) return get_proc(base, name);
    return nullptr;
}

class module_loader {
public:
    module_loader(const char* name) noexcept : handle_(nullptr) { get_module_base_ansi(name, &handle_); }
    module_loader(uint64_t name_hash) noexcept : handle_(nullptr) { get_module_base_by_hash(name_hash, &handle_); }
    [[nodiscard]] void* get() const noexcept { return handle_; }
    [[nodiscard]] bool is_valid() const noexcept { return handle_ != nullptr; }
    bool operator!() const noexcept { return handle_ == nullptr; }
    template<typename T> [[nodiscard]] T get_function(const char* name) const noexcept { return reinterpret_cast<T>(get_proc(handle_, name)); }
    template<typename T> [[nodiscard]] T get_function_by_hash(uint64_t name_hash) const noexcept { return reinterpret_cast<T>(get_proc_by_hash(handle_, name_hash)); }
    template<typename T> [[nodiscard]] T get_proc_address(const char* name) const noexcept { return get_function<T>(name); }
    template<typename T> [[nodiscard]] T get_proc_address_by_hash(uint64_t name_hash) const noexcept { return get_function_by_hash<T>(name_hash); }
private:
    void* handle_;
};

template<typename FuncT>
class stealth_api {
public:
    using func_type = FuncT;
    stealth_api() noexcept : func_ptr_(nullptr) {}
    stealth_api(std::nullptr_t) noexcept : func_ptr_(nullptr) {}
    stealth_api(const char* module_name, const char* function_name) noexcept {
        void* base = nullptr;
        if (get_module_base_ansi(module_name, &base)) func_ptr_ = reinterpret_cast<FuncT*>(get_proc(base, function_name));
        else func_ptr_ = nullptr;
    }
    stealth_api(uint64_t module_hash, uint64_t function_hash) noexcept {
        void* base = nullptr;
        if (get_module_base_by_hash(module_hash, &base)) func_ptr_ = reinterpret_cast<FuncT*>(get_proc_by_hash(base, function_hash));
        else func_ptr_ = nullptr;
    }
    [[nodiscard]] FuncT* get() const noexcept { return func_ptr_; }
    [[nodiscard]] bool is_valid() const noexcept { return func_ptr_ != nullptr; }
    bool operator!() const noexcept { return func_ptr_ == nullptr; }
    void reset() noexcept { func_ptr_ = nullptr; }
    void reset(const char* module_name, const char* function_name) noexcept {
        void* base = nullptr;
        if (get_module_base_ansi(module_name, &base)) func_ptr_ = reinterpret_cast<FuncT*>(get_proc(base, function_name));
        else func_ptr_ = nullptr;
    }
    void reset(uint64_t module_hash, uint64_t function_hash) noexcept {
        void* base = nullptr;
        if (get_module_base_by_hash(module_hash, &base)) func_ptr_ = reinterpret_cast<FuncT*>(get_proc_by_hash(base, function_hash));
        else func_ptr_ = nullptr;
    }
private:
    FuncT* func_ptr_;
};

} // namespace stealth

#endif // _WIN32
#endif // STEALTH_PE_PE_PARSER_HPP
