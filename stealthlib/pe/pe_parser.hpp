#pragma once
#ifndef STEALTH_PE_PE_PARSER_HPP
#define STEALTH_PE_PE_PARSER_HPP

#ifdef _WIN32
#include "pe_layout.hpp"
#include "../detail/hashes.hpp"

#include <cstring>
#include <type_traits>

namespace stealth {
namespace detail {

inline bool export_name_equals(const char* candidate, const char* requested) noexcept {
    return candidate && requested && std::strcmp(candidate, requested) == 0;
}

inline bool rva_array_in_image(void* base, uint32_t rva, uint32_t count, size_t item_size) noexcept {
    if (item_size == 0 || count > (static_cast<uint32_t>(-1) / item_size)) return false;
    return rva_range_in_image(base, rva, static_cast<size_t>(count) * item_size);
}

inline bool bounded_image_string(void* base, uint32_t rva, const char** value) noexcept {
    if (!value || !rva_range_in_image(base, rva, 1)) return false;
    const char* text = reinterpret_cast<const char*>(static_cast<const uint8_t*>(base) + rva);
    const uint32_t image_size = get_image_size(base);
    for (uint32_t offset = rva; offset < image_size; ++offset) {
        if (text[offset - rva] == '\0') {
            *value = text;
            return true;
        }
    }
    return false;
}

inline bool bounded_region_string(
    void* base,
    uint32_t rva,
    const IMAGE_DATA_DIRECTORY& region,
    const char** value) noexcept {
    if (!value || rva < region.VirtualAddress || rva - region.VirtualAddress >= region.Size) {
        return false;
    }
    const char* text = reinterpret_cast<const char*>(static_cast<const uint8_t*>(base) + rva);
    const uint32_t remaining = region.Size - (rva - region.VirtualAddress);
    for (uint32_t index = 0; index < remaining; ++index) {
        if (text[index] == '\0') {
            *value = text;
            return true;
        }
    }
    return false;
}

inline bool get_export_tables(
    void* base,
    IMAGE_EXPORT_DIRECTORY** directory,
    IMAGE_DATA_DIRECTORY* export_data,
    uint32_t** functions,
    uint32_t** names,
    uint16_t** ordinals) noexcept {
    if (!directory || !export_data || !functions || !names || !ordinals) return false;
    *directory = get_export(base);
    if (!*directory || !get_data_directory(base, IMAGE_DIRECTORY_ENTRY_EXPORT, export_data)) {
        return false;
    }
    if (!rva_array_in_image(base, (*directory)->AddressOfFunctions,
                            (*directory)->NumberOfFunctions, sizeof(**functions)) ||
        !rva_array_in_image(base, (*directory)->AddressOfNames,
                            (*directory)->NumberOfNames, sizeof(**names)) ||
        !rva_array_in_image(base, (*directory)->AddressOfNameOrdinals,
                            (*directory)->NumberOfNames, sizeof(**ordinals))) {
        return false;
    }
    *functions = reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(base) + (*directory)->AddressOfFunctions);
    *names = reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(base) + (*directory)->AddressOfNames);
    *ordinals = reinterpret_cast<uint16_t*>(static_cast<uint8_t*>(base) + (*directory)->AddressOfNameOrdinals);
    return true;
}

inline void* get_proc_impl(void* base, const char* name, unsigned depth) noexcept;
inline void* get_proc_by_ordinal_impl(void* base, uint16_t ordinal, unsigned depth) noexcept;

inline bool copy_forwarder_module_name(
    const char* forwarder,
    const char* separator,
    char module[MAX_PATH]) noexcept {
    const size_t length = static_cast<size_t>(separator - forwarder);
    if (length == 0 || length + 5 >= MAX_PATH) return false;
    for (size_t i = 0; i < length; ++i) module[i] = forwarder[i];

    const bool has_dll_suffix = length >= 4 && module[length - 4] == '.' &&
        (module[length - 3] == 'd' || module[length - 3] == 'D') &&
        (module[length - 2] == 'l' || module[length - 2] == 'L') &&
        (module[length - 1] == 'l' || module[length - 1] == 'L');
    if (!has_dll_suffix) {
        module[length] = '.';
        module[length + 1] = 'd';
        module[length + 2] = 'l';
        module[length + 3] = 'l';
    }
    return true;
}

inline bool parse_forwarded_ordinal(const char* text, uint16_t* ordinal) noexcept {
    if (!text || !ordinal || text[0] != '#') return false;
    uint32_t value = 0;
    bool has_digit = false;
    for (const char* digit = text + 1; *digit != '\0'; ++digit) {
        if (*digit < '0' || *digit > '9' || value > 6553u) return false;
        has_digit = true;
        value = value * 10u + static_cast<uint32_t>(*digit - '0');
    }
    if (!has_digit || value > 0xFFFFu) return false;
    *ordinal = static_cast<uint16_t>(value);
    return true;
}

inline void* resolve_forwarder(
    void* base,
    uint32_t forwarder_rva,
    const IMAGE_DATA_DIRECTORY& export_data,
    unsigned depth) noexcept {
    if (depth >= 8) return nullptr;

    const char* forwarder = nullptr;
    if (!bounded_region_string(base, forwarder_rva, export_data, &forwarder)) return nullptr;
    const char* separator = forwarder;
    while (*separator != '\0' && *separator != '.') ++separator;
    if (*separator != '.' || separator == forwarder || separator[1] == '\0') return nullptr;

    char module[MAX_PATH] = {};
    if (!copy_forwarder_module_name(forwarder, separator, module)) return nullptr;

    void* target_module = nullptr;
    if (!get_module_base_ansi(module, &target_module)) return nullptr;

    const char* target = separator + 1;
    uint16_t ordinal = 0;
    return target[0] == '#'
        ? (parse_forwarded_ordinal(target, &ordinal)
            ? get_proc_by_ordinal_impl(target_module, ordinal, depth + 1)
            : nullptr)
        : get_proc_impl(target_module, target, depth + 1);
}

inline void* resolve_export_rva(
    void* base,
    uint32_t function_rva,
    const IMAGE_DATA_DIRECTORY& export_data,
    unsigned depth) noexcept {
    if (!rva_range_in_image(base, function_rva, 1)) return nullptr;
    if (function_rva >= export_data.VirtualAddress &&
        function_rva - export_data.VirtualAddress < export_data.Size) {
        return resolve_forwarder(base, function_rva, export_data, depth);
    }
    return static_cast<uint8_t*>(base) + function_rva;
}

inline void* get_proc_impl(void* base, const char* name, unsigned depth) noexcept {
    if (!base || !name || depth >= 8) return nullptr;

    IMAGE_EXPORT_DIRECTORY* directory = nullptr;
    IMAGE_DATA_DIRECTORY export_data{};
    uint32_t* functions = nullptr;
    uint32_t* names = nullptr;
    uint16_t* ordinals = nullptr;
    if (!get_export_tables(base, &directory, &export_data, &functions, &names, &ordinals)) return nullptr;

    for (uint32_t index = 0; index < directory->NumberOfNames; ++index) {
        const char* export_name = nullptr;
        if (!bounded_image_string(base, names[index], &export_name)) return nullptr;
        if (!export_name_equals(export_name, name)) continue;

        const uint16_t ordinal_index = ordinals[index];
        return ordinal_index < directory->NumberOfFunctions
            ? resolve_export_rva(base, functions[ordinal_index], export_data, depth)
            : nullptr;
    }
    return nullptr;
}

inline void* get_proc_by_ordinal_impl(void* base, uint16_t ordinal, unsigned depth) noexcept {
    if (!base || depth >= 8) return nullptr;

    IMAGE_EXPORT_DIRECTORY* directory = nullptr;
    IMAGE_DATA_DIRECTORY export_data{};
    uint32_t* functions = nullptr;
    uint32_t* names = nullptr;
    uint16_t* ordinals = nullptr;
    if (!get_export_tables(base, &directory, &export_data, &functions, &names, &ordinals) ||
        ordinal < directory->Base) {
        return nullptr;
    }

    const uint32_t ordinal_index = static_cast<uint32_t>(ordinal - directory->Base);
    return ordinal_index < directory->NumberOfFunctions
        ? resolve_export_rva(base, functions[ordinal_index], export_data, depth)
        : nullptr;
}

template<typename T>
using function_result_t = std::conditional_t<std::is_function_v<T>, std::add_pointer_t<T>, T>;

} // namespace detail

inline void* get_proc(void* base, const char* name) noexcept {
    return detail::get_proc_impl(base, name, 0);
}

inline void* get_proc_by_hash(void* base, uint64_t hash) noexcept {
    if (!base) return nullptr;

    IMAGE_EXPORT_DIRECTORY* directory = nullptr;
    IMAGE_DATA_DIRECTORY export_data{};
    uint32_t* functions = nullptr;
    uint32_t* names = nullptr;
    uint16_t* ordinals = nullptr;
    if (!detail::get_export_tables(base, &directory, &export_data, &functions, &names, &ordinals)) {
        return nullptr;
    }

    for (uint32_t index = 0; index < directory->NumberOfNames; ++index) {
        const char* export_name = nullptr;
        if (!detail::bounded_image_string(base, names[index], &export_name)) return nullptr;
        if (hashes::fnv(export_name, std::strlen(export_name)) == hash) {
            return detail::get_proc_impl(base, export_name, 0);
        }
    }
    return nullptr;
}

template<typename T>
inline detail::function_result_t<T> get_function(const char* module, const char* function) noexcept {
    void* base = nullptr;
    return get_module_base_ansi(module, &base)
        ? reinterpret_cast<detail::function_result_t<T>>(get_proc(base, function))
        : nullptr;
}

template<typename T>
inline detail::function_result_t<T> get_function_by_hash(uint64_t module_hash, uint64_t function_hash) noexcept {
    void* base = nullptr;
    return get_module_base_by_hash(module_hash, &base)
        ? reinterpret_cast<detail::function_result_t<T>>(get_proc_by_hash(base, function_hash))
        : nullptr;
}

inline void* get_module_function(const char* module, const char* function) noexcept {
    void* base = nullptr;
    return get_module_base_ansi(module, &base) ? get_proc(base, function) : nullptr;
}

inline void* get_module_function_by_hash(uint64_t module_hash, uint64_t function_hash) noexcept {
    void* base = nullptr;
    return get_module_base_by_hash(module_hash, &base) ? get_proc_by_hash(base, function_hash) : nullptr;
}

inline void* get_nt_api(const char* name) noexcept { return get_module_function("ntdll.dll", name); }
inline void* get_kernel32_api(const char* name) noexcept { return get_module_function("kernel32.dll", name); }
inline void* get_user32_api(const char* name) noexcept { return get_module_function("user32.dll", name); }

class module_loader {
public:
    explicit module_loader(const char* name) noexcept : handle_(nullptr) { get_module_base_ansi(name, &handle_); }
    explicit module_loader(uint64_t name_hash) noexcept : handle_(nullptr) { get_module_base_by_hash(name_hash, &handle_); }

    [[nodiscard]] void* get() const noexcept { return handle_; }
    [[nodiscard]] bool is_valid() const noexcept { return handle_ != nullptr; }
    bool operator!() const noexcept { return handle_ == nullptr; }

    template<typename T>
    [[nodiscard]] detail::function_result_t<T> get_function(const char* name) const noexcept {
        return reinterpret_cast<detail::function_result_t<T>>(get_proc(handle_, name));
    }

    template<typename T>
    [[nodiscard]] detail::function_result_t<T> get_function_by_hash(uint64_t name_hash) const noexcept {
        return reinterpret_cast<detail::function_result_t<T>>(get_proc_by_hash(handle_, name_hash));
    }

    template<typename T>
    [[nodiscard]] detail::function_result_t<T> get_proc_address(const char* name) const noexcept {
        return get_function<T>(name);
    }

    template<typename T>
    [[nodiscard]] detail::function_result_t<T> get_proc_address_by_hash(uint64_t name_hash) const noexcept {
        return get_function_by_hash<T>(name_hash);
    }

private:
    void* handle_;
};

template<typename FuncT>
class stealth_api {
    static_assert(std::is_function_v<FuncT>, "stealth_api expects a function type, not a function pointer type");

public:
    using func_type = FuncT;

    stealth_api() noexcept : func_ptr_(nullptr) {}
    stealth_api(std::nullptr_t) noexcept : func_ptr_(nullptr) {}
    stealth_api(const char* module_name, const char* function_name) noexcept
        : func_ptr_(get_function<FuncT>(module_name, function_name)) {}
    stealth_api(uint64_t module_hash, uint64_t function_hash) noexcept
        : func_ptr_(get_function_by_hash<FuncT>(module_hash, function_hash)) {}

    [[nodiscard]] FuncT* get() const noexcept { return func_ptr_; }
    [[nodiscard]] bool is_valid() const noexcept { return func_ptr_ != nullptr; }
    bool operator!() const noexcept { return func_ptr_ == nullptr; }
    void reset() noexcept { func_ptr_ = nullptr; }
    void reset(const char* module_name, const char* function_name) noexcept {
        func_ptr_ = get_function<FuncT>(module_name, function_name);
    }
    void reset(uint64_t module_hash, uint64_t function_hash) noexcept {
        func_ptr_ = get_function_by_hash<FuncT>(module_hash, function_hash);
    }

private:
    FuncT* func_ptr_;
};

} // namespace stealth

#endif // _WIN32
#endif // STEALTH_PE_PE_PARSER_HPP
