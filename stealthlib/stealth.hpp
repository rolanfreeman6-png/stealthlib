#pragma once
#ifndef STEALTH_HPP
#define STEALTH_HPP

#define STEALTH_VERSION_STRING "1.0.0"

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <array>
#include <optional>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace stealth {

constexpr const char* version() noexcept { return STEALTH_VERSION_STRING; }

namespace detail {
    constexpr uint64_t key_seed = 0x5EED5EED5EED5EEDULL;
    
    constexpr uint64_t mix(uint64_t v) noexcept { 
        v ^= v >> 33; 
        v *= 0xFF51AFD7ED558CCDuLL; 
        v ^= v >> 33; 
        v *= 0xC4CEB9FC1CE12D6DuLL; 
        v ^= v >> 33; 
        return v; 
    }
    
    constexpr uint8_t derive_byte(uint64_t index, size_t pos) noexcept { 
        return static_cast<uint8_t>((mix(key_seed + index * 0x9E3779B97F4A7C15ULL) >> (pos * 8)) & 0xFF); 
    }
    
    template<size_t N, size_t Idx>
    struct encrypted_string_impl {
        mutable std::array<char, N> encrypted{};
        mutable char buffer[N + 1];
        mutable bool decrypted = false;
        
        constexpr encrypted_string_impl(const char* src) noexcept {
            for (size_t i = 0; i < N; ++i) {
                encrypted[i] = static_cast<char>(static_cast<uint8_t>(src[i]) ^ derive_byte(Idx, i % 8));
            }
        }
        
        const char* decrypt() const noexcept {
            if (!decrypted) {
                for (size_t i = 0; i < N; ++i) {
                    buffer[i] = static_cast<char>(static_cast<uint8_t>(encrypted[i]) ^ derive_byte(Idx, i % 8));
                }
                buffer[N] = '\0';
                decrypted = true;
            }
            return buffer;
        }
    };
    
    template<size_t N, size_t Idx>
    struct encrypted_wstring_impl {
        mutable std::array<wchar_t, N> encrypted{};
        mutable wchar_t buffer[N + 1];
        mutable bool decrypted = false;
        
        constexpr encrypted_wstring_impl(const wchar_t* src) noexcept {
            for (size_t i = 0; i < N; ++i) {
                uint32_t ch = static_cast<uint32_t>(src[i]);
                ch ^= derive_byte(Idx, i % 4);
                encrypted[i] = static_cast<wchar_t>(ch);
            }
        }
        
        const wchar_t* decrypt() const noexcept {
            if (!decrypted) {
                for (size_t i = 0; i < N; ++i) {
                    uint32_t ch = static_cast<uint32_t>(encrypted[i]);
                    ch ^= derive_byte(Idx, i % 4);
                    buffer[i] = static_cast<wchar_t>(ch);
                }
                buffer[N] = L'\0';
                decrypted = true;
            }
            return buffer;
        }
    };
    
    template<size_t N, size_t Idx>
struct stealth_encrypted_char {
    char buffer[N + 1];
    
    constexpr stealth_encrypted_char(const char* src) noexcept {
        for (size_t i = 0; i < N; ++i) {
            buffer[i] = static_cast<char>(static_cast<uint8_t>(src[i]) ^ detail::derive_byte(Idx, i % 8));
        }
        buffer[N] = '\0';
    }
    
    constexpr operator const char*() const noexcept { return buffer; }
};

template<size_t N, size_t Idx>
struct stealth_encrypted_wchar {
    wchar_t buffer[N + 1];
    
    constexpr stealth_encrypted_wchar(const wchar_t* src) noexcept {
        for (size_t i = 0; i < N; ++i) {
            uint32_t ch = static_cast<uint32_t>(src[i]);
            ch ^= detail::derive_byte(Idx, i % 4);
            buffer[i] = static_cast<wchar_t>(ch);
        }
        buffer[N] = L'\0';
    }
    
    constexpr operator const wchar_t*() const noexcept { return buffer; }
};
}

template<size_t MaxSize = 256>
class secure_string {
public:
    using char_type = char;
    
    secure_string() noexcept : length_(0) {
        std::memset(data_, 0, MaxSize);
    }
    
    explicit secure_string(const char* str) noexcept {
        length_ = 0;
        while (str[length_] != '\0' && length_ < MaxSize - 1) {
            data_[length_] = str[length_];
            ++length_;
        }
        data_[length_] = '\0';
    }
    
    secure_string(const secure_string&) = delete;
    secure_string& operator=(const secure_string&) = delete;
    
    ~secure_string() noexcept {
        std::memset(data_, 0, MaxSize);
        length_ = 0;
    }
    
    [[nodiscard]] char* data() noexcept { return data_; }
    [[nodiscard]] const char* data() const noexcept { return data_; }
    [[nodiscard]] const char* c_str() const noexcept { return data_; }
    [[nodiscard]] size_t length() const noexcept { return length_; }
    [[nodiscard]] size_t size() const noexcept { return length_; }
    
    void clear() noexcept {
        std::memset(data_, 0, MaxSize);
        length_ = 0;
    }
    
private:
    char data_[MaxSize];
    size_t length_;
};

namespace encoding {

inline std::string base64_encode(const void* data, size_t len) noexcept;
inline std::string base64_encode(const std::string_view& str) noexcept {
    return base64_encode(str.data(), str.size());
}
inline std::optional<std::string> base64_decode(const std::string_view& str) noexcept;
inline std::string hex_encode(const void* data, size_t len) noexcept;
inline std::string hex_encode(const std::string_view& str) noexcept {
    return hex_encode(str.data(), str.size());
}
inline std::optional<std::vector<uint8_t>> hex_decode(const std::string_view& str) noexcept;

inline void rot13_encode(void* dst, const void* src, size_t len) noexcept {
    const uint8_t* s = static_cast<const uint8_t*>(src);
    uint8_t* d = static_cast<uint8_t*>(dst);
    for (size_t i = 0; i < len; ++i) {
        uint8_t ch = s[i];
        if (ch >= 'a' && ch <= 'z') ch = static_cast<uint8_t>((ch - 'a' + 13) % 26 + 'a');
        else if (ch >= 'A' && ch <= 'Z') ch = static_cast<uint8_t>((ch - 'A' + 13) % 26 + 'A');
        d[i] = ch;
    }
}

inline void rot13_decode(void* dst, const void* src, size_t len) noexcept {
    rot13_encode(dst, src, len);
}

template<size_t KeySize>
struct xor_key {
    std::array<uint8_t, KeySize> data{};
    size_t length = 0;
    
    xor_key() noexcept = default;
    
    xor_key(const uint8_t* k, size_t len) noexcept : length(len < KeySize ? len : KeySize) {
        for (size_t i = 0; i < length; ++i) data[i] = k[i];
    }
    
    constexpr xor_key(const char* str) noexcept : length(0) {
        size_t i = 0;
        while (str[i] && i < KeySize) {
            data[i] = static_cast<uint8_t>(str[i]);
            ++length;
            ++i;
        }
    }
    
    [[nodiscard]] uint8_t operator[](size_t idx) const noexcept { return data[idx % length]; }
};

template<size_t KeySize>
inline void xor_crypt(void* data, size_t len, const xor_key<KeySize>& key) noexcept {
    uint8_t* d = static_cast<uint8_t*>(data);
    for (size_t i = 0; i < len; ++i) d[i] ^= key[i];
}

template<size_t KeySize>
inline void xor_encode(void* data, size_t len, const xor_key<KeySize>& key) noexcept {
    xor_crypt(data, len, key);
}

template<size_t KeySize>
inline void xor_decode(void* data, size_t len, const xor_key<KeySize>& key) noexcept {
    xor_crypt(data, len, key);
}

namespace detail_base64 {
static const char b64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
inline char encode_b64_byte(unsigned char v) noexcept { return b64_alphabet[v & 0x3F]; }
}

inline std::string base64_encode(const void* data, size_t len) noexcept {
    const unsigned char* src = static_cast<const unsigned char*>(data);
    std::string result;
    result.reserve((len + 2) / 3 * 4);
    size_t i = 0;
    while (i + 2 < len) {
        unsigned int v = (static_cast<unsigned int>(src[i]) << 16) | 
                        (static_cast<unsigned int>(src[i + 1]) << 8) | 
                        static_cast<unsigned int>(src[i + 2]);
        result += detail_base64::encode_b64_byte(static_cast<unsigned char>(v >> 18));
        result += detail_base64::encode_b64_byte(static_cast<unsigned char>(v >> 12));
        result += detail_base64::encode_b64_byte(static_cast<unsigned char>(v >> 6));
        result += detail_base64::encode_b64_byte(static_cast<unsigned char>(v));
        i += 3;
    }
    if (i + 1 < len) {
        unsigned int v = (static_cast<unsigned int>(src[i]) << 16) | 
                        (static_cast<unsigned int>(src[i + 1]) << 8);
        result += detail_base64::encode_b64_byte(static_cast<unsigned char>(v >> 18));
        result += detail_base64::encode_b64_byte(static_cast<unsigned char>(v >> 12));
        result += detail_base64::encode_b64_byte(static_cast<unsigned char>(v >> 6));
        result += '=';
    } else if (i < len) {
        unsigned int v = static_cast<unsigned int>(src[i]) << 16;
        result += detail_base64::encode_b64_byte(static_cast<unsigned char>(v >> 18));
        result += detail_base64::encode_b64_byte(static_cast<unsigned char>(v >> 12));
        result += "==";
    }
    return result;
}

inline std::optional<std::string> base64_decode(const std::string_view& str) noexcept {
    if (str.size() % 4 != 0) return std::nullopt;
    static const int8_t b64_decode[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    std::string result;
    result.reserve(str.size() * 3 / 4);
    const char* s = str.data();
    size_t len_str = str.size();
    for (size_t i = 0; i < len_str; i += 4) {
        int8_t vals[4] = {-1, -1, -1, -1};
        for (int j = 0; j < 4; ++j) {
            if (s[i + j] != '=') {
                unsigned char c = static_cast<unsigned char>(s[i + j]);
                vals[j] = b64_decode[c];
                if (vals[j] < 0) return std::nullopt;
            }
        }
        if (vals[0] < 0 || vals[1] < 0) return std::nullopt;
        result += static_cast<char>((vals[0] << 2) | (vals[1] >> 4));
        if (vals[2] >= 0 && s[i + 2] != '=') result += static_cast<char>((vals[1] << 4) | (vals[2] >> 2));
        if (vals[3] >= 0 && s[i + 3] != '=') result += static_cast<char>((vals[2] << 6) | vals[3]);
    }
    return result;
}

inline std::string hex_encode(const void* data, size_t len) noexcept {
    static const char hex_chars[] = "0123456789ABCDEF";
    const unsigned char* src = static_cast<const unsigned char*>(data);
    std::string result(len * 2, '\0');
    for (size_t i = 0; i < len; ++i) {
        result[i * 2] = hex_chars[src[i] >> 4];
        result[i * 2 + 1] = hex_chars[src[i] & 0x0F];
    }
    return result;
}

inline std::optional<std::vector<uint8_t>> hex_decode(const std::string_view& str) noexcept {
    if (str.size() % 2 != 0) return std::nullopt;
    std::vector<uint8_t> result(str.size() / 2);
    const char* s = str.data();
    for (size_t i = 0; i < str.size() / 2; ++i) {
        char h = s[i * 2], l = s[i * 2 + 1];
        int hi = 0, lo = 0;
        if (h >= '0' && h <= '9') hi = h - '0';
        else if (h >= 'A' && h <= 'F') hi = h - 'A' + 10;
        else if (h >= 'a' && h <= 'f') hi = h - 'a' + 10;
        else return std::nullopt;
        if (l >= '0' && l <= '9') lo = l - '0';
        else if (l >= 'A' && l <= 'F') lo = l - 'A' + 10;
        else if (l >= 'a' && l <= 'f') lo = l - 'a' + 10;
        else return std::nullopt;
        result[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return result;
}

}

namespace memory {

inline void secure_zero(void* ptr, size_t len) noexcept {
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) *p++ = 0;
}

inline bool compare_constant_time(const void* a, const void* b, size_t len) noexcept {
    const uint8_t* A = static_cast<const uint8_t*>(a);
    const uint8_t* B = static_cast<const uint8_t*>(b);
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) diff |= A[i] ^ B[i];
    return diff == 0;
}

}

namespace detection {

inline bool is_debugger_present() noexcept {
#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
    auto peb = reinterpret_cast<void*>(__readgsqword(0x60));
    if (!peb) return false;
    return *static_cast<uint8_t*>(static_cast<void*>(static_cast<char*>(peb) + 2)) != 0;
#elif defined(_WIN32) && defined(_M_IX86)
    auto peb = reinterpret_cast<void*>(__readfsdword(0x30));
    if (!peb) return false;
    return *static_cast<uint8_t*>(static_cast<void*>(static_cast<char*>(peb) + 2)) != 0;
#else
    return false;
#endif
}

}

#ifdef _WIN32

#if defined(_M_X64) || defined(__x86_64__)
inline void* get_peb_ptr() noexcept { return reinterpret_cast<void*>(__readgsqword(0x60)); }
#elif defined(_M_IX86)
inline void* get_peb_ptr() noexcept { return reinterpret_cast<void*>(__readfsdword(0x30)); }
#else
inline void* get_peb_ptr() noexcept { return nullptr; }
#endif

struct UNICODE_STRING_NT { uint16_t Length; uint16_t MaximumLength; wchar_t* Buffer; };
struct LIST_ENTRY_NT { void* Flink; void* Blink; };
struct LDR_ENTRY_NT { LIST_ENTRY_NT InLoadOrderLinks; void* DllBase; uint32_t SizeOfImage; UNICODE_STRING_NT BaseDllName; };
struct PEB_LDR_NT { uint32_t Length; uint8_t Initialized; void* SsHandle; LIST_ENTRY_NT InLoadOrderModuleList; };
struct PEB_STRUCT_NT { uint8_t InheritedAddressSpace; uint8_t ReadImageFileExecOptions; uint8_t BeingDebugged; uint8_t BitField; void* Mutant; void* ImageBaseAddress; PEB_LDR_NT* Ldr; };

inline bool get_module_base(const wchar_t* name, void** out) noexcept {
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
    while (name[i] && i < 259) {
        wide[i] = static_cast<wchar_t>(static_cast<unsigned char>(name[i]));
        ++i;
    }
    return get_module_base(wide, out);
}

struct DOS_HEADER_NT { uint16_t e_magic; int32_t e_lfanew; };
struct NT_HEADERS_NT { uint32_t Signature; uint8_t Padding[4]; uint16_t Machine; uint16_t NumberOfSections; uint32_t TimeDateStamp; uint32_t PointerToSymbolTable; uint32_t NumberOfSymbols; uint16_t SizeOfOptionalHeader; uint16_t Characteristics; uint16_t Magic; uint8_t MajorLinkerVersion; uint8_t MinorLinkerVersion; uint32_t SizeOfCode; uint32_t SizeOfInitializedData; uint32_t SizeOfUninitializedData; uint32_t AddressOfEntryPoint; uint32_t BaseOfCode; uint64_t ImageBase; uint32_t SectionAlignment; uint32_t FileAlignment; uint16_t MajorOperatingSystemVersion; uint16_t MinorOperatingSystemVersion; uint16_t MajorImageVersion; uint16_t MinorImageVersion; uint16_t MajorSubsystemVersion; uint16_t MinorSubsystemVersion; uint32_t Win32VersionValue; uint32_t SizeOfImage; uint32_t SizeOfHeaders; uint32_t CheckSum; uint16_t Subsystem; uint16_t DllCharacteristics; uint64_t SizeOfStackReserve; uint64_t SizeOfStackCommit; uint64_t SizeOfHeapReserve; uint64_t SizeOfHeapCommit; uint32_t LoaderFlags; uint32_t NumberOfRvaAndSizes; uint32_t DataDirectory[32]; };
struct EXPORT_DIRECTORY_NT { uint32_t Characteristics; uint32_t TimeDateStamp; uint16_t MajorVersion; uint16_t MinorVersion; uint32_t Name; uint32_t Base; uint32_t NumberOfFunctions; uint32_t NumberOfNames; uint32_t AddressOfFunctions; uint32_t AddressOfNames; uint32_t AddressOfNameOrdinals; };

inline DOS_HEADER_NT* get_dos(void* base) noexcept { return static_cast<DOS_HEADER_NT*>(base); }
inline NT_HEADERS_NT* get_nt(void* base) noexcept {
    auto dos = get_dos(base);
    if (!dos || dos->e_magic != 0x5A4D) return nullptr;
    return reinterpret_cast<NT_HEADERS_NT*>(static_cast<char*>(base) + dos->e_lfanew);
}
inline EXPORT_DIRECTORY_NT* get_export(void* base) noexcept {
    auto nt = get_nt(base);
    if (!nt || nt->Signature != 0x4550) return nullptr;
    uint32_t rva = nt->DataDirectory[0];
    if (!rva) return nullptr;
    return reinterpret_cast<EXPORT_DIRECTORY_NT*>(static_cast<char*>(base) + rva);
}
inline void* get_proc(void* base, const char* name) noexcept {
    auto exp = get_export(base);
    if (!exp || !exp->NumberOfNames) return nullptr;
    auto names = reinterpret_cast<uint32_t*>(static_cast<char*>(base) + exp->AddressOfNames);
    auto ordinals = reinterpret_cast<uint16_t*>(static_cast<char*>(base) + exp->AddressOfNameOrdinals);
    auto funcs = reinterpret_cast<uint32_t*>(static_cast<char*>(base) + exp->AddressOfFunctions);
    for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
        const char* n = reinterpret_cast<const char*>(base) + names[i];
        bool match = true;
        size_t j = 0;
        for (; n[j] && name[j]; ++j) {
            char a = n[j], b = name[j];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) { match = false; break; }
        }
        if (match && n[j] == '\0' && name[j] == '\0') {
            return static_cast<char*>(base) + funcs[ordinals[i]];
        }
    }
    return nullptr;
}

template<typename T>
T get_function(const char* module, const char* func) noexcept {
    void* base = nullptr;
    if (get_module_base_ansi(module, &base)) {
        return reinterpret_cast<T>(get_proc(base, func));
    }
    return nullptr;
}

inline void* get_module_function(const char* module, const char* func) noexcept {
    void* base = nullptr;
    if (get_module_base_ansi(module, &base)) {
        return get_proc(base, func);
    }
    return nullptr;
}

inline void* get_nt_api(const char* name) noexcept {
    void* base = nullptr;
    if (get_module_base(L"ntdll.dll", &base)) {
        return get_proc(base, name);
    }
    return nullptr;
}

inline void* get_kernel32_api(const char* name) noexcept {
    void* base = nullptr;
    if (get_module_base(L"kernel32.dll", &base)) {
        return get_proc(base, name);
    }
    return nullptr;
}

inline void* get_user32_api(const char* name) noexcept {
    void* base = nullptr;
    if (get_module_base(L"user32.dll", &base)) {
        return get_proc(base, name);
    }
    return nullptr;
}

class module_loader {
public:
    module_loader(const char* name) noexcept : handle_(nullptr) {
        get_module_base_ansi(name, &handle_);
    }
    [[nodiscard]] void* get() const noexcept { return handle_; }
    [[nodiscard]] bool is_valid() const noexcept { return handle_ != nullptr; }
    bool operator!() const noexcept { return handle_ == nullptr; }
    template<typename T>
    [[nodiscard]] T get_function(const char* name) const noexcept {
        return reinterpret_cast<T>(get_proc(handle_, name));
    }
    template<typename T>
    [[nodiscard]] T get_proc_address(const char* name) const noexcept {
        return get_function<T>(name);
    }
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
        if (get_module_base_ansi(module_name, &base)) {
            func_ptr_ = reinterpret_cast<FuncT*>(get_proc(base, function_name));
        } else {
            func_ptr_ = nullptr;
        }
    }

    [[nodiscard]] FuncT* get() const noexcept { return func_ptr_; }
    [[nodiscard]] bool is_valid() const noexcept { return func_ptr_ != nullptr; }
    bool operator!() const noexcept { return func_ptr_ == nullptr; }
    
    void reset() noexcept { func_ptr_ = nullptr; }
    void reset(const char* module_name, const char* function_name) noexcept {
        void* base = nullptr;
        if (get_module_base_ansi(module_name, &base)) {
            func_ptr_ = reinterpret_cast<FuncT*>(get_proc(base, function_name));
        } else {
            func_ptr_ = nullptr;
        }
    }

private:
    FuncT* func_ptr_;
};

#endif

}

#define S(str) stealth_encrypted_char<sizeof(str) - 1, __COUNTER__>(str)
#define SW(str) stealth_encrypted_wchar<(sizeof(str) - 1) / sizeof(wchar_t), __COUNTER__>(str)

#endif