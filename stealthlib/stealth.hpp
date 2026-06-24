#pragma once
#ifndef STEALTH_HPP
#define STEALTH_HPP

#define STEALTH_VERSION_STRING "1.0.0"

#include <atomic>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <array>
#include <type_traits>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
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
    
    constexpr uint64_t make_key(uint64_t line, uint64_t counter, uint64_t size, uint64_t tag) noexcept {
        return mix(key_seed ^ (line * 0x9E3779B97F4A7C15ULL) ^ (counter * 0xBF58476D1CE4E5B9ULL) ^ (size << 17) ^ tag);
    }

    constexpr uint8_t derive_byte(uint64_t key, size_t pos) noexcept {
        return static_cast<uint8_t>(mix(key + static_cast<uint64_t>(pos) * 0xD6E8FEB86659FD93ULL) & 0xFF);
    }

    template<typename CharT>
    constexpr CharT crypt_char(CharT ch, uint64_t key, size_t index) noexcept {
        using unsigned_char_t = std::make_unsigned_t<CharT>;
        uint64_t mask = 0;
        for (size_t byte = 0; byte < sizeof(CharT) && byte < 8; ++byte) {
            mask |= static_cast<uint64_t>(derive_byte(key, index * sizeof(CharT) + byte)) << (byte * 8);
        }
        return static_cast<CharT>(static_cast<unsigned_char_t>(ch) ^ static_cast<unsigned_char_t>(mask));
    }

    template<typename CharT, size_t N>
    struct encrypted_blob {
        std::array<CharT, N> encrypted{};
        uint64_t key = 0;
    };

    template<uint64_t Key, typename CharT, size_t N>
    consteval encrypted_blob<CharT, N> make_encrypted_blob(const CharT (&src)[N]) noexcept {
        encrypted_blob<CharT, N> blob{};
        blob.key = Key;
        for (size_t i = 0; i < N; ++i) {
            blob.encrypted[i] = crypt_char(src[i], Key, i);
        }
        return blob;
    }

    template<typename CharT, size_t N>
    class encrypted_string_impl {
    public:
        constexpr explicit encrypted_string_impl(const encrypted_blob<CharT, N>& blob) noexcept
            : encrypted(blob.encrypted), key(blob.key), buffer{}, state(0) {}

        const CharT* decrypt() const noexcept {
            unsigned current = state.load(std::memory_order_acquire);
            if (current != 2) {
                unsigned expected = 0;
                if (state.compare_exchange_strong(expected, 1, std::memory_order_acq_rel, std::memory_order_acquire)) {
                    for (size_t i = 0; i < N; ++i) {
                        buffer[i] = crypt_char(encrypted[i], key, i);
                    }
                    state.store(2, std::memory_order_release);
                } else {
                    while (state.load(std::memory_order_acquire) != 2) {
                    }
                }
            }
            return buffer.data();
        }

    private:
        std::array<CharT, N> encrypted{};
        uint64_t key = 0;
        mutable std::array<CharT, N> buffer{};
        mutable std::atomic<unsigned> state;
    };

    template<size_t N, uint64_t Key>
    consteval auto make_char_blob(const char (&src)[N]) noexcept {
        return make_encrypted_blob<Key>(src);
    }

    template<size_t N, uint64_t Key>
    consteval auto make_wchar_blob(const wchar_t (&src)[N]) noexcept {
        return make_encrypted_blob<Key>(src);
    }
}

namespace memory {

inline void secure_zero(void* ptr, size_t len) noexcept {
#ifdef _WIN32
    if (ptr && len) SecureZeroMemory(ptr, len);
#else
    if (!ptr) return;
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) *p++ = 0;
#endif
}

inline bool compare_constant_time(const void* a, const void* b, size_t len) noexcept {
    if (len == 0) return true;
    if (!a || !b) return false;
    const uint8_t* A = static_cast<const uint8_t*>(a);
    const uint8_t* B = static_cast<const uint8_t*>(b);
    uint32_t diff = 0;
    for (size_t i = 0; i < len; ++i) diff |= A[i] ^ B[i];
    return diff == 0;
}

}

template<size_t MaxSize = 256>
class secure_string {
    static_assert(MaxSize > 0, "secure_string MaxSize must be greater than zero");
public:
    using char_type = char;
    
    secure_string() noexcept : length_(0) {
        memory::secure_zero(data_, MaxSize);
    }
    
    explicit secure_string(const char* str) noexcept : length_(0) {
        memory::secure_zero(data_, MaxSize);
        if (!str) return;
        while (str[length_] != '\0' && length_ < MaxSize - 1) {
            data_[length_] = str[length_];
            ++length_;
        }
        data_[length_] = '\0';
    }
    
    secure_string(const secure_string&) = delete;
    secure_string& operator=(const secure_string&) = delete;
    
    ~secure_string() noexcept {
        memory::secure_zero(data_, MaxSize);
        length_ = 0;
    }
    
    [[nodiscard]] char* data() noexcept { return data_; }
    [[nodiscard]] const char* data() const noexcept { return data_; }
    [[nodiscard]] const char* c_str() const noexcept { return data_; }
    [[nodiscard]] size_t length() const noexcept { return length_; }
    [[nodiscard]] size_t size() const noexcept { return length_; }
    
    void clear() noexcept {
        memory::secure_zero(data_, MaxSize);
        length_ = 0;
    }
    
private:
    char data_[MaxSize]{};
    size_t length_;
};

namespace encoding {

template<size_t MaxBytes = 4096>
class decode_result {
public:
    uint8_t data[MaxBytes];
    size_t len = 0;
    bool valid = false;
    
    decode_result() noexcept { std::memset(data, 0, MaxBytes); }
    
    [[nodiscard]] const uint8_t* begin() const noexcept { return data; }
    [[nodiscard]] const uint8_t* end() const noexcept { return data + len; }
    [[nodiscard]] size_t size() const noexcept { return len; }
    [[nodiscard]] bool has_value() const noexcept { return valid; }
    explicit operator bool() const noexcept { return valid; }
};

inline std::string base64_encode(const void* data, size_t len);
inline std::string base64_encode(const std::string_view& str) {
    return base64_encode(str.data(), str.size());
}
template<size_t MaxBytes = 4096>
decode_result<MaxBytes> base64_decode(const std::string_view& str) noexcept;
inline std::string hex_encode(const void* data, size_t len);
inline std::string hex_encode(const std::string_view& str) {
    return hex_encode(str.data(), str.size());
}
template<size_t MaxBytes = 4096>
decode_result<MaxBytes> hex_decode(const std::string_view& str) noexcept;

inline void rot13_encode(void* dst, const void* src, size_t len) noexcept {
    if (len == 0) return;
    if (!dst || !src) return;
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
    
    [[nodiscard]] uint8_t operator[](size_t idx) const noexcept {
        if (length == 0) return 0;
        return data[idx % length];
    }
};

template<size_t KeySize>
inline void xor_crypt(void* data, size_t len, const xor_key<KeySize>& key) noexcept {
    if (len == 0 || !data || key.length == 0) return;
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

namespace detail {
static const char b64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
inline char encode_b64_byte(unsigned char v) noexcept { return b64_alphabet[v & 0x3F]; }
}

inline std::string base64_encode(const void* data, size_t len) {
    if (len == 0) return {};
    if (!data) return {};
    const unsigned char* src = static_cast<const unsigned char*>(data);
    std::string result;
    result.reserve((len + 2) / 3 * 4);
    size_t i = 0;
    while (i + 2 < len) {
        unsigned int v = (static_cast<unsigned int>(src[i]) << 16) | 
                        (static_cast<unsigned int>(src[i + 1]) << 8) | 
                        static_cast<unsigned int>(src[i + 2]);
        result += detail::encode_b64_byte(static_cast<unsigned char>(v >> 18));
        result += detail::encode_b64_byte(static_cast<unsigned char>(v >> 12));
        result += detail::encode_b64_byte(static_cast<unsigned char>(v >> 6));
        result += detail::encode_b64_byte(static_cast<unsigned char>(v));
        i += 3;
    }
    if (i + 1 < len) {
        unsigned int v = (static_cast<unsigned int>(src[i]) << 16) | 
                        (static_cast<unsigned int>(src[i + 1]) << 8);
        result += detail::encode_b64_byte(static_cast<unsigned char>(v >> 18));
        result += detail::encode_b64_byte(static_cast<unsigned char>(v >> 12));
        result += detail::encode_b64_byte(static_cast<unsigned char>(v >> 6));
        result += '=';
    } else if (i < len) {
        unsigned int v = static_cast<unsigned int>(src[i]) << 16;
        result += detail::encode_b64_byte(static_cast<unsigned char>(v >> 18));
        result += detail::encode_b64_byte(static_cast<unsigned char>(v >> 12));
        result += "==";
    }
    return result;
}

template<size_t MaxBytes>
decode_result<MaxBytes> base64_decode(const std::string_view& str) noexcept {
    decode_result<MaxBytes> result;
    if (str.size() % 4 != 0) return result;
    if (str.empty()) {
        result.valid = true;
        return result;
    }
    size_t padding = 0;
    if (!str.empty() && str[str.size() - 1] == '=') ++padding;
    if (str.size() > 1 && str[str.size() - 2] == '=') ++padding;
    for (size_t i = 0; i + padding < str.size(); ++i) {
        if (str[i] == '=') return result;
    }
    if (padding > 2) return result;
    const size_t required = (str.size() / 4) * 3 - padding;
    if (required > MaxBytes) return result;
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
    size_t out = 0;
    const char* s = str.data();
    size_t len_str = str.size();
    for (size_t i = 0; i < len_str; i += 4) {
        int8_t vals[4] = {-1, -1, -1, -1};
        for (int j = 0; j < 4; ++j) {
            if (s[i + j] != '=') {
                unsigned char c = static_cast<unsigned char>(s[i + j]);
                vals[j] = b64_decode[c];
                if (vals[j] < 0) return result;
            } else {
                if (i + 4 != len_str) return result;
                if (j < 2) return result;
                vals[j] = 0;
            }
        }
        if (vals[0] < 0 || vals[1] < 0) return result;
        result.data[out++] = static_cast<uint8_t>((vals[0] << 2) | (vals[1] >> 4));
        if (s[i + 2] != '=') result.data[out++] = static_cast<uint8_t>((vals[1] << 4) | (vals[2] >> 2));
        if (s[i + 3] != '=') result.data[out++] = static_cast<uint8_t>((vals[2] << 6) | vals[3]);
    }
    result.len = out;
    result.valid = true;
    return result;
}

inline std::string hex_encode(const void* data, size_t len) {
    if (len == 0) return {};
    if (!data) return {};
    static const char hex_chars[] = "0123456789ABCDEF";
    const unsigned char* src = static_cast<const unsigned char*>(data);
    std::string result(len * 2, '\0');
    for (size_t i = 0; i < len; ++i) {
        result[i * 2] = hex_chars[src[i] >> 4];
        result[i * 2 + 1] = hex_chars[src[i] & 0x0F];
    }
    return result;
}

template<size_t MaxBytes>
decode_result<MaxBytes> hex_decode(const std::string_view& str) noexcept {
    decode_result<MaxBytes> result;
    if (str.size() % 2 != 0) return result;
    if (str.size() / 2 > MaxBytes) return result;
    size_t out = 0;
    const char* s = str.data();
    for (size_t i = 0; i < str.size() / 2; ++i) {
        char h = s[i * 2], l = s[i * 2 + 1];
        int hi = 0, lo = 0;
        if (h >= '0' && h <= '9') hi = h - '0';
        else if (h >= 'A' && h <= 'F') hi = h - 'A' + 10;
        else if (h >= 'a' && h <= 'f') hi = h - 'a' + 10;
        else return result;
        if (l >= '0' && l <= '9') lo = l - '0';
        else if (l >= 'A' && l <= 'F') lo = l - 'A' + 10;
        else if (l >= 'a' && l <= 'f') lo = l - 'a' + 10;
        else return result;
        result.data[out++] = static_cast<uint8_t>((hi << 4) | lo);
    }
    result.len = out;
    result.valid = true;
    return result;
}

}

namespace detection {

inline bool is_debugger_present() noexcept {
#ifdef _WIN32
    #if defined(_M_X64) || defined(__x86_64__)
    auto peb = reinterpret_cast<void*>(__readgsqword(0x60));
    #elif defined(_M_IX86)
    auto peb = reinterpret_cast<void*>(__readfsdword(0x30));
    #else
    return false;
    #endif
    if (!peb) return false;
    return *static_cast<uint8_t*>(static_cast<void*>(static_cast<char*>(peb) + 2)) != 0;
#else
    return false;
#endif
}

inline bool check_remote_debugger() noexcept;

}

#ifdef _WIN32

#if defined(_M_X64) || defined(__x86_64__)
inline void* get_peb_ptr() noexcept { return reinterpret_cast<void*>(__readgsqword(0x60)); }
#elif defined(_M_IX86)
inline void* get_peb_ptr() noexcept { return reinterpret_cast<void*>(__readfsdword(0x30)); }
#else
inline void* get_peb_ptr() noexcept { return nullptr; }
#endif

struct UNICODE_STRING_TEMP { uint16_t Length; uint16_t MaximumLength; wchar_t* Buffer; };
struct LIST_ENTRY_TEMP2 { void* Flink; void* Blink; };
struct LDR_ENTRY_TEMP2 { LIST_ENTRY_TEMP2 InLoadOrderLinks; LIST_ENTRY_TEMP2 InMemoryOrderLinks; LIST_ENTRY_TEMP2 InInitializationOrderLinks; void* DllBase; void* EntryPoint; uint32_t SizeOfImage; UNICODE_STRING_TEMP FullDllName; UNICODE_STRING_TEMP BaseDllName; };
struct PEB_LDR_TEMP2 { uint32_t Length; uint8_t Initialized; void* SsHandle; LIST_ENTRY_TEMP2 InLoadOrderModuleList; };
struct PEB_STRUCT_TEMP2 { uint8_t InheritedAddressSpace; uint8_t ReadImageFileExecOptions; uint8_t BeingDebugged; uint8_t BitField; void* Mutant; void* ImageBaseAddress; PEB_LDR_TEMP2* Ldr; };

inline bool get_module_base(const wchar_t* name, void** out) noexcept {
    if (out) *out = nullptr;
    if (!name || !out) return false;
    auto peb = reinterpret_cast<PEB_STRUCT_TEMP2*>(get_peb_ptr());
    if (!peb || !peb->Ldr) return false;
    size_t len = 0;
    while (name[len] && len < 260) ++len;
    if (len == 0 || len >= 260) return false;
    auto head = &peb->Ldr->InLoadOrderModuleList;
    auto entry = reinterpret_cast<LDR_ENTRY_TEMP2*>(peb->Ldr->InLoadOrderModuleList.Flink);
    for (size_t guard = 0; entry && entry != reinterpret_cast<LDR_ENTRY_TEMP2*>(head) && guard < 1024; ++guard) {
        if (!entry->BaseDllName.Buffer) break;
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
        entry = reinterpret_cast<LDR_ENTRY_TEMP2*>(entry->InLoadOrderLinks.Flink);
    }
    return false;
}

inline bool get_module_base_ansi(const char* name, void** out) noexcept {
    if (out) *out = nullptr;
    if (!name || !out) return false;
    wchar_t wide[260] = {};
    size_t i = 0;
    while (name[i] && i < 259) {
        wide[i] = static_cast<wchar_t>(static_cast<unsigned char>(name[i]));
        ++i;
    }
    return get_module_base(wide, out);
}

struct DOS_HEADER { uint16_t e_magic; uint16_t e_cblp; uint16_t e_cp; uint16_t e_crlc; uint16_t e_cparhdr; uint16_t e_minalloc; uint16_t e_maxalloc; uint16_t e_ss; uint16_t e_sp; uint16_t e_csum; uint16_t e_ip; uint16_t e_cs; uint16_t e_lfarlc; uint16_t e_ovno; uint16_t e_res[4]; uint16_t e_oemid; uint16_t e_oeminfo; uint16_t e_res2[10]; int32_t e_lfanew; };
struct NT_HEADERS { uint32_t Signature; uint16_t Machine; uint16_t NumberOfSections; uint32_t TimeDateStamp; uint32_t PointerToSymbolTable; uint32_t NumberOfSymbols; uint16_t SizeOfOptionalHeader; uint16_t Characteristics; uint16_t Magic; uint8_t MajorLinkerVersion; uint8_t MinorLinkerVersion; uint32_t SizeOfCode; uint32_t SizeOfInitializedData; uint32_t SizeOfUninitializedData; uint32_t AddressOfEntryPoint; uint32_t BaseOfCode; uint64_t ImageBase; uint32_t SectionAlignment; uint32_t FileAlignment; uint16_t MajorOperatingSystemVersion; uint16_t MinorOperatingSystemVersion; uint16_t MajorImageVersion; uint16_t MinorImageVersion; uint16_t MajorSubsystemVersion; uint16_t MinorSubsystemVersion; uint32_t Win32VersionValue; uint32_t SizeOfImage; uint32_t SizeOfHeaders; uint32_t CheckSum; uint16_t Subsystem; uint16_t DllCharacteristics; uint64_t SizeOfStackReserve; uint64_t SizeOfStackCommit; uint64_t SizeOfHeapReserve; uint64_t SizeOfHeapCommit; uint32_t LoaderFlags; uint32_t NumberOfRvaAndSizes; uint32_t DataDirectory[16]; };
struct EXPORT_DIRECTORY { uint32_t Characteristics; uint32_t TimeDateStamp; uint16_t MajorVersion; uint16_t MinorVersion; uint32_t Name; uint32_t Base; uint32_t NumberOfFunctions; uint32_t NumberOfNames; uint32_t AddressOfFunctions; uint32_t AddressOfNames; uint32_t AddressOfNameOrdinals; };

inline DOS_HEADER* get_dos(void* base) noexcept { return static_cast<DOS_HEADER*>(base); }
inline NT_HEADERS* get_nt(void* base) noexcept {
    auto dos = get_dos(base);
    if (!dos || dos->e_magic != 0x5A4D) return nullptr;
    if (dos->e_lfanew < static_cast<int32_t>(sizeof(DOS_HEADER))) return nullptr;
    if (dos->e_lfanew > 0x100000) return nullptr;
    return reinterpret_cast<NT_HEADERS*>(static_cast<char*>(base) + dos->e_lfanew);
}

inline bool rva_in_image(void* base, uint32_t rva, size_t bytes = 1) noexcept {
    auto nt = get_nt(base);
    if (!nt || nt->Signature != 0x4550 || nt->SizeOfImage == 0) return false;
    if (rva >= nt->SizeOfImage) return false;
    return bytes <= static_cast<size_t>(nt->SizeOfImage - rva);
}

inline EXPORT_DIRECTORY* get_export(void* base) noexcept {
    auto nt = get_nt(base);
    if (!nt || nt->Signature != 0x4550) return nullptr;
    if (nt->NumberOfRvaAndSizes == 0) return nullptr;
    uint32_t rva = nt->DataDirectory[0];
    uint32_t size = nt->DataDirectory[1];
    if (!rva || size < sizeof(EXPORT_DIRECTORY)) return nullptr;
    if (!rva_in_image(base, rva, sizeof(EXPORT_DIRECTORY))) return nullptr;
    return reinterpret_cast<EXPORT_DIRECTORY*>(static_cast<char*>(base) + rva);
}

namespace detail {
inline bool ascii_ieq(char a, char b) noexcept {
    if (a >= 'A' && a <= 'Z') a = static_cast<char>(a + 32);
    if (b >= 'A' && b <= 'Z') b = static_cast<char>(b + 32);
    return a == b;
}

inline bool ascii_iequals(const char* a, const char* b) noexcept {
    if (!a || !b) return false;
    size_t guard = 0;
    while (*a && *b && guard++ < 512) {
        if (!ascii_ieq(*a, *b)) return false;
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}
}

inline void* get_proc_impl(void* base, const char* name, unsigned depth) noexcept {
    if (!base || !name || depth > 8) return nullptr;
    auto exp = get_export(base);
    auto nt = get_nt(base);
    if (!exp || !nt || !exp->NumberOfNames || !exp->NumberOfFunctions) return nullptr;
    if (!rva_in_image(base, exp->AddressOfNames, static_cast<size_t>(exp->NumberOfNames) * sizeof(uint32_t))) return nullptr;
    if (!rva_in_image(base, exp->AddressOfNameOrdinals, static_cast<size_t>(exp->NumberOfNames) * sizeof(uint16_t))) return nullptr;
    if (!rva_in_image(base, exp->AddressOfFunctions, static_cast<size_t>(exp->NumberOfFunctions) * sizeof(uint32_t))) return nullptr;
    auto names = reinterpret_cast<uint32_t*>(static_cast<char*>(base) + exp->AddressOfNames);
    auto ordinals = reinterpret_cast<uint16_t*>(static_cast<char*>(base) + exp->AddressOfNameOrdinals);
    auto funcs = reinterpret_cast<uint32_t*>(static_cast<char*>(base) + exp->AddressOfFunctions);
    const uint32_t export_rva = nt->DataDirectory[0];
    const uint32_t export_size = nt->DataDirectory[1];
    for (uint32_t i = 0; i < exp->NumberOfNames; ++i) {
        if (!rva_in_image(base, names[i])) return nullptr;
        const char* n = reinterpret_cast<const char*>(base) + names[i];
        bool match = true;
        size_t j = 0;
        for (; j < 512 && n[j] && name[j]; ++j) {
            if (!detail::ascii_ieq(n[j], name[j])) { match = false; break; }
        }
        if (j >= 512) return nullptr;
        if (match && n[j] == '\0' && name[j] == '\0') {
            uint16_t ordinal = ordinals[i];
            if (ordinal >= exp->NumberOfFunctions) return nullptr;
            uint32_t func_rva = funcs[ordinal];
            if (!rva_in_image(base, func_rva)) return nullptr;
            if (func_rva >= export_rva && func_rva < export_rva + export_size) {
                const char* forwarder = static_cast<const char*>(base) + func_rva;
                char module[128]{};
                char function[128]{};
                size_t m = 0;
                size_t f = 0;
                while (forwarder[m] && forwarder[m] != '.' && m < sizeof(module) - 5) {
                    module[m] = forwarder[m];
                    ++m;
                }
                if (forwarder[m] != '.') return nullptr;
                const size_t dot = m;
                module[m++] = '.';
                module[m++] = 'd';
                module[m++] = 'l';
                module[m++] = 'l';
                module[m] = '\0';
                while (forwarder[dot + 1 + f] && f < sizeof(function) - 1) {
                    function[f] = forwarder[dot + 1 + f];
                    ++f;
                }
                function[f] = '\0';
                void* forwarded_base = nullptr;
                if (!get_module_base_ansi(module, &forwarded_base)) return nullptr;
                return get_proc_impl(forwarded_base, function, depth + 1);
            }
            return static_cast<char*>(base) + func_rva;
        }
    }
    return nullptr;
}

inline void* get_proc(void* base, const char* name) noexcept {
    return get_proc_impl(base, name, 0);
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
        if (!handle_) return nullptr;
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
    using pointer_type = std::conditional_t<std::is_pointer_v<FuncT>, FuncT, std::add_pointer_t<FuncT>>;

    stealth_api() noexcept : func_ptr_(nullptr) {}
    stealth_api(std::nullptr_t) noexcept : func_ptr_(nullptr) {}
    stealth_api(const char* module_name, const char* function_name) noexcept {
        void* base = nullptr;
        if (get_module_base_ansi(module_name, &base)) {
            func_ptr_ = reinterpret_cast<pointer_type>(get_proc(base, function_name));
        } else {
            func_ptr_ = nullptr;
        }
    }

    [[nodiscard]] pointer_type get() const noexcept { return func_ptr_; }
    [[nodiscard]] bool is_valid() const noexcept { return func_ptr_ != nullptr; }
    bool operator!() const noexcept { return func_ptr_ == nullptr; }
    explicit operator bool() const noexcept { return is_valid(); }
    
    void reset() noexcept { func_ptr_ = nullptr; }
    void reset(const char* module_name, const char* function_name) noexcept {
        void* base = nullptr;
        if (get_module_base_ansi(module_name, &base)) {
            func_ptr_ = reinterpret_cast<pointer_type>(get_proc(base, function_name));
        } else {
            func_ptr_ = nullptr;
        }
    }

private:
    pointer_type func_ptr_;
};

namespace detection {
inline bool check_remote_debugger() noexcept {
    using NtQueryInformationProcess_t = int(void*, int, void*, uint32_t, uint32_t*);
    auto proc = reinterpret_cast<NtQueryInformationProcess_t*>(get_nt_api("NtQueryInformationProcess"));
    if (!proc) return false;
    uintptr_t debug_port = 0;
    uint32_t return_len = 0;
    int result = proc(reinterpret_cast<void*>(-1), 7, &debug_port, sizeof(debug_port), &return_len);
    return result == 0 && debug_port != 0;
}
}

#endif

} // namespace stealth

#define STEALTH_S_IMPL(str, line, counter) ([]() noexcept { \
    constexpr auto stealth_blob = ::stealth::detail::make_char_blob<sizeof(str), ::stealth::detail::make_key((line), (counter), sizeof(str), 0x5354524152524159ULL)>(str); \
    static const ::stealth::detail::encrypted_string_impl<char, sizeof(str)> stealth_holder(stealth_blob); \
    return stealth_holder.decrypt(); \
}())

#define STEALTH_SW_IMPL(str, line, counter) ([]() noexcept { \
    constexpr auto stealth_blob = ::stealth::detail::make_wchar_blob<sizeof(str) / sizeof(wchar_t), ::stealth::detail::make_key((line), (counter), sizeof(str), 0x5753545241525241ULL)>(str); \
    static const ::stealth::detail::encrypted_string_impl<wchar_t, sizeof(str) / sizeof(wchar_t)> stealth_holder(stealth_blob); \
    return stealth_holder.decrypt(); \
}())

#define S(str) STEALTH_S_IMPL(str, __LINE__, __COUNTER__)
#define SW(str) STEALTH_SW_IMPL(str, __LINE__, __COUNTER__)

#endif
