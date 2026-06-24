#pragma once
#ifndef STEALTH_STRINGS_HPP
#define STEALTH_STRINGS_HPP

#include <cstdint>
#include <cstddef>
#include <array>
#include <string>
#include <string_view>
#include <type_traits>
#include <cstring>

#ifdef _WIN32
#define STEALTH_PLATFORM_WINDOWS 1
#elif defined(__linux__)
#define STEALTH_PLATFORM_LINUX 1
#else
#define STEALTH_PLATFORM_UNKNOWN 1
#endif

namespace stealth {

namespace detail {

constexpr inline uint64_t stealth_key_seed = 0x5EED5EED5EED5EEDULL;

constexpr uint64_t mix(uint64_t value) noexcept {
    value ^= value >> 33;
    value *= 0xFF51AFD7ED558CCDuLL;
    value ^= value >> 33;
    value *= 0xC4CEB9FC1CE12D6DuLL;
    value ^= value >> 33;
    return value;
}

constexpr uint64_t derive_key(size_t index) noexcept {
    return mix(stealth_key_seed + static_cast<uint64_t>(index) * 0x9E3779B97F4A7C15ULL);
}

constexpr uint8_t derive_byte(size_t index, size_t position) noexcept {
    uint64_t key = derive_key(index);
    return static_cast<uint8_t>((key >> (position * 8)) & 0xFF);
}

template<size_t N>
constexpr auto xor_encrypt(const char* src, size_t index) noexcept {
    std::array<char, N> result{};
    for (size_t i = 0; i < N; ++i) {
        result[i] = static_cast<char>(static_cast<uint8_t>(src[i]) ^ derive_byte(index, i % 8));
    }
    return result;
}

template<size_t N>
constexpr auto xor_encrypt_wide(const wchar_t* src, size_t index) noexcept {
    std::array<wchar_t, N> result{};
    for (size_t i = 0; i < N; ++i) {
        uint32_t ch = static_cast<uint32_t>(src[i]);
        ch ^= derive_byte(index, i % 4);
        result[i] = static_cast<wchar_t>(ch);
    }
    return result;
}

struct encrypted_string_storage {
    std::array<char, 512> encrypted{};
    char buffer[512];
    bool decrypted;
};

struct encrypted_wide_storage {
    std::array<wchar_t, 256> encrypted{};
    wchar_t buffer[256];
    bool decrypted;
};

template<size_t N>
struct encrypted_string_impl {
    mutable std::array<char, N> encrypted{};
    mutable char buffer[N + 1];
    mutable bool decrypted_flag;

    constexpr encrypted_string_impl() noexcept : encrypted{}, buffer{}, decrypted_flag(false) {}

    constexpr encrypted_string_impl(const char* src, size_t idx) noexcept {
        for (size_t i = 0; i < N; ++i) {
            encrypted[i] = static_cast<char>(static_cast<uint8_t>(src[i]) ^ derive_byte(idx, i % 8));
        }
        decrypted_flag = false;
    }

    void decrypt(size_t idx) const noexcept {
        if (decrypted_flag) return;
        for (size_t i = 0; i < N; ++i) {
            buffer[i] = static_cast<char>(static_cast<uint8_t>(encrypted[i]) ^ derive_byte(idx, i % 8));
        }
        buffer[N] = '\0';
        decrypted_flag = true;
    }

    void encrypt(size_t idx) const noexcept {
        for (size_t i = 0; i < N; ++i) {
            encrypted[i] = static_cast<char>(static_cast<uint8_t>(encrypted[i]) ^ derive_byte(idx, i % 8));
        }
    }
};

template<size_t N>
struct encrypted_wide_impl {
    mutable std::array<wchar_t, N> encrypted{};
    mutable wchar_t buffer[N + 1];
    mutable bool decrypted_flag;

    constexpr encrypted_wide_impl() noexcept : encrypted{}, buffer{}, decrypted_flag(false) {}

    constexpr encrypted_wide_impl(const wchar_t* src, size_t idx) noexcept {
        for (size_t i = 0; i < N; ++i) {
            uint32_t ch = static_cast<uint32_t>(src[i]);
            ch ^= derive_byte(idx, i % 4);
            encrypted[i] = static_cast<wchar_t>(ch);
        }
        decrypted_flag = false;
    }

    void decrypt(size_t idx) const noexcept {
        if (decrypted_flag) return;
        for (size_t i = 0; i < N; ++i) {
            uint32_t ch = static_cast<uint32_t>(encrypted[i]);
            ch ^= derive_byte(idx, i % 4);
            buffer[i] = static_cast<wchar_t>(ch);
        }
        buffer[N] = L'\0';
        decrypted_flag = true;
    }
};

}

template<size_t N>
struct encrypted_string {
    static_assert(N > 0 && N < 512, "String size must be between 1 and 511");

    using char_type = char;

    size_t index;
    detail::encrypted_string_impl<N> data;

    constexpr encrypted_string(const char* src, size_t idx = 0) noexcept
        : index(idx), data(src, idx) {
    }

    encrypted_string(const encrypted_string&) = default;
    encrypted_string& operator=(const encrypted_string&) = default;

    [[nodiscard]] char* decrypt() noexcept {
        data.decrypt(index);
        return data.buffer;
    }

    [[nodiscard]] const char* decrypt() const noexcept {
        data.decrypt(index);
        return data.buffer;
    }

    [[nodiscard]] const char* c_str() const noexcept { return decrypt(); }
    [[nodiscard]] char* c_str() noexcept { return decrypt(); }

    [[nodiscard]] constexpr size_t size() const noexcept { return N; }
    [[nodiscard]] constexpr size_t length() const noexcept { return N; }
    [[nodiscard]] constexpr bool is_decrypted() const noexcept { return data.decrypted_flag; }

    template<size_t M>
    [[nodiscard]] bool operator==(const encrypted_string<M>& other) const noexcept {
        if (N != M) return false;
        const char* a = decrypt();
        const char* b = other.decrypt();
        return std::strcmp(a, b) == 0;
    }

    [[nodiscard]] explicit operator std::string_view() const noexcept {
        return std::string_view(decrypt(), N);
    }

    [[nodiscard]] explicit operator std::string() const noexcept {
        return std::string(decrypt(), N);
    }
};

template<size_t N>
encrypted_string(const char (&)[N]) -> encrypted_string<N - 1>;

template<size_t N>
encrypted_string(const char (&)[N], size_t) -> encrypted_string<N - 1>;

template<size_t N>
struct encrypted_wide_string {
    static_assert(N > 0 && N < 256, "Wide string size must be between 1 and 255");

    using char_type = wchar_t;

    size_t index;
    detail::encrypted_wide_impl<N> data;

    constexpr encrypted_wide_string(const wchar_t* src, size_t idx = 0) noexcept
        : index(idx), data(src, idx) {
    }

    encrypted_wide_string(const encrypted_wide_string&) = default;
    encrypted_wide_string& operator=(const encrypted_wide_string&) = default;

    [[nodiscard]] wchar_t* decrypt() noexcept {
        data.decrypt(index);
        return data.buffer;
    }

    [[nodiscard]] const wchar_t* decrypt() const noexcept {
        data.decrypt(index);
        return data.buffer;
    }

    [[nodiscard]] const wchar_t* c_str() const noexcept { return decrypt(); }
    [[nodiscard]] wchar_t* c_str() noexcept { return decrypt(); }

    [[nodiscard]] constexpr size_t size() const noexcept { return N; }
    [[nodiscard]] constexpr size_t length() const noexcept { return N; }
    [[nodiscard]] constexpr bool is_decrypted() const noexcept { return data.decrypted_flag; }
};

template<size_t N>
encrypted_wide_string(const wchar_t (&)[N]) -> encrypted_wide_string<N - 1>;

template<size_t N>
encrypted_wide_string(const wchar_t (&)[N], size_t) -> encrypted_wide_string<N - 1>;

template<size_t N>
using encrypted_wstring = encrypted_wide_string<N>;

namespace literals {

constexpr encrypted_string<1> operator""_s(const char* str, [[maybe_unused]] size_t len) noexcept {
    return encrypted_string<1>(str);
}

template<encrypted_string Str>
[[nodiscard]] constexpr auto operator""_encrypted() noexcept {
    return Str;
}

}

#define STEALTH_STR_LITERAL(str) ::stealth::encrypted_string<sizeof(str) - 1>(str, __COUNTER__)

#if defined(_MSC_VER)
#define STEALTH_DECRYPT_STR(str) ::stealth::encrypted_string<sizeof(str) - 1>(str, __COUNTER__).decrypt()
#elif defined(__GNUC__) || defined(__clang__)
#define STEALTH_DECRYPT_STR(str) ({ \
    static_assert(sizeof(str) > 0, "String cannot be empty"); \
    ::stealth::encrypted_string<sizeof(str) - 1>(str, __LINE__).decrypt(); \
})
#else
#define STEALTH_DECRYPT_STR(str) str
#endif

#define S(str) STEALTH_DECRYPT_STR(str)
#define SW(str) ::stealth::encrypted_wide_string<sizeof(L##str) / sizeof(wchar_t) - 1>(str, __COUNTER__).decrypt()

namespace detail {

template<typename CharT, size_t N>
struct basic_static_string {
    using value_type = CharT;
    CharT data[N + 1];

    constexpr basic_static_string(const CharT* src) noexcept {
        for (size_t i = 0; i < N; ++i) {
            data[i] = src[i];
        }
        data[N] = 0;
    }

    [[nodiscard]] constexpr const CharT* c_str() const noexcept { return data; }
    [[nodiscard]] constexpr size_t length() const noexcept { return N; }
    [[nodiscard]] constexpr size_t size() const noexcept { return N; }
};

template<size_t N>
basic_static_string(const char (&)[N]) -> basic_static_string<char, N - 1>;

template<size_t N>
basic_static_string(const wchar_t (&)[N]) -> basic_static_string<wchar_t, N - 1>;

}

template<size_t N>
using static_string = detail::basic_static_string<char, N>;

template<size_t N>
using static_wstring = detail::basic_static_string<wchar_t, N>;

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

}

#endif