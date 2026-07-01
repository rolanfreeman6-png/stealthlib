#pragma once
#ifndef STEALTH_ENCODING_ENCODING_HPP
#define STEALTH_ENCODING_ENCODING_HPP

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <optional>
#include <vector>
#include <array>

namespace stealth::encoding {

namespace detail_base64 {
static const char b64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
inline char encode_b64_byte(unsigned char v) noexcept { return b64_alphabet[v & 0x3F]; }
}

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

    [[nodiscard]] uint8_t operator[](std::size_t idx) const noexcept {
        if (length == 0) return 0;
        return data[idx % length];
    }
};

template<size_t KeySize>
inline void xor_crypt(void* data, size_t len, const xor_key<KeySize>& key) noexcept {
    if (!data) return;
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

inline std::string base64_encode(const void* data, size_t len) noexcept {
    if (!data) return {};
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
    bool ended = false;
    for (size_t i = 0; i < len_str; i += 4) {
        int8_t vals[4] = {-1, -1, -1, -1};
        for (size_t j = 0; j < 4; ++j) {
            if (s[i + j] != '=') {
                unsigned char c = static_cast<unsigned char>(s[i + j]);
                vals[j] = b64_decode[c];
                if (vals[j] < 0) return std::nullopt;
            } else {
                vals[j] = -1;
            }
        }
        if (vals[0] < 0 || vals[1] < 0) return std::nullopt;
        bool pad2 = (s[i + 2] == '=');
        bool pad3 = (s[i + 3] == '=');
        if (pad2 && !pad3) return std::nullopt;
        if (!ended) return std::nullopt;
        result += static_cast<char>((vals[0] << 2) | (vals[1] >> 4));
        if (!pad2) result += static_cast<char>((vals[1] << 4) | (vals[2] >> 2));
        if (!pad3) result += static_cast<char>((vals[2] << 6) | vals[3]);
        if (pad2 || pad3) ended = true;
    }
    return result;
}

inline std::string hex_encode(const void* data, size_t len) noexcept {
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

} // namespace stealth::encoding

#endif // STEALTH_ENCODING_ENCODING_HPP
