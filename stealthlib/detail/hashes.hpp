#pragma once
#ifndef STEALTH_DETAIL_HASHES_HPP
#define STEALTH_DETAIL_HASHES_HPP

#include <cstdint>
#include <cstddef>
#include <cstdint>

namespace stealth::detail {

constexpr uint64_t fnv1a_basis = 0xCBF29CE484222325ULL;
constexpr uint64_t fnv1a_prime = 0x100000001B3ULL;

constexpr uint64_t fnv1a_64(const char* s, size_t n) noexcept {
    uint64_t h = fnv1a_basis;
    for (size_t i = 0; i < n; ++i) {
        h ^= static_cast<uint64_t>(static_cast<uint8_t>(s[i]));
        h *= fnv1a_prime;
    }
    return h;
}

constexpr uint64_t fnv1a_wide(const wchar_t* s, size_t n) noexcept {
    uint64_t h = fnv1a_basis;
    for (size_t i = 0; i < n; ++i) {
        uint32_t ch = static_cast<uint32_t>(s[i]) & 0xFFFFu;
        h ^= static_cast<uint64_t>(ch & 0xFFu);
        h *= fnv1a_prime;
        h ^= static_cast<uint64_t>((ch >> 8) & 0xFFu);
        h *= fnv1a_prime;
    }
    return h;
}

constexpr uint64_t djb2(const char* s, size_t n) noexcept {
    uint64_t h = 5381ULL;
    for (size_t i = 0; i < n; ++i) {
        h = ((h << 5) + h) + static_cast<uint8_t>(s[i]);
    }
    return h;
}

template<size_t N>
struct cexpr_str {
    char v[N];
    constexpr cexpr_str(const char (&s)[N]) noexcept {
        for (size_t i = 0; i < N; ++i) v[i] = s[i];
    }
};

template<size_t N>
struct cexpr_wstr {
    wchar_t v[N];
    constexpr cexpr_wstr(const wchar_t (&s)[N]) noexcept {
        for (size_t i = 0; i < N; ++i) v[i] = s[i];
    }
};

constexpr uint64_t mix(uint64_t v) noexcept {
    v ^= v >> 33;
    v *= 0xFF51AFD7ED558CCDuLL;
    v ^= v >> 33;
    v *= 0xC4CEB9FC1CE12D6DuLL;
    v ^= v >> 33;
    return v;
}

constexpr uint64_t derive_seed(size_t idx, uint64_t mix_k) noexcept {
    return mix(idx * 0x9E3779B97F4A7C15ULL + mix_k + STEALTH_BUILD_KEY);
}

constexpr uint8_t derive_byte(size_t idx, size_t pos, uint64_t mix_k) noexcept {
    return static_cast<uint8_t>((derive_seed(idx, mix_k) >> (pos * 8)) & 0xFFu);
}

} // namespace stealth::detail

namespace stealth::hashes {

constexpr size_t constexpr_strlen(const char* s, size_t i = 0) noexcept {
    return (s[i] == '\0') ? i : constexpr_strlen(s, i + 1);
}

constexpr size_t constexpr_wcslen(const wchar_t* s, size_t i = 0) noexcept {
    return (s[i] == L'\0') ? i : constexpr_wcslen(s, i + 1);
}

constexpr uint64_t fnv(const char* s, size_t n) noexcept {
    return detail::fnv1a_64(s, n);
}

constexpr uint64_t fnv(const char* s) noexcept {
    return detail::fnv1a_64(s, constexpr_strlen(s));
}

inline uint64_t fnv(const uint8_t* s, size_t n) noexcept {
    return detail::fnv1a_64(reinterpret_cast<const char*>(s), n);
}

constexpr uint64_t fnv(const wchar_t* s, size_t n) noexcept {
    return detail::fnv1a_wide(s, n);
}

constexpr uint64_t fnv(const wchar_t* s) noexcept {
    return detail::fnv1a_wide(s, constexpr_wcslen(s));
}

template<size_t N>
constexpr uint64_t fnv(const detail::cexpr_str<N>& s) noexcept {
    uint64_t h = detail::fnv1a_basis;
    for (size_t i = 0; i < N - 1; ++i) {
        h ^= static_cast<uint64_t>(static_cast<uint8_t>(s.v[i]));
        h *= detail::fnv1a_prime;
    }
    return h;
}

constexpr uint64_t djb2(const char* s, size_t n) noexcept {
    return detail::djb2(s, n);
}

inline uint64_t runtime(const char* s) noexcept {
    if (!s) return 0;
    uint64_t h = detail::fnv1a_basis;
    while (*s) {
        h ^= static_cast<uint64_t>(static_cast<unsigned char>(*s));
        h *= detail::fnv1a_prime;
        ++s;
    }
    return h;
}

inline uint64_t runtime(const uint8_t* s) noexcept {
    return runtime(reinterpret_cast<const char*>(s));
}

inline uint64_t djb2(const uint8_t* s, size_t n) noexcept {
    return djb2(reinterpret_cast<const char*>(s), n);
}

} // namespace stealth::hashes

#endif // STEALTH_DETAIL_HASHES_HPP
