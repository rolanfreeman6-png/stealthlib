#pragma once
#ifndef STEALTH_DETAIL_ENCRYPTION_HPP
#define STEALTH_DETAIL_ENCRYPTION_HPP

#include <cstdint>
#include <cstddef>
#include "version.hpp"
#include "hashes.hpp"

#if defined(__SSE2__) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2) || defined(_M_X64)
#include <emmintrin.h>
#endif

#if defined(_MSC_VER)
#include <intrin.h>
#endif

namespace stealth::detail {

template<size_t N, size_t Idx>
struct encrypted_string_impl {
    char encrypted[N]{};
    char buffer[N + 1]{};
    bool decrypted{false};

    template<size_t M>
    consteval encrypted_string_impl(const char (&src)[M]) noexcept
        : decrypted(false) {
        static_assert(M == N + 1, "StealthLib: literal length mismatch");
        constexpr uint8_t mask_table[16] = {
            0xA5,0xB6,0xC7,0xD8, 0xE9,0xFA,0x0B,0x1C,
            0x2D,0x3E,0x4F,0x50, 0x61,0x72,0x83,0x94
        };
        constexpr uint8_t var_mask = mask_table[STEALTH_BUILD_KEY % 16];
        for (size_t i = 0; i < N; ++i) {
            uint8_t b = static_cast<uint8_t>(src[i]) ^ derive_byte(Idx, i % 8, mix(0xAAAA));
            b ^= static_cast<uint8_t>(var_mask + (i & 0x0F));
            encrypted[i] = static_cast<char>(b);
        }
    }

    const char* decrypt() noexcept {
        if (!decrypted) {
#if STEALTHLIB_SSE2_DECRYPT && (defined(__SSE2__) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2) || defined(_M_X64))
            if constexpr (N >= 32) {
                constexpr uint8_t mask_table[16] = {
                    0xA5,0xB6,0xC7,0xD8, 0xE9,0xFA,0x0B,0x1C,
                    0x2D,0x3E,0x4F,0x50, 0x61,0x72,0x83,0x94
                };
                constexpr uint8_t var_mask = mask_table[STEALTH_BUILD_KEY % 16];
                constexpr uint8_t ks[16] = {
                    static_cast<uint8_t>(var_mask + 0)  ^ derive_byte(Idx, 0, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 1)  ^ derive_byte(Idx, 1, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 2)  ^ derive_byte(Idx, 2, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 3)  ^ derive_byte(Idx, 3, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 4)  ^ derive_byte(Idx, 4, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 5)  ^ derive_byte(Idx, 5, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 6)  ^ derive_byte(Idx, 6, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 7)  ^ derive_byte(Idx, 7, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 8)  ^ derive_byte(Idx, 0, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 9)  ^ derive_byte(Idx, 1, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 10) ^ derive_byte(Idx, 2, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 11) ^ derive_byte(Idx, 3, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 12) ^ derive_byte(Idx, 4, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 13) ^ derive_byte(Idx, 5, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 14) ^ derive_byte(Idx, 6, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 15) ^ derive_byte(Idx, 7, mix(0xAAAA)),
                };
                const __m128i k = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ks));
                size_t i = 0;
                for (; i + 16 <= N; i += 16) {
                    __m128i v  = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&encrypted[i]));
                    __m128i r  = _mm_xor_si128(v, k);
                    _mm_storeu_si128(reinterpret_cast<__m128i*>(&buffer[i]), r);
                }
                constexpr uint8_t mask_table_t[16] = {
                    0xA5,0xB6,0xC7,0xD8, 0xE9,0xFA,0x0B,0x1C,
                    0x2D,0x3E,0x4F,0x50, 0x61,0x72,0x83,0x94
                };
                constexpr uint8_t var_mask_t = mask_table_t[STEALTH_BUILD_KEY % 16];
                for (; i < N; ++i) {
                    uint8_t b = static_cast<uint8_t>(encrypted[i])
                              ^ static_cast<uint8_t>(var_mask_t + (i & 0x0F));
                    b ^= derive_byte(Idx, i % 8, mix(0xAAAA));
                    buffer[i] = static_cast<char>(b);
                }
                buffer[N] = '\0';
                decrypted = true;
                return buffer;
            }
#endif
            constexpr uint8_t mask_table[16] = {
                0xA5,0xB6,0xC7,0xD8, 0xE9,0xFA,0x0B,0x1C,
                0x2D,0x3E,0x4F,0x50, 0x61,0x72,0x83,0x94
            };
            constexpr uint8_t var_mask = mask_table[STEALTH_BUILD_KEY % 16];
            for (size_t i = 0; i < N; ++i) {
                uint8_t b = static_cast<uint8_t>(encrypted[i])
                          ^ static_cast<uint8_t>(var_mask + (i & 0x0F));
                b ^= derive_byte(Idx, i % 8, mix(0xAAAA));
                buffer[i] = static_cast<char>(b);
            }
            buffer[N] = '\0';
            decrypted = true;
        }
        return buffer;
    }

#if defined(__GNUC__) && __GNUC__ >= 14
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdangling-pointer"
#endif

    void reencrypt() noexcept {
        if (decrypted) {
#if STEALTHLIB_SSE2_DECRYPT && (defined(__SSE2__) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2) || defined(_M_X64))
            if constexpr (N >= 32) {
                constexpr uint8_t mask_table[16] = {
                    0xA5,0xB6,0xC7,0xD8, 0xE9,0xFA,0x0B,0x1C,
                    0x2D,0x3E,0x4F,0x50, 0x61,0x72,0x83,0x94
                };
                constexpr uint8_t var_mask = mask_table[STEALTH_BUILD_KEY % 16];
                constexpr uint8_t ks[16] = {
                    static_cast<uint8_t>(var_mask + 0)  ^ derive_byte(Idx, 0, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 1)  ^ derive_byte(Idx, 1, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 2)  ^ derive_byte(Idx, 2, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 3)  ^ derive_byte(Idx, 3, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 4)  ^ derive_byte(Idx, 4, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 5)  ^ derive_byte(Idx, 5, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 6)  ^ derive_byte(Idx, 6, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 7)  ^ derive_byte(Idx, 7, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 8)  ^ derive_byte(Idx, 0, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 9)  ^ derive_byte(Idx, 1, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 10) ^ derive_byte(Idx, 2, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 11) ^ derive_byte(Idx, 3, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 12) ^ derive_byte(Idx, 4, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 13) ^ derive_byte(Idx, 5, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 14) ^ derive_byte(Idx, 6, mix(0xAAAA)),
                    static_cast<uint8_t>(var_mask + 15) ^ derive_byte(Idx, 7, mix(0xAAAA)),
                };
                const __m128i k = _mm_loadu_si128(reinterpret_cast<const __m128i*>(ks));
                size_t i = 0;
                for (; i + 16 <= N; i += 16) {
                    __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&buffer[i]));
                    __m128i r = _mm_xor_si128(v, k);
                    _mm_storeu_si128(reinterpret_cast<__m128i*>(&encrypted[i]), r);
                }
                constexpr uint8_t mask_table_t[16] = {
                    0xA5,0xB6,0xC7,0xD8, 0xE9,0xFA,0x0B,0x1C,
                    0x2D,0x3E,0x4F,0x50, 0x61,0x72,0x83,0x94
                };
                constexpr uint8_t var_mask_t = mask_table_t[STEALTH_BUILD_KEY % 16];
                for (; i < N; ++i) {
                    uint8_t ch = static_cast<uint8_t>(buffer[i]);
                    ch ^= derive_byte(Idx, i % 8, mix(0xAAAA));
                    ch ^= static_cast<uint8_t>(var_mask_t + (i & 0x0F));
                    encrypted[i] = static_cast<char>(ch);
                }
                for (size_t j = 0; j < N + 1; ++j) {
                    reinterpret_cast<volatile char*>(&buffer[j])[0] = 0;
                }
                decrypted = false;
                return;
            }
#endif
            constexpr uint8_t mask_table[16] = {
                0xA5,0xB6,0xC7,0xD8, 0xE9,0xFA,0x0B,0x1C,
                0x2D,0x3E,0x4F,0x50, 0x61,0x72,0x83,0x94
            };
            constexpr uint8_t var_mask = mask_table[STEALTH_BUILD_KEY % 16];
            for (size_t i = 0; i < N; ++i) {
                uint8_t ch = static_cast<uint8_t>(buffer[i]);
                ch ^= derive_byte(Idx, i % 8, mix(0xAAAA));
                ch ^= static_cast<uint8_t>(var_mask + (i & 0x0F));
                encrypted[i] = static_cast<char>(ch);
            }
            for (size_t i = 0; i < N + 1; ++i) {
                reinterpret_cast<volatile char*>(&buffer[i])[0] = 0;
            }
            decrypted = false;
        }
    }

#if defined(__GNUC__) && __GNUC__ >= 14
#pragma GCC diagnostic pop
#endif
};

template<size_t N, size_t Idx>
struct encrypted_wstring_impl {
    wchar_t encrypted[N]{};
    wchar_t buffer[N + 1]{};
    bool decrypted{false};

    template<size_t M>
    consteval encrypted_wstring_impl(const wchar_t (&src)[M]) noexcept
        : decrypted(false) {
        static_assert(M == N + 1, "StealthLib: literal length mismatch");
        constexpr uint16_t wmask_table[16] = {
            0xA5A5,0xB6B6,0xC7C7,0xD8D8, 0xE9E9,0xFAFA,0x0B0B,0x1C1C,
            0x2D2D,0x3E3E,0x4F4F,0x5050, 0x6161,0x7272,0x8383,0x9494
        };
        constexpr uint16_t var_mask = wmask_table[STEALTH_BUILD_KEY % 16];
        for (size_t i = 0; i < N; ++i) {
            uint32_t ch = static_cast<uint32_t>(src[i]);
            uint32_t k  = derive_byte(Idx, i % 4, mix(0xBBBB));
            uint32_t km = static_cast<uint32_t>(var_mask) + (i & 0x0F);
            ch ^= k ^ km;
            encrypted[i] = static_cast<wchar_t>(ch);
        }
    }

    const wchar_t* decrypt() noexcept {
        if (!decrypted) {
            constexpr uint16_t wmask_table[16] = {
                0xA5A5,0xB6B6,0xC7C7,0xD8D8, 0xE9E9,0xFAFA,0x0B0B,0x1C1C,
                0x2D2D,0x3E3E,0x4F4F,0x5050, 0x6161,0x7272,0x8383,0x9494
            };
            constexpr uint16_t var_mask = wmask_table[STEALTH_BUILD_KEY % 16];
            for (size_t i = 0; i < N; ++i) {
                uint32_t ch = static_cast<uint32_t>(encrypted[i]);
                uint32_t km = static_cast<uint32_t>(var_mask) + (i & 0x0F);
                ch ^= km;
                ch ^= derive_byte(Idx, i % 4, mix(0xBBBB));
                buffer[i] = static_cast<wchar_t>(ch);
            }
            buffer[N] = L'\0';
            decrypted = true;
        }
        return buffer;
    }

    void reencrypt() noexcept {
#if defined(__GNUC__) && __GNUC__ >= 14
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdangling-pointer"
#endif
        if (decrypted) {
            constexpr uint16_t wmask_table[16] = {
                0xA5A5,0xB6B6,0xC7C7,0xD8D8, 0xE9E9,0xFAFA,0x0B0B,0x1C1C,
                0x2D2D,0x3E3E,0x4F4F,0x5050, 0x6161,0x7272,0x8383,0x9494
            };
            constexpr uint16_t var_mask = wmask_table[STEALTH_BUILD_KEY % 16];
            for (size_t i = 0; i < N; ++i) {
                uint32_t ch = static_cast<uint32_t>(buffer[i]);
                ch ^= derive_byte(Idx, i % 4, mix(0xBBBB));
                ch ^= static_cast<uint32_t>(var_mask) + (i & 0x0F);
                encrypted[i] = static_cast<wchar_t>(ch);
            }
            for (size_t i = 0; i < N + 1; ++i) {
                reinterpret_cast<volatile wchar_t*>(&buffer[i])[0] = 0;
            }
            decrypted = false;
        }
#if defined(__GNUC__) && __GNUC__ >= 14
#pragma GCC diagnostic pop
#endif
    }
};

} // namespace stealth::detail

#endif // STEALTH_DETAIL_ENCRYPTION_HPP
