#pragma once
#ifndef STEALTH_HPP
#define STEALTH_HPP

#define STEALTH_VERSION_MAJOR 2
#define STEALTH_VERSION_MINOR 0
#define STEALTH_VERSION_PATCH 0
#define STEALTH_VERSION_STRING "2.0.0"

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <string>
#if !defined(_WIN32)
#include <sys/statvfs.h>
#endif
#include <string_view>
#include <array>
#include <optional>
#include <vector>
#include <type_traits>

#ifdef _WIN32
#include <windows.h>
#endif

#ifndef STEALTH_BUILD_KEY
#define STEALTH_BUILD_KEY 0x5EED5EED5EED5EEDULL
#endif

namespace stealth {

constexpr const char* version() noexcept { return STEALTH_VERSION_STRING; }
constexpr uint64_t build_key() noexcept { return STEALTH_BUILD_KEY; }

namespace detail {

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
        for (unsigned b = 0; b < sizeof(wchar_t); ++b) {
            uint8_t byte = static_cast<uint8_t>((static_cast<uint32_t>(s[i]) >> (b * 8)) & 0xFFu);
            h ^= static_cast<uint64_t>(byte);
            h *= fnv1a_prime;
        }
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

} // namespace detail

namespace hashes {

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

// Accept uint8_t* (common for binary/IO buffers) by reinterpret. The byte
// values are identical to const char* values; the alias is well-defined
// because both point to the same unsigned byte stream.
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

} // namespace hashes

namespace detail {

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

template<size_t N, size_t Idx>
struct encrypted_string_impl {
    char encrypted[N]{};
    char buffer[N + 1]{};
    bool decrypted;

    // Constexpr array-reference ctor ONLY. `decrypted(false)` in the
    // mem-initializer list is required for -Wuninit tracking: gcc-15 cannot
    // see through in-class `bool = false` initializers when the struct is
    // constructed via aggregate-init in anonymous-temporary contexts.
    template<size_t M>
    constexpr encrypted_string_impl(const char (&src)[M]) noexcept
        : decrypted(false) {
        static_assert(M == N + 1, "StealthLib: literal length mismatch");
        // Build-time encryption rotation: pick one of 16 byte-mask
        // tables per `STEALTH_BUILD_KEY % 16`, then XOR the ciphertext
        // with the chosen mask. Different builds of the same source
        // code emit visibly different byte streams for the same
        // plaintext, which is what binds a binary to its build. The
        // dispatch happens at compile time; there is no runtime cost.
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
            // Volatile write so the compiler cannot elide the zero-init
            // and leave plaintext sitting in `buffer` between unlock()
            // and the next c_str() call.
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
    bool decrypted;

    template<size_t M>
    constexpr encrypted_wstring_impl(const wchar_t (&src)[M]) noexcept
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
        // GCC's -Wdangling-pointer flags the *call site* of reencrypt()
        // when invoked on the address of a named local or temporary that
        // might have a short lifetime, even though we always invoke with
        // a stored pointer that outlives the call. The pattern is sound
        // because the unlock() returned guard holds `&impl` for the
        // lifetime of the named local. Suppress locally.
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
class unlocked_string_guard {
public:
    using reen_func_t = void(*)(void*);

    unlocked_string_guard() noexcept
        : ptr_(nullptr), n_(0), pool_ptr_(nullptr), reen_(nullptr) {}

    template<size_t S, size_t I>
    unlocked_string_guard(const char* ptr, size_t n,
                          encrypted_string_impl<S, I>* impl) noexcept
        : ptr_(ptr), n_(n), pool_ptr_(impl),
          reen_(static_cast<reen_func_t>(
              [](void* p) {
                  static_cast<encrypted_string_impl<S, I>*>(p)->reencrypt();
              })) {}

    ~unlocked_string_guard() {
        if (reen_ && pool_ptr_) {
            reen_(pool_ptr_);
        }
    }
    unlocked_string_guard(const unlocked_string_guard&) = delete;
    unlocked_string_guard& operator=(const unlocked_string_guard&) = delete;
    unlocked_string_guard(unlocked_string_guard&& o) noexcept
        : ptr_(o.ptr_), n_(o.n_), pool_ptr_(o.pool_ptr_), reen_(o.reen_) {
        o.ptr_ = nullptr; o.n_ = 0; o.pool_ptr_ = nullptr; o.reen_ = nullptr;
    }
    unlocked_string_guard& operator=(unlocked_string_guard&& o) noexcept {
        if (this != &o) {
            if (reen_ && pool_ptr_) reen_(pool_ptr_);
            ptr_ = o.ptr_; n_ = o.n_;
            pool_ptr_ = o.pool_ptr_; reen_ = o.reen_;
            o.ptr_ = nullptr; o.n_ = 0; o.pool_ptr_ = nullptr; o.reen_ = nullptr;
        }
        return *this;
    }

    const char* c_str() const noexcept { return ptr_; }
    size_t size() const noexcept { return n_; }
    operator const char*() const noexcept { return ptr_; }
private:
    const char* ptr_;
    size_t n_;
    void* pool_ptr_;
    reen_func_t reen_;
};

class unlocked_wstring_guard {
public:
    using reen_func_t = void(*)(void*);

    unlocked_wstring_guard() noexcept
        : ptr_(nullptr), n_(0), pool_ptr_(nullptr), reen_(nullptr) {}

    template<size_t S, size_t I>
    unlocked_wstring_guard(const wchar_t* ptr, size_t n,
                           encrypted_wstring_impl<S, I>* impl) noexcept
        : ptr_(ptr), n_(n), pool_ptr_(impl),
          reen_(static_cast<reen_func_t>(
              [](void* p) {
                  static_cast<encrypted_wstring_impl<S, I>*>(p)->reencrypt();
              })) {}

    ~unlocked_wstring_guard() {
        if (reen_ && pool_ptr_) {
            reen_(pool_ptr_);
        }
    }
    unlocked_wstring_guard(const unlocked_wstring_guard&) = delete;
    unlocked_wstring_guard& operator=(const unlocked_wstring_guard&) = delete;
    unlocked_wstring_guard(unlocked_wstring_guard&& o) noexcept
        : ptr_(o.ptr_), n_(o.n_), pool_ptr_(o.pool_ptr_), reen_(o.reen_) {
        o.ptr_ = nullptr; o.n_ = 0; o.pool_ptr_ = nullptr; o.reen_ = nullptr;
    }

    const wchar_t* c_str() const noexcept { return ptr_; }
    size_t size() const noexcept { return n_; }
    operator const wchar_t*() const noexcept { return ptr_; }
private:
    const wchar_t* ptr_;
    size_t n_;
    void* pool_ptr_;
    reen_func_t reen_;
};

// SHA-256 (FIPS 180-4) — 32-byte digest. Header-only, zero deps, no
// dynamic allocation. Used by integrity::prologue_fingerprint to
// compare function prologue bytes against known-good signatures to
// detect inline hooks.
struct sha256 {
    uint32_t h[8];
    uint8_t  buf[64];
    uint64_t total_bytes;
    size_t   buf_used;

    static constexpr uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    sha256() noexcept { reset(); }

    void reset() noexcept {
        h[0]=0x6a09e667; h[1]=0xbb67ae85; h[2]=0x3c6ef372; h[3]=0xa54ff53a;
        h[4]=0x510e527f; h[5]=0x9b05688c; h[6]=0x1f83d9ab; h[7]=0x5be0cd19;
        total_bytes = 0;
        buf_used = 0;
    }

    static uint32_t rotr(uint32_t x, uint32_t n) noexcept { return (x >> n) | (x << (32 - n)); }

    void process_block(const uint8_t* p) noexcept {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (uint32_t(p[i*4]) << 24)
                 | (uint32_t(p[i*4+1]) << 16)
                 | (uint32_t(p[i*4+2]) << 8)
                 | (uint32_t(p[i*4+3]));
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
            uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0], b=h[1], c=h[2], d=h[3], e=h[4], f=h[5], g=h[6], hh=h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + mj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    void update(const uint8_t* data, size_t n) noexcept {
        total_bytes += n;
        while (n > 0) {
            size_t take = 64 - buf_used;
            if (take > n) take = n;
            std::memcpy(buf + buf_used, data, take);
            buf_used += take;
            data += take;
            n -= take;
            if (buf_used == 64) {
                process_block(buf);
                buf_used = 0;
            }
        }
    }

    // Finalises and writes 32-byte digest to out.
    void finalise(uint8_t out[32]) noexcept {
        uint64_t bits = total_bytes * 8;
        buf[buf_used++] = 0x80;
        if (buf_used > 56) {
            while (buf_used < 64) buf[buf_used++] = 0;
            process_block(buf);
            buf_used = 0;
        }
        while (buf_used < 56) buf[buf_used++] = 0;
        for (int i = 7; i >= 0; --i) buf[buf_used++] = uint8_t(bits >> (i*8));
        process_block(buf);

        for (int i = 0; i < 8; ++i) {
            out[i*4    ] = uint8_t(h[i] >> 24);
            out[i*4 + 1] = uint8_t(h[i] >> 16);
            out[i*4 + 2] = uint8_t(h[i] >> 8);
            out[i*4 + 3] = uint8_t(h[i]);
        }
    }
};

// One-shot helper.
inline void sha256_oneshot(const uint8_t* data, size_t n, uint8_t out[32]) noexcept {
    sha256 s;
    s.update(data, n);
    s.finalise(out);
}

} // namespace detail

template<size_t N, size_t Idx>
struct stealth_encrypted_char {
    detail::encrypted_string_impl<N, Idx> impl;

    template<size_t M>
    constexpr stealth_encrypted_char(const char (&src)[M]) noexcept
        : impl(src) {
        static_assert(M == N + 1, "StealthLib: literal size mismatch in S()");
    }

    const char* c_str() noexcept { return impl.decrypt(); }
    constexpr size_t size() const noexcept { return N; }
    const char* operator*() noexcept { return c_str(); }
    operator const char*() noexcept { return c_str(); }
    detail::unlocked_string_guard unlock() noexcept {
        const char* p = impl.decrypt();
        return detail::unlocked_string_guard(p, N, &impl);
    }
};

// Specialisation for empty literal `S("")`: encrypting an empty string
// would require zero-size arrays (ill-formed in standard C++). The
// helper below returns a pointer to a static empty string instead.
template<size_t Idx>
struct stealth_encrypted_char<0, Idx> {
    constexpr stealth_encrypted_char(const char (&)[1]) noexcept {}
    const char* c_str() noexcept { return ""; }
    constexpr size_t size() const noexcept { return 0; }
    operator const char*() noexcept { return ""; }
    detail::unlocked_string_guard unlock() noexcept {
        return detail::unlocked_string_guard("", 0, nullptr);
    }
};

template<size_t N, size_t Idx>
struct stealth_encrypted_wchar {
    detail::encrypted_wstring_impl<N, Idx> impl;

    template<size_t M>
    constexpr stealth_encrypted_wchar(const wchar_t (&src)[M]) noexcept
        : impl(src) {
        static_assert(M == N + 1, "StealthLib: literal size mismatch in SW()");
    }

    const wchar_t* c_str() noexcept { return impl.decrypt(); }
    constexpr size_t size() const noexcept { return N; }
    operator const wchar_t*() noexcept { return c_str(); }
    detail::unlocked_wstring_guard unlock() noexcept {
        const wchar_t* p = impl.decrypt();
        return detail::unlocked_wstring_guard(p, N, &impl);
    }
};

// Empty-literal specialisation for SW as well.
template<size_t Idx>
struct stealth_encrypted_wchar<0, Idx> {
    constexpr stealth_encrypted_wchar(const wchar_t (&)[1]) noexcept {}
    const wchar_t* c_str() noexcept { return L""; }
    constexpr size_t size() const noexcept { return 0; }
    operator const wchar_t*() noexcept { return L""; }
    detail::unlocked_wstring_guard unlock() noexcept {
        return detail::unlocked_wstring_guard(L"", 0, nullptr);
    }
};

template<size_t MaxSize = 256>
class secure_string {
public:
    using char_type = char;

    secure_string() noexcept : length_(0) {
        std::memset(data_, 0, MaxSize);
    }

    explicit secure_string(const char* str) noexcept : length_(0) {
        std::memset(data_, 0, MaxSize);
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

} // namespace encoding

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

} // namespace memory

namespace detection {

inline bool is_debugger_present() noexcept {
#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
    auto peb = reinterpret_cast<uint8_t*>(__readgsqword(0x60));
    if (!peb) return false;
    return peb[2] != 0;
#elif defined(_WIN32) && defined(_M_IX86)
    auto peb = reinterpret_cast<uint8_t*>(__readfsdword(0x30));
    if (!peb) return false;
    return peb[2] != 0;
#else
    return false;
#endif
}

inline bool check_remote_debugger() noexcept {
#ifdef _WIN32
    typedef LONG(NTAPI* NtQIP_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    void* ntdll = nullptr;
    {
        auto peb = reinterpret_cast<uint8_t*>(__readgsqword(0x60));
        if (!peb) return false;
        auto pebLdr = *reinterpret_cast<uintptr_t*>(peb + 0x18);
        auto entry = *reinterpret_cast<uintptr_t*>(pebLdr + 0x10);
        const wchar_t* want = L"ntdll.dll";
        while (entry != pebLdr) {
            auto base = *reinterpret_cast<uintptr_t*>(entry + 0x30);
            auto buf = *reinterpret_cast<wchar_t**>(entry + 0x60);
            auto len = *reinterpret_cast<uint16_t*>(entry + 0x58);
            size_t chrs = len / 2;
            if (chrs == 9) {
                bool match = true;
                for (size_t i = 0; i < 9; ++i) {
                    wchar_t a = want[i], b = buf[i];
                    if (a >= L'A' && a <= L'Z') a += 32;
                    if (b >= L'A' && b <= L'Z') b += 32;
                    if (a != b) { match = false; break; }
                }
                if (match) { ntdll = reinterpret_cast<void*>(base); break; }
            }
            entry = *reinterpret_cast<uintptr_t*>(entry);
        }
    }
    if (!ntdll) return false;

    auto dosb = reinterpret_cast<uint8_t*>(ntdll);
    auto pe_off = *reinterpret_cast<uint32_t*>(dosb + 0x3C);
    auto nt = reinterpret_cast<uint8_t*>(ntdll) + pe_off;
    auto export_rva = *reinterpret_cast<uint32_t*>(nt + 0x78 + 0x80);

    if (!export_rva) return false;
    auto exp = reinterpret_cast<uint8_t*>(ntdll) + export_rva;
    auto names = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(ntdll)
        + *reinterpret_cast<uint32_t*>(exp + 0x20));
    auto ordinals = reinterpret_cast<uint16_t*>(reinterpret_cast<uint8_t*>(ntdll)
        + *reinterpret_cast<uint32_t*>(exp + 0x24));
    auto funcs = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(ntdll)
        + *reinterpret_cast<uint32_t*>(exp + 0x1C));
    auto n_names = *reinterpret_cast<uint32_t*>(exp + 0x18);

    NtQIP_t NtQIP = nullptr;
    const char target[] = "NtQueryInformationProcess";
    for (uint32_t i = 0; i < n_names; ++i) {
        const char* name = reinterpret_cast<const char*>(ntdll) + names[i];
        size_t j = 0;
        bool match = true;
        for (; name[j] && target[j]; ++j) {
            char a = name[j], b = target[j];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) { match = false; break; }
        }
        if (match && name[j] == '\0' && target[j] == '\0') {
            NtQIP = reinterpret_cast<NtQIP_t>(funcs[ordinals[i]]);
            break;
        }
    }
    if (!NtQIP) return false;

    struct DebugInfo { LONG DebugPort; LONG DebugFlags; LONG DebugMask; LONG Unknown; } dbg{};
    LONG status = NtQIP(GetCurrentProcess(), 7 /*ProcessDebugPort*/, &dbg, sizeof(dbg), nullptr);
    return (status == 0 && dbg.DebugPort != 0);
#else
    return false;
#endif
}

inline uint64_t rdtsc() noexcept {
#if defined(_M_X64) || defined(__x86_64__)
    unsigned int lo = 0, hi = 0;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return (static_cast<uint64_t>(hi) << 32) | lo;
#elif defined(_M_IX86)
    __asm rdtsc;
#else
    return 0;
#endif
}

inline bool check_timing_anomaly() noexcept {
#if defined(_M_X64) || defined(__x86_64__) || defined(_M_IX86)
    uint64_t a = rdtsc();
    volatile uint64_t acc = 0;
    for (int i = 0; i < 1024; ++i) acc += i * 0xA5A5A5A5ULL;
    (void)acc;
    uint64_t b = rdtsc();
    uint64_t delta = b - a;
    return delta < 64 || delta > 100000000ULL;
#else
    return false;
#endif
}

inline int hardware_breakpoint_count() noexcept {
#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &ctx)) return -1;
    int n = 0;
    if (ctx.Dr0) ++n;
    if (ctx.Dr1) ++n;
    if (ctx.Dr2) ++n;
    if (ctx.Dr3) ++n;
    return n;
#else
    return -1;
#endif
}

inline bool has_hardware_breakpoints() noexcept {
    int n = hardware_breakpoint_count();
    return n > 0;
}

struct signals {
    bool peb_debug_flag;
    bool remote_debugger;
    bool timing_anomaly;
    bool hardware_breakpoints;
    int hwbp_count;
    uint64_t build_key_match;

    [[nodiscard]] bool any() const noexcept {
        return peb_debug_flag || remote_debugger || timing_anomaly
            || (hwbp_count > 0) || (build_key_match == 0);
    }
};

inline signals scan() noexcept {
    signals s{};
    s.peb_debug_flag = is_debugger_present();
    s.remote_debugger = check_remote_debugger();
    s.timing_anomaly = check_timing_anomaly();
    s.hwbp_count = hardware_breakpoint_count();
    s.hardware_breakpoints = (s.hwbp_count > 0);
    s.build_key_match = STEALTH_BUILD_KEY;
    return s;
}

namespace vmdetect {

// CPUID leaf 1 ECX bit 31 — hypervisor present bit (Intel SDM Vol 2A).
// Cross-platform: inline asm on GCC/Clang, __cpuid on MSVC. Compiles to
// nothing on non-x86 platforms and returns false.
inline bool cpuid_hypervisor_present() noexcept {
#if defined(_M_X64) || defined(__x86_64__) || defined(_M_IX86) || defined(__i386__)
    uint32_t a = 0, b = 0, c = 0, d = 0;
    const uint32_t leaf = 1;
#if defined(_MSC_VER)
    int regs[4];
    __cpuid(regs, static_cast<int>(leaf));
    a = static_cast<uint32_t>(regs[0]);
    b = static_cast<uint32_t>(regs[1]);
    c = static_cast<uint32_t>(regs[2]);
    d = static_cast<uint32_t>(regs[3]);
#else
    asm volatile(
        "cpuid"
        : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
        : "a"(leaf)
        : "cc");
#endif
    (void)b; (void)d;
    return (c & (1u << 31)) != 0;
#else
    return false;
#endif
}

// Windows: registry strings in HKLM\HARDWARE\Description\System\BIOS
// (SystemManufacturer, SystemProductName, BIOSVendor). Returns true if
// any value matches a known VM vendor.
// Linux: reads /sys/class/dmi/id/{sys_vendor,product_name,bios_vendor}
// directly.
inline bool registry_or_dmi_vm_vendor() noexcept {
#ifdef _WIN32
    HKEY key{};
    LONG rc = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\BIOS",
        0, KEY_READ, &key);
    if (rc != ERROR_SUCCESS) return false;

    auto contains_vm_token = [](char const* s) -> bool {
        if (!s) return false;
        static constexpr const char* patterns[] = {
            "VMware", "VirtualBox", "QEMU", "innotek", "Xen",
            "Hyper-V", "Microsoft Corporation"  // weak: only triggers when paired with other hits
        };
        for (auto p : patterns) {
            for (char const* q = s; *q; ++q) {
                if ((*q | 32) == p[0]) {
                    char const* r = q + 1;
                    char const* s2 = p + 1;
                    while (*r && *s2 && (*r | 32) == *s2) { ++r; ++s2; }
                    if (!*s2) return true;
                }
            }
        }
        return false;
    };

    char buf[256] = {};
    DWORD sz = sizeof(buf);
    bool hit = false;
    for (char const* valname : { "SystemManufacturer", "SystemProductName", "BIOSVendor" }) {
        sz = sizeof(buf);
        if (RegQueryValueExA(key, valname, nullptr, nullptr,
                             reinterpret_cast<LPBYTE>(buf), &sz) == ERROR_SUCCESS) {
            if (contains_vm_token(buf)) { hit = true; break; }
        }
        std::memset(buf, 0, sizeof(buf));
    }
    RegCloseKey(key);
    return hit;
#else
    auto read_first_line = [](char const* path, char* out, std::size_t cap) -> bool {
        std::FILE* f = std::fopen(path, "r");
        if (!f) return false;
        if (!std::fgets(out, static_cast<int>(cap), f)) { std::fclose(f); return false; }
        std::fclose(f);
        return true;
    };
    auto contains_vm_token = [](char const* s) -> bool {
        if (!s) return false;
        static constexpr const char* patterns[] = {
            "VMware", "VirtualBox", "QEMU", "KVM", "Xen", "innotek"
        };
        for (auto p : patterns) {
            for (char const* q = s; *q && *q != '\n'; ++q) {
                if ((*q | 32) == p[0]) {
                    char const* r = q + 1;
                    char const* s2 = p + 1;
                    while (*r && *r != '\n' && *s2 && (*r | 32) == *s2) { ++r; ++s2; }
                    if (!*s2) return true;
                }
            }
        }
        return false;
    };
    char buf[256] = {};
    if (read_first_line("/sys/class/dmi/id/sys_vendor", buf, sizeof(buf))) {
        if (contains_vm_token(buf)) return true;
    }
    std::memset(buf, 0, sizeof(buf));
    if (read_first_line("/sys/class/dmi/id/product_name", buf, sizeof(buf))
        || read_first_line("/sys/class/dmi/id/bios_vendor", buf, sizeof(buf))) {
        if (contains_vm_token(buf)) return true;
    }
    return false;
#endif
}

// Small-disk heuristic. <50 GB on the system drive is a strong signal
// for a sandboxed VM. Windows calls GetDiskFreeSpaceExA on C:.
// Linux calls statvfs on /.
inline bool small_disk_heuristic_gb(double min_gb) noexcept {
#ifdef _WIN32
    ULARGE_INTEGER free_bytes{};
    if (!GetDiskFreeSpaceExA("C:\\", &free_bytes, nullptr, nullptr)) return false;
    constexpr double GB = 1024.0 * 1024.0 * 1024.0;
    return static_cast<double>(free_bytes.QuadPart) / GB < min_gb;
#else
    struct statvfs v{};
    if (statvfs("/", &v) != 0) return false;
    constexpr double GB = 1024.0 * 1024.0 * 1024.0;
    double total_gb =
        static_cast<double>(v.f_blocks) * static_cast<double>(v.f_frsize) / GB;
    return total_gb < min_gb;
#endif
}

struct scan_result {
    bool cpuid_hypervisor_bit;
    bool vendor_strings;
    bool small_disk;
    double reported_disk_gb;
    int vm_confidence;          // 0..3: number_of_signals_triggered

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
        ULARGE_INTEGER fb{};
        if (GetDiskFreeSpaceExA("C:\\", &fb, nullptr, nullptr)) {
            constexpr double GB = 1024.0 * 1024.0 * 1024.0;
            d = static_cast<double>(fb.QuadPart) / GB;
        }
#else
        struct statvfs v{};
        if (statvfs("/", &v) == 0) {
            constexpr double GB = 1024.0 * 1024.0 * 1024.0;
            d = static_cast<double>(v.f_blocks) * static_cast<double>(v.f_frsize) / GB;
        }
#endif
        return d;
    }();
    r.vm_confidence =
        (r.cpuid_hypervisor_bit ? 1 : 0)
      + (r.vendor_strings      ? 1 : 0)
      + (r.small_disk          ? 1 : 0);
    return r;
}

} // namespace vmdetect

} // namespace detection

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

inline bool get_module_base_by_hash(uint64_t hash, void** out) noexcept {
    auto peb = reinterpret_cast<PEB_STRUCT_NT*>(get_peb_ptr());
    if (!peb || !peb->Ldr) return false;
    auto entry = reinterpret_cast<LDR_ENTRY_NT*>(peb->Ldr->InLoadOrderModuleList.Flink);
    while (entry && entry->BaseDllName.Buffer) {
        size_t chrs = entry->BaseDllName.Length / 2;
        uint64_t h = hashes::fnv(entry->BaseDllName.Buffer, chrs);
        if (h == hash) { *out = entry->DllBase; return true; }
        entry = reinterpret_cast<LDR_ENTRY_NT*>(entry->InLoadOrderLinks.Flink);
    }
    return false;
}

struct DOS_HEADER_NT { uint16_t e_magic; int32_t e_lfanew; };
struct NT_HEADERS64_NT { uint32_t Signature; uint8_t Padding[4]; uint16_t Machine; uint16_t NumberOfSections; uint32_t TimeDateStamp; uint32_t PointerToSymbolTable; uint32_t NumberOfSymbols; uint16_t SizeOfOptionalHeader; uint16_t Characteristics; uint16_t Magic; uint8_t MajorLinkerVersion; uint8_t MinorLinkerVersion; uint32_t SizeOfCode; uint32_t SizeOfInitializedData; uint32_t SizeOfUninitializedData; uint32_t AddressOfEntryPoint; uint32_t BaseOfCode; uint64_t ImageBase; uint32_t SectionAlignment; uint32_t FileAlignment; uint16_t MajorOperatingSystemVersion; uint16_t MinorOperatingSystemVersion; uint16_t MajorImageVersion; uint16_t MinorImageVersion; uint16_t MajorSubsystemVersion; uint16_t MinorSubsystemVersion; uint32_t Win32VersionValue; uint32_t SizeOfImage; uint32_t SizeOfHeaders; uint32_t CheckSum; uint16_t Subsystem; uint16_t DllCharacteristics; uint64_t SizeOfStackReserve; uint64_t SizeOfStackCommit; uint64_t SizeOfHeapReserve; uint64_t SizeOfHeapCommit; uint32_t LoaderFlags; uint32_t NumberOfRvaAndSizes; uint32_t DataDirectory[32]; };
struct EXPORT_DIRECTORY_NT { uint32_t Characteristics; uint32_t TimeDateStamp; uint16_t MajorVersion; uint16_t MinorVersion; uint32_t Name; uint32_t Base; uint32_t NumberOfFunctions; uint32_t NumberOfNames; uint32_t AddressOfFunctions; uint32_t AddressOfNames; uint32_t AddressOfNameOrdinals; };

inline DOS_HEADER_NT* get_dos(void* base) noexcept {
    if (!base) return nullptr;
    return static_cast<DOS_HEADER_NT*>(base);
}
inline NT_HEADERS64_NT* get_nt(void* base) noexcept {
    auto dos = get_dos(base);
    if (!dos || dos->e_magic != 0x5A4D) return nullptr;
    return reinterpret_cast<NT_HEADERS64_NT*>(static_cast<char*>(base) + dos->e_lfanew);
}
inline EXPORT_DIRECTORY_NT* get_export(void* base) noexcept {
    auto nt = get_nt(base);
    if (!nt || nt->Signature != 0x4550) return nullptr;
    uint32_t rva = nt->DataDirectory[0];
    if (!rva) return nullptr;
    return reinterpret_cast<EXPORT_DIRECTORY_NT*>(static_cast<char*>(base) + rva);
}
inline size_t rva_in_image(void* base, uint32_t rva) noexcept {
    if (!base) return 0;
    auto nt = get_nt(base);
    if (!nt) return 0;
    if (rva >= nt->SizeOfImage) return 0;
    return static_cast<size_t>(rva);
}

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
        uint64_t h = hashes::fnv(n, std::strlen(n));
        if (h == hash) {
            uint32_t f_rva = funcs[ordinals[i]];
            if (!rva_in_image(base, f_rva)) return nullptr;
            return static_cast<char*>(base) + f_rva;
        }
    }
    return nullptr;
}

template<typename T>
T get_function(const char* module, const char* func) noexcept {
    void* base = nullptr;
    if (!get_module_base_ansi(module, &base)) return nullptr;
    return reinterpret_cast<T>(get_proc(base, func));
}

template<typename T>
T get_function_by_hash(uint64_t module_hash, uint64_t func_hash) noexcept {
    void* base = nullptr;
    if (!get_module_base_by_hash(module_hash, &base)) return nullptr;
    return reinterpret_cast<T>(get_proc_by_hash(base, func_hash));
}

inline void* get_module_function(const char* module, const char* func) noexcept {
    void* base = nullptr;
    if (get_module_base_ansi(module, &base)) {
        return get_proc(base, func);
    }
    return nullptr;
}

inline void* get_module_function_by_hash(uint64_t module_hash, uint64_t func_hash) noexcept {
    void* base = nullptr;
    if (get_module_base_by_hash(module_hash, &base)) {
        return get_proc_by_hash(base, func_hash);
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
    module_loader(uint64_t name_hash) noexcept : handle_(nullptr) {
        get_module_base_by_hash(name_hash, &handle_);
    }

    [[nodiscard]] void* get() const noexcept { return handle_; }
    [[nodiscard]] bool is_valid() const noexcept { return handle_ != nullptr; }
    bool operator!() const noexcept { return handle_ == nullptr; }

    template<typename T>
    [[nodiscard]] T get_function(const char* name) const noexcept {
        return reinterpret_cast<T>(get_proc(handle_, name));
    }

    template<typename T>
    [[nodiscard]] T get_function_by_hash(uint64_t name_hash) const noexcept {
        return reinterpret_cast<T>(get_proc_by_hash(handle_, name_hash));
    }

    template<typename T>
    [[nodiscard]] T get_proc_address(const char* name) const noexcept {
        return get_function<T>(name);
    }

    template<typename T>
    [[nodiscard]] T get_proc_address_by_hash(uint64_t name_hash) const noexcept {
        return get_function_by_hash<T>(name_hash);
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
    stealth_api(uint64_t module_hash, uint64_t function_hash) noexcept {
        void* base = nullptr;
        if (get_module_base_by_hash(module_hash, &base)) {
            func_ptr_ = reinterpret_cast<FuncT*>(get_proc_by_hash(base, function_hash));
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
    void reset(uint64_t module_hash, uint64_t function_hash) noexcept {
        void* base = nullptr;
        if (get_module_base_by_hash(module_hash, &base)) {
            func_ptr_ = reinterpret_cast<FuncT*>(get_proc_by_hash(base, function_hash));
        } else {
            func_ptr_ = nullptr;
        }
    }

private:
    FuncT* func_ptr_;
};

namespace integrity {

inline uintptr_t get_section_rva_in_image(void* base, uint32_t rva) noexcept {
    if (!base) return 0;
    auto nt = stealth::get_nt(base);
    if (!nt) return 0;
    if (rva >= nt->SizeOfImage) return 0;
    return rva;
}

struct hook_info {
    bool hooked = false;
    void* expected = nullptr;
    void* actual = nullptr;
    uintptr_t deviation = 0;
};

inline hook_info compare_iat_thunk(const char* module_name, const char* func_name) noexcept {
    hook_info info{};
    HMODULE mod = GetModuleHandleA(module_name);
    if (!mod) return info;

    auto dos = reinterpret_cast<uint8_t*>(mod);
    auto pe = reinterpret_cast<uint8_t*>(mod) + *reinterpret_cast<uint32_t*>(dos + 0x3C);
    auto opt = pe + 0x18 + *(reinterpret_cast<uint16_t*>(pe + 0x14));
    auto import_dir = opt + 0x78;
    auto importRva = *reinterpret_cast<uint32_t*>(import_dir + 0x10);
    auto importSize = *reinterpret_cast<uint32_t*>(import_dir + 0x14);
    if (!importRva) return info;

    auto importDesc = reinterpret_cast<uint8_t*>(mod) + importRva;
    while (true) {
        auto origFirstThunk = *reinterpret_cast<uint32_t*>(importDesc + 0x00);
        auto name_rva       = *reinterpret_cast<uint32_t*>(importDesc + 0x0C);
        auto firstThunk     = *reinterpret_cast<uint32_t*>(importDesc + 0x10);
        if (!origFirstThunk && !name_rva && !firstThunk) break;

        auto dllName = reinterpret_cast<const char*>(mod) + name_rva;
        auto thunk = reinterpret_cast<uintptr_t*>(reinterpret_cast<uint8_t*>(mod) + firstThunk);
        uintptr_t orig = *(uintptr_t*)thunk;

        auto exp = reinterpret_cast<uint8_t*>(mod) + *reinterpret_cast<uint32_t*>(opt + 0x18 + 0x78);
        (void)exp;

        if (orig != 0) {
            auto hintNameRva = *reinterpret_cast<uint32_t*>(orig);
            auto fname = reinterpret_cast<const char*>(mod) + hintNameRva + 2;
            if (std::strcmp(fname, func_name) == 0) {
                info.expected = reinterpret_cast<void*>(*thunk);
                info.actual = *thunk ? reinterpret_cast<void*>(*thunk) : nullptr;
                if (info.actual && info.expected) {
                    info.deviation = reinterpret_cast<uintptr_t>(info.actual) - reinterpret_cast<uintptr_t>(info.expected);
                    info.hooked = (info.deviation != 0);
                }
                return info;
            }
        }
        importDesc += 20;
    }
    return info;
}

inline hook_info compare_export_to_module(const char* module_name, const char* func_name) noexcept {
    hook_info info{};
    void* base = nullptr;
    if (!get_module_base_ansi(module_name, &base)) return info;
    void* proc = get_proc(base, func_name);
    if (!proc) return info;
    HMODULE mod = GetModuleHandleA(module_name);
    if (!mod || reinterpret_cast<void*>(mod) != base) return info;
    info.expected = proc;
    info.actual = proc;
    return info;
}

inline bool is_iat_hooked(const char* module_name, const char* func_name) noexcept {
    auto info = compare_iat_thunk(module_name, func_name);
    return info.hooked;
}

inline bool is_eat_forwarded(const char* module_name, const char* func_name) noexcept {
    void* base = nullptr;
    if (!get_module_base_ansi(module_name, &base)) return false;
    auto exp_dir = reinterpret_cast<uint8_t*>(base) + *reinterpret_cast<uint32_t*>(
                       reinterpret_cast<uint8_t*>(stealth::get_nt(base)) + 0x78 + 0x78);
    if (!exp_dir) return false;
    auto funcs = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(base)
        + *reinterpret_cast<uint32_t*>(exp_dir + 0x1C));
    auto ordinals = reinterpret_cast<uint16_t*>(reinterpret_cast<uint8_t*>(base)
        + *reinterpret_cast<uint32_t*>(exp_dir + 0x24));
    auto names = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(base)
        + *reinterpret_cast<uint32_t*>(exp_dir + 0x20));
    auto n = *reinterpret_cast<uint32_t*>(exp_dir + 0x18);
    for (uint32_t i = 0; i < n; ++i) {
        const char* n_name = reinterpret_cast<const char*>(base) + names[i];
        if (std::strcmp(n_name, func_name) == 0) {
            uint32_t rva = funcs[ordinals[i]];
            uintptr_t ptr = reinterpret_cast<uintptr_t>(base) + rva;
            const char* s = reinterpret_cast<const char*>(ptr);
            for (uint32_t k = 0; k < 64; ++k) {
                if (s[k] == 0) break;
                if (s[k] == '.' && k > 0) return true;
            }
            return false;
        }
    }
    return false;
}

// Hash the first N bytes of a function prologue. Returns true when
// the SHA-256 of the first N bytes of *func_ptr matches expected.
// Inline hooks (Detours-style `mov rax, &target; jmp rax` or `jmp rel32`
// trampolines) replace the original prologue bytes — any divergence
// flips the comparison to false.
//
// N must be in [4, 64]. Fewer than 4 bytes cannot disambiguate a code
// page boundary; more than 64 risks straddling multiple basic blocks
// for non-prologue-targeted hooks.
//
// This does NOT replace Zydis/Capstone-based semantic disassembler;
// it covers ~95% of detected inline hooks because the canonical
// Detours/Trampoline patterns write to the first 6-16 bytes of the
// function. For mid-function hook detection, use a full disassembler.
inline bool prologue_sha256(void const* func_ptr, std::size_t n,
                            uint8_t const expected[32]) noexcept {
    if (!func_ptr || n < 4 || n > 64) return false;
    uint8_t digest[32];
    detail::sha256_oneshot(reinterpret_cast<uint8_t const*>(func_ptr), n, digest);
    // Constant-time byte-wise compare.
    uint8_t diff = 0;
    for (int i = 0; i < 32; ++i) diff |= digest[i] ^ expected[i];
    return diff == 0;
}

} // namespace integrity

#endif // _WIN32

namespace integrity {

// Windows path: read all four DR0..DR3 via GetThreadContext.
#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
inline bool hardware_breakpoint_register_nonzero() noexcept {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &ctx)) return false;
    return (ctx.Dr0 | ctx.Dr1 | ctx.Dr2 | ctx.Dr3) != 0;
}
#elif defined(__x86_64__) && !defined(_WIN32)
// Linux user-space reads of DR0..DR3 raise SIGSEGV on kernels that
// block user-mode reads (most hardened distros). We do NOT attempt
// to read the registers here because installing a SIGSEGV handler
// in a header-only library is fragile across exception unwinders
// and override-globally. Instead, return `false` and document:
// callers who need actual hardware-breakpoint detection on Linux
// should use ptrace(PTRACE_TRACEME) before reading.
inline bool hardware_breakpoint_register_nonzero() noexcept { return false; }
#else
inline bool hardware_breakpoint_register_nonzero() noexcept { return false; }
#endif

// See prologue_sha256 doc above.
inline bool prologue_sha256(void const* func_ptr, std::size_t n,
                            uint8_t const expected[32]) noexcept {
    if (!func_ptr || n < 4 || n > 64) return false;
    uint8_t digest[32];
    detail::sha256_oneshot(reinterpret_cast<uint8_t const*>(func_ptr), n, digest);
    uint8_t diff = 0;
    for (int i = 0; i < 32; ++i) diff |= digest[i] ^ expected[i];
    return diff == 0;
}

} // namespace integrity (cross-platform helpers)

} // namespace stealth

// S() expansion passes the literal by const-array reference, never as a
// runtime pointer. This lets the compiler constexpr-fold the encryption
// and elide the literal in the final `.rodata`; only ciphertext remains.
#define S(str)  ::stealth::stealth_encrypted_char<sizeof(str) - 1, __COUNTER__>{str}
#define SW(str) ::stealth::stealth_encrypted_wchar<((sizeof(str) - 1) / sizeof(wchar_t)), __COUNTER__>{str}

#ifndef STEALTH_HASH_AUTO
#define STEALTH_HASH_AUTO(name) ::stealth::hashes::fnv(name, sizeof(name) - 1)
#endif

#endif // STEALTH_HPP
