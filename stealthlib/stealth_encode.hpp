#pragma once
#ifndef STEALTH_ENCODE_HPP
#define STEALTH_ENCODE_HPP

#include <cstdint>
#include <cstddef>
#include <array>
#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <optional>

namespace stealth {
namespace encode {

namespace detail {

constexpr uint8_t default_base64_alphabet[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

constexpr uint8_t default_base64_decode[256] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 62,  0xFF, 0xFF, 0xFF, 63,
    52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0,   1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,
    15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,
    41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

constexpr uint32_t rotl(uint32_t val, int shift) noexcept {
    return (val << shift) | (val >> (32 - shift));
}

constexpr uint32_t rotr(uint32_t val, int shift) noexcept {
    return (val >> shift) | (val << (32 - shift));
}

constexpr uint64_t fnv1a_64(const char* str, size_t len) noexcept {
    uint64_t hash = 0xCBF29CE484222325ULL;
    for (size_t i = 0; i < len; ++i) {
        hash ^= static_cast<uint8_t>(str[i]);
        hash *= 0x100000001B3ULL;
    }
    return hash;
}

}

template<size_t KeySize = 16>
struct xor_key {
    std::array<uint8_t, KeySize> data;
    size_t length;

    constexpr xor_key() noexcept : data{}, length(0) {}
    constexpr xor_key(const uint8_t* key_data, size_t len) noexcept
        : data{}, length(len < KeySize ? len : KeySize) {
        for (size_t i = 0; i < length; ++i) {
            data[i] = key_data[i];
        }
    }

    template<size_t N>
    constexpr xor_key(const char (&str)[N]) noexcept
        : data{}, length(N > 0 && N <= KeySize + 1 ? N - 1 : 0) {
        for (size_t i = 0; i < length; ++i) {
            data[i] = static_cast<uint8_t>(str[i]);
        }
    }

    [[nodiscard]] constexpr uint8_t operator[](size_t idx) const noexcept {
        return data[idx % length];
    }
};

template<size_t KeySize>
struct xor_encrypted {
    std::array<uint8_t, KeySize> data;
    size_t length;

    xor_encrypted() noexcept : data{}, length(0) {}

    xor_encrypted(const uint8_t* src, size_t len) noexcept
        : data{}, length(len < KeySize ? len : KeySize) {
        for (size_t i = 0; i < length; ++i) {
            data[i] = src[i];
        }
    }

    void decrypt(const xor_key<KeySize>& key) noexcept {
        for (size_t i = 0; i < length; ++i) {
            data[i] ^= key[i];
        }
    }

    void encrypt(const xor_key<KeySize>& key) noexcept {
        for (size_t i = 0; i < length; ++i) {
            data[i] ^= key[i];
        }
    }

    [[nodiscard]] uint8_t* ptr() noexcept { return data.data(); }
    [[nodiscard]] const uint8_t* ptr() const noexcept { return data.data(); }
    [[nodiscard]] size_t size() const noexcept { return length; }
};

template<size_t KeySize>
[[nodiscard]] xor_encrypted<KeySize> xor_crypt(const void* src, size_t len, const xor_key<KeySize>& key) noexcept {
    xor_encrypted<KeySize> result{};
    size_t copy_len = len < KeySize ? len : KeySize;
    const uint8_t* s = static_cast<const uint8_t*>(src);
    for (size_t i = 0; i < copy_len; ++i) {
        result.data[i] = s[i] ^ key[i];
    }
    result.length = copy_len;
    return result;
}

template<size_t KeySize>
inline void xor_crypt_inplace(void* data, size_t len, const xor_key<KeySize>& key) noexcept {
    uint8_t* d = static_cast<uint8_t*>(data);
    for (size_t i = 0; i < len; ++i) {
        d[i] ^= key[i % key.length];
    }
}

template<size_t KeySize>
inline void xor_crypt_buffer(void* dst, const void* src, size_t len, const xor_key<KeySize>& key) noexcept {
    const uint8_t* s = static_cast<const uint8_t*>(src);
    uint8_t* d = static_cast<uint8_t*>(dst);
    for (size_t i = 0; i < len; ++i) {
        d[i] = s[i] ^ key[i % key.length];
    }
}

struct rot13_cipher {
    static constexpr uint8_t transform(uint8_t ch) noexcept {
        if (ch >= 'a' && ch <= 'z') {
            return (ch - 'a' + 13) % 26 + 'a';
        }
        if (ch >= 'A' && ch <= 'Z') {
            return (ch - 'A' + 13) % 26 + 'A';
        }
        return ch;
    }
};

inline void rot13_encode(void* dst, const void* src, size_t len) noexcept {
    const uint8_t* s = static_cast<const uint8_t*>(src);
    uint8_t* d = static_cast<uint8_t*>(dst);
    for (size_t i = 0; i < len; ++i) {
        d[i] = rot13_cipher::transform(s[i]);
    }
}

inline void rot13_decode(void* dst, const void* src, size_t len) noexcept {
    rot13_encode(dst, src, len);
}

struct custom_base64 {
    std::array<uint8_t, 64> alphabet;
    std::array<int8_t, 256> decode_table;
    uint8_t padding_char;

    custom_base64(const uint8_t* custom_alphabet = nullptr, uint8_t pad = '=') noexcept
        : alphabet{}, decode_table{}, padding_char(pad) {

        if (custom_alphabet) {
            for (size_t i = 0; i < 64; ++i) {
                alphabet[i] = custom_alphabet[i];
            }
        } else {
            for (size_t i = 0; i < 64; ++i) {
                alphabet[i] = detail::default_base64_alphabet[i];
            }
        }

        for (size_t i = 0; i < 256; ++i) {
            decode_table[i] = -1;
        }
        for (size_t i = 0; i < 64; ++i) {
            decode_table[alphabet[i]] = static_cast<int8_t>(i);
        }
    }

    void encode(void* dst, const void* src, size_t src_len) const noexcept {
        const uint8_t* s = static_cast<const uint8_t*>(src);
        uint8_t* d = static_cast<uint8_t*>(dst);

        size_t i = 0;
        size_t j = 0;
        size_t available = src_len;

        while (available >= 3) {
            uint32_t val = (static_cast<uint32_t>(s[i]) << 16) |
                          (static_cast<uint32_t>(s[i + 1]) << 8) |
                          static_cast<uint32_t>(s[i + 2]);

            d[j++] = alphabet[(val >> 18) & 0x3F];
            d[j++] = alphabet[(val >> 12) & 0x3F];
            d[j++] = alphabet[(val >> 6) & 0x3F];
            d[j++] = alphabet[val & 0x3F];

            i += 3;
            available -= 3;
        }

        if (available == 2) {
            uint32_t val = (static_cast<uint32_t>(s[i]) << 16) |
                          (static_cast<uint32_t>(s[i + 1]) << 8);

            d[j++] = alphabet[(val >> 18) & 0x3F];
            d[j++] = alphabet[(val >> 12) & 0x3F];
            d[j++] = alphabet[(val >> 6) & 0x3F];
            d[j++] = padding_char;
        } else if (available == 1) {
            uint32_t val = static_cast<uint32_t>(s[i]) << 16;

            d[j++] = alphabet[(val >> 18) & 0x3F];
            d[j++] = alphabet[(val >> 12) & 0x3F];
            d[j++] = padding_char;
            d[j++] = padding_char;
        }
    }

    [[nodiscard]] std::vector<uint8_t> encode(const void* src, size_t src_len) const noexcept {
        size_t result_len = ((src_len + 2) / 3) * 4;
        std::vector<uint8_t> result(result_len);
        encode(result.data(), src, src_len);
        return result;
    }

    [[nodiscard]] std::vector<uint8_t> encode(const std::string_view& str) const noexcept {
        return encode(str.data(), str.size());
    }

    [[nodiscard]] std::string encode_string(const void* src, size_t src_len) const noexcept {
        auto result = encode(src, src_len);
        return std::string(reinterpret_cast<char*>(result.data()), result.size());
    }

    [[nodiscard]] std::string encode_string(const std::string_view& str) const noexcept {
        return encode_string(str.data(), str.size());
    }

    bool decode(void* dst, const void* src, size_t src_len) const noexcept {
        if (src_len % 4 != 0) return false;

        const uint8_t* s = static_cast<const uint8_t*>(src);
        uint8_t* d = static_cast<uint8_t*>(dst);

        size_t i = 0;
        size_t j = 0;
        size_t available = src_len;

        while (available >= 4) {
            int8_t vals[4];
            for (int k = 0; k < 4; ++k) {
                uint8_t ch = s[i + k];
                if (ch == padding_char) {
                    vals[k] = 0;
                } else {
                    vals[k] = decode_table[ch];
                    if (vals[k] < 0) return false;
                }
            }

            d[j++] = static_cast<uint8_t>((vals[0] << 2) | (vals[1] >> 4));
            if (s[i + 2] != padding_char) {
                d[j++] = static_cast<uint8_t>((vals[1] << 4) | (vals[2] >> 2));
            }
            if (s[i + 3] != padding_char) {
                d[j++] = static_cast<uint8_t>((vals[2] << 6) | vals[3]);
            }

            i += 4;
            available -= 4;
        }

        return true;
    }

    [[nodiscard]] std::optional<std::vector<uint8_t>> decode(const void* src, size_t src_len) const noexcept {
        size_t result_len = (src_len / 4) * 3;
        const uint8_t* src_bytes = static_cast<const uint8_t*>(src);
        if (src_len > 0 && src_bytes[src_len - 1] == padding_char) --result_len;
        if (src_len > 1 && src_bytes[src_len - 2] == padding_char) --result_len;

        std::vector<uint8_t> result(result_len);
        if (!decode(result.data(), src, src_len)) {
            return std::nullopt;
        }
        return result;
    }

    [[nodiscard]] std::optional<std::vector<uint8_t>> decode(const std::string_view& str) const noexcept {
        return decode(str.data(), str.size());
    }

    [[nodiscard]] std::optional<std::string> decode_string(const void* src, size_t src_len) const noexcept {
        auto result = decode(src, src_len);
        if (!result) return std::nullopt;
        return std::string(reinterpret_cast<char*>(result->data()), result->size());
    }

    [[nodiscard]] std::optional<std::string> decode_string(const std::string_view& str) const noexcept {
        return decode_string(str.data(), str.size());
    }
};

inline const custom_base64& standard_base64() noexcept {
    static custom_base64 instance(nullptr, '=');
    return instance;
}

template<size_t N>
struct encoded_data {
    std::array<uint8_t, N> data;
    size_t length;
    uint64_t key_id;

    constexpr encoded_data() noexcept : data{}, length(0), key_id(0) {}
};

template<size_t KeySize>
class secure_buffer {
public:
    using value_type = uint8_t;

    secure_buffer() noexcept : size_(0), capacity_(KeySize) {
        clear();
    }

    explicit secure_buffer(size_t size) noexcept : size_(0), capacity_(KeySize) {
        if (size <= KeySize) {
            size_ = size;
        }
        clear();
    }

    ~secure_buffer() noexcept {
        clear();
    }

    secure_buffer(const secure_buffer&) = delete;
    secure_buffer& operator=(const secure_buffer&) = delete;

    secure_buffer(secure_buffer&& other) noexcept {
        size_ = other.size_;
        capacity_ = other.capacity_;
        for (size_t i = 0; i < size_; ++i) {
            data_[i] = other.data_[i];
        }
        other.clear();
    }

    secure_buffer& operator=(secure_buffer&& other) noexcept {
        if (this != &other) {
            clear();
            size_ = other.size_;
            capacity_ = other.capacity_;
            for (size_t i = 0; i < size_; ++i) {
                data_[i] = other.data_[i];
            }
            other.clear();
        }
        return *this;
    }

    void clear() noexcept {
        for (size_t i = 0; i < size_; ++i) {
            data_[i] = 0;
        }
        size_ = 0;
    }

    void resize(size_t new_size) noexcept {
        if (new_size <= KeySize) {
            clear();
            size_ = new_size;
        }
    }

    void write(const void* src, size_t len) noexcept {
        size_t copy = len < (KeySize - size_) ? len : (KeySize - size_);
        const uint8_t* s = static_cast<const uint8_t*>(src);
        for (size_t i = 0; i < copy; ++i) {
            data_[size_ + i] = s[i];
        }
        size_ += copy;
    }

    [[nodiscard]] uint8_t* data() noexcept { return data_; }
    [[nodiscard]] const uint8_t* data() const noexcept { return data_; }
    [[nodiscard]] size_t size() const noexcept { return size_; }
    [[nodiscard]] size_t capacity() const noexcept { return capacity_; }
    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }

private:
    uint8_t data_[KeySize];
    size_t size_;
    size_t capacity_;
};

template<size_t KeySize>
inline void secure_xor(void* dst, const void* src, size_t len, const xor_key<KeySize>& key) noexcept {
    xor_crypt_inplace(dst, len, key);
}

template<size_t KeySize>
inline void secure_xor_with_seed(void* dst, const void* src, size_t len, uint64_t seed) noexcept {
    xor_key<KeySize> key{};
    for (size_t i = 0; i < KeySize && i < 16; ++i) {
        key.data[i] = static_cast<uint8_t>((seed >> (i * 8)) ^ 0x5A);
    }
    key.length = KeySize < 16 ? KeySize : 16;
    xor_crypt_inplace(dst, len, key);
}

struct hex_encoder {
    static constexpr char hex_digits[] = "0123456789ABCDEF";

    static void encode(void* dst, const void* src, size_t len) noexcept {
        const uint8_t* s = static_cast<const uint8_t*>(src);
        char* d = static_cast<char*>(dst);

        for (size_t i = 0; i < len; ++i) {
            d[i * 2] = hex_digits[(s[i] >> 4) & 0x0F];
            d[i * 2 + 1] = hex_digits[s[i] & 0x0F];
        }
    }

    [[nodiscard]] static std::string encode_string(const void* src, size_t len) noexcept {
        std::string result(len * 2, '\0');
        encode(result.data(), src, len);
        return result;
    }

    [[nodiscard]] static std::string encode_string(const std::string_view& str) noexcept {
        return encode_string(str.data(), str.size());
    }

    static bool decode(void* dst, const void* src, size_t src_len) noexcept {
        if (src_len % 2 != 0) return false;

        const char* s = static_cast<const char*>(src);
        uint8_t* d = static_cast<uint8_t*>(dst);

        for (size_t i = 0; i < src_len / 2; ++i) {
            char high = s[i * 2];
            char low = s[i * 2 + 1];

            uint8_t h = 0, l = 0;

            if (high >= '0' && high <= '9') h = high - '0';
            else if (high >= 'A' && high <= 'F') h = high - 'A' + 10;
            else if (high >= 'a' && high <= 'f') h = high - 'a' + 10;
            else return false;

            if (low >= '0' && low <= '9') l = low - '0';
            else if (low >= 'A' && low <= 'F') l = low - 'A' + 10;
            else if (low >= 'a' && low <= 'f') l = low - 'a' + 10;
            else return false;

            d[i] = static_cast<uint8_t>((h << 4) | l);
        }
        return true;
    }

    [[nodiscard]] static std::optional<std::vector<uint8_t>> decode(const void* src, size_t src_len) noexcept {
        if (src_len % 2 != 0) return std::nullopt;
        std::vector<uint8_t> result(src_len / 2);
        if (!decode(result.data(), src, src_len)) {
            return std::nullopt;
        }
        return result;
    }
};

template<typename T>
[[nodiscard]] constexpr uint64_t hash_value(const T& value, uint64_t seed = 0x9E3779B97F4A7C15ULL) noexcept {
    uint64_t h = seed;
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&value);
    for (size_t i = 0; i < sizeof(T); ++i) {
        h ^= static_cast<uint64_t>(bytes[i]) + 0x9E3779B9 + (h << 6) + (h >> 2);
    }
    return h;
}

template<>
[[nodiscard]] constexpr uint64_t hash_value<std::string_view>(const std::string_view& value, [[maybe_unused]] uint64_t seed) noexcept {
    return detail::fnv1a_64(value.data(), value.size());
}

[[nodiscard]] inline constexpr uint64_t hash_value(const char* value, uint64_t = 0x9E3779B97F4A7C15ULL) noexcept {
    size_t len = 0;
    while (value[len] != '\0') ++len;
    return detail::fnv1a_64(value, len);
}

template<size_t N>
class rolling_xor {
public:
    rolling_xor(const uint8_t* key, size_t key_len) noexcept
        : key_data_{}, key_len_(key_len < N ? key_len : N) {
        for (size_t i = 0; i < key_len_; ++i) {
            key_data_[i] = key[i];
        }
    }

    void encrypt(void* data, size_t len) noexcept {
        uint8_t* d = static_cast<uint8_t*>(data);
        for (size_t i = 0; i < len; ++i) {
            uint8_t k = key_data_[i % key_len_];
            uint8_t prev = i > 0 ? d[i - 1] : 0;
            d[i] ^= k ^ prev;
        }
    }

    void decrypt(void* data, size_t len) noexcept {
        encrypt(data, len);
    }

private:
    uint8_t key_data_[N];
    size_t key_len_;
};

class poly_xor {
public:
    static constexpr size_t MAX_STATE = 256;

    poly_xor() noexcept : state_{}, state_len_(0), rounds_(3) {}

    void set_rounds(size_t r) noexcept { rounds_ = r; }

    void process(void* data, size_t len, const void* key, size_t key_len) noexcept {
        uint8_t* d = static_cast<uint8_t*>(data);
        const uint8_t* k = static_cast<const uint8_t*>(key);

        state_len_ = key_len < MAX_STATE ? key_len : MAX_STATE;
        for (size_t i = 0; i < state_len_; ++i) {
            state_[i] = k[i];
        }

        for (size_t r = 0; r < rounds_; ++r) {
            for (size_t i = 0; i < len; ++i) {
                uint8_t feedback = 0;
                for (size_t j = 0; j < state_len_; ++j) {
                    feedback ^= state_[j];
                    state_[j] = (state_[j] << 1) | (state_[j] >> 7);
                }
                d[i] ^= feedback ^ k[i % key_len];
            }
        }
    }

private:
    uint8_t state_[MAX_STATE];
    size_t state_len_;
    size_t rounds_;
};

}

}

#endif