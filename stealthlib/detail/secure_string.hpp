#pragma once
#ifndef STEALTH_DETAIL_SECURE_STRING_HPP
#define STEALTH_DETAIL_SECURE_STRING_HPP

#include <cstdint>
#include <cstddef>
#include <cstring>

namespace stealth {

template<size_t MaxSize = 256>
class secure_string {
public:
    using char_type = char;
    secure_string() noexcept : length_(0) { std::memset(data_, 0, MaxSize); }
    explicit secure_string(const char* str) noexcept : length_(0) {
        std::memset(data_, 0, MaxSize);
        if (!str) return;
        while (str[length_] != '\0' && length_ + 1 < MaxSize) { data_[length_] = str[length_]; ++length_; }
        data_[length_] = '\0';
    }
    secure_string(const secure_string&) = delete;
    secure_string& operator=(const secure_string&) = delete;
    ~secure_string() noexcept { std::memset(data_, 0, MaxSize); length_ = 0; }
    [[nodiscard]] char* raw_data() noexcept { return data_; }
    [[nodiscard]] const char* raw_data() const noexcept { return data_; }
    [[nodiscard]] const char* c_str() const noexcept { return data_; }
    [[nodiscard]] size_t length() const noexcept { return length_; }
    [[nodiscard]] size_t size() const noexcept { return length_; }
    void clear() noexcept { std::memset(data_, 0, MaxSize); length_ = 0; }
private:
    char data_[MaxSize];
    size_t length_;
};

} // namespace stealth

#endif // STEALTH_DETAIL_SECURE_STRING_HPP
