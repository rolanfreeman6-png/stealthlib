#pragma once
#ifndef STEALTH_MEMORY_MEMORY_HPP
#define STEALTH_MEMORY_MEMORY_HPP

#include <cstdint>
#include <cstddef>

namespace stealth::memory {

inline void secure_zero(void* ptr, size_t len) noexcept {
    if (!ptr) return;
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len--) *p++ = 0;
}

inline bool compare_constant_time(const void* a, const void* b, size_t len) noexcept {
    if (len > 0 && (!a || !b)) return false;
    const uint8_t* A = static_cast<const uint8_t*>(a);
    const uint8_t* B = static_cast<const uint8_t*>(b);
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) diff |= A[i] ^ B[i];
    return diff == 0;
}

} // namespace stealth::memory

#endif // STEALTH_MEMORY_MEMORY_HPP
