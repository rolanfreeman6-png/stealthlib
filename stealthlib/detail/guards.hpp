#pragma once
#ifndef STEALTH_DETAIL_GUARDS_HPP
#define STEALTH_DETAIL_GUARDS_HPP

#include <cstddef>
#include <cstddef>
#include "encryption.hpp"

namespace stealth::detail {

class unlocked_string_guard {
public:
    using reen_func_t = void(*)(void*);
    unlocked_string_guard() noexcept : ptr_(nullptr), n_(0), pool_ptr_(nullptr), reen_(nullptr) {}
    template<size_t S, size_t I>
    unlocked_string_guard(const char* ptr, size_t n, encrypted_string_impl<S, I>* impl) noexcept
        : ptr_(ptr), n_(n), pool_ptr_(impl), reen_(static_cast<reen_func_t>([](void* p){ static_cast<encrypted_string_impl<S, I>*>(p)->reencrypt(); })) {}
    unlocked_string_guard(const char* ptr, size_t n, std::nullptr_t) noexcept : ptr_(ptr), n_(n), pool_ptr_(nullptr), reen_(nullptr) {}
    ~unlocked_string_guard() { if (reen_ && pool_ptr_) reen_(pool_ptr_); }
    unlocked_string_guard(const unlocked_string_guard&) = delete;
    unlocked_string_guard& operator=(const unlocked_string_guard&) = delete;
    unlocked_string_guard(unlocked_string_guard&& o) noexcept : ptr_(o.ptr_), n_(o.n_), pool_ptr_(o.pool_ptr_), reen_(o.reen_) { o.ptr_=nullptr; o.n_=0; o.pool_ptr_=nullptr; o.reen_=nullptr; }
    unlocked_string_guard& operator=(unlocked_string_guard&& o) noexcept { if(this!=&o){ if(reen_&&pool_ptr_) reen_(pool_ptr_); ptr_=o.ptr_; n_=o.n_; pool_ptr_=o.pool_ptr_; reen_=o.reen_; o.ptr_=nullptr; o.n_=0; o.pool_ptr_=nullptr; o.reen_=nullptr; } return *this; }
    const char* c_str() const noexcept { return ptr_; }
    size_t size() const noexcept { return n_; }
    operator const char*() const noexcept { return ptr_; }
private:
    const char* ptr_; size_t n_; void* pool_ptr_; reen_func_t reen_;
};

class unlocked_wstring_guard {
public:
    using reen_func_t = void(*)(void*);
    unlocked_wstring_guard() noexcept : ptr_(nullptr), n_(0), pool_ptr_(nullptr), reen_(nullptr) {}
    template<size_t S, size_t I>
    unlocked_wstring_guard(const wchar_t* ptr, size_t n, encrypted_wstring_impl<S, I>* impl) noexcept
        : ptr_(ptr), n_(n), pool_ptr_(impl), reen_(static_cast<reen_func_t>([](void* p){ static_cast<encrypted_wstring_impl<S, I>*>(p)->reencrypt(); })) {}
    unlocked_wstring_guard(const wchar_t* ptr, size_t n, std::nullptr_t) noexcept : ptr_(ptr), n_(n), pool_ptr_(nullptr), reen_(nullptr) {}
    ~unlocked_wstring_guard() { if (reen_ && pool_ptr_) reen_(pool_ptr_); }
    unlocked_wstring_guard(const unlocked_wstring_guard&) = delete;
    unlocked_wstring_guard& operator=(const unlocked_wstring_guard&) = delete;
    unlocked_wstring_guard(unlocked_wstring_guard&& o) noexcept : ptr_(o.ptr_), n_(o.n_), pool_ptr_(o.pool_ptr_), reen_(o.reen_) { o.ptr_=nullptr; o.n_=0; o.pool_ptr_=nullptr; o.reen_=nullptr; }
    unlocked_wstring_guard& operator=(unlocked_wstring_guard&& o) noexcept { if(this!=&o){ if(reen_&&pool_ptr_) reen_(pool_ptr_); ptr_=o.ptr_; n_=o.n_; pool_ptr_=o.pool_ptr_; reen_=o.reen_; o.ptr_=nullptr; o.n_=0; o.pool_ptr_=nullptr; o.reen_=nullptr; } return *this; }
    const wchar_t* c_str() const noexcept { return ptr_; }
    size_t size() const noexcept { return n_; }
    operator const wchar_t*() const noexcept { return ptr_; }
private:
    const wchar_t* ptr_; size_t n_; void* pool_ptr_; reen_func_t reen_;
};

} // namespace stealth::detail

namespace stealth {

template<size_t N, size_t Idx>
struct stealth_encrypted_char {
    detail::encrypted_string_impl<N, Idx> impl;
    template<size_t M>
    consteval stealth_encrypted_char(const char (&src)[M]) noexcept : impl(src) { static_assert(M == N + 1, "StealthLib: literal size mismatch in S()"); }
    const char* c_str() noexcept { return impl.decrypt(); }
    constexpr size_t size() const noexcept { return N; }
    const char* operator*() noexcept { return c_str(); }
    operator const char*() noexcept { return c_str(); }
    detail::unlocked_string_guard unlock() noexcept { const char* p = impl.decrypt(); return detail::unlocked_string_guard(p, N, &impl); }
};

template<size_t Idx>
struct stealth_encrypted_char<0, Idx> {
    constexpr stealth_encrypted_char(const char (&)[1]) noexcept {}
    const char* c_str() noexcept { return ""; }
    constexpr size_t size() const noexcept { return 0; }
    const char* operator*() noexcept { return c_str(); }
    operator const char*() noexcept { return ""; }
    detail::unlocked_string_guard unlock() noexcept { return detail::unlocked_string_guard("", 0, nullptr); }
};

template<size_t N, size_t Idx>
struct stealth_encrypted_wchar {
    detail::encrypted_wstring_impl<N, Idx> impl;
    template<size_t M>
    consteval stealth_encrypted_wchar(const wchar_t (&src)[M]) noexcept : impl(src) { static_assert(M == N + 1, "StealthLib: literal size mismatch in SW()"); }
    const wchar_t* c_str() noexcept { return impl.decrypt(); }
    constexpr size_t size() const noexcept { return N; }
    operator const wchar_t*() noexcept { return c_str(); }
    detail::unlocked_wstring_guard unlock() noexcept { const wchar_t* p = impl.decrypt(); return detail::unlocked_wstring_guard(p, N, &impl); }
};

template<size_t Idx>
struct stealth_encrypted_wchar<0, Idx> {
    constexpr stealth_encrypted_wchar(const wchar_t (&)[1]) noexcept {}
    const wchar_t* c_str() noexcept { return L""; }
    constexpr size_t size() const noexcept { return 0; }
    operator const wchar_t*() noexcept { return L""; }
    detail::unlocked_wstring_guard unlock() noexcept { return detail::unlocked_wstring_guard(L"", 0, nullptr); }
};

} // namespace stealth

#endif // STEALTH_DETAIL_GUARDS_HPP
