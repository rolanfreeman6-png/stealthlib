#pragma once
#ifndef STEALTH_HPP
#define STEALTH_HPP

// StealthLib v2.2.0 — header-only C++20 Windows hardening library
// Single-include umbrella: users only #include "stealthlib/stealth.hpp"
// Internal implementation is split into sub-files for maintainability.

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <string_view>
#include <array>
#include <optional>
#include <vector>
#include <type_traits>
#if !defined(_WIN32)
#include <sys/statvfs.h>
#endif

// STEALTHLIB_SSE2_DECRYPT may be defined by CMake to enable the SSE2 fast path.
#ifndef STEALTHLIB_SSE2_DECRYPT
#define STEALTHLIB_SSE2_DECRYPT 0
#endif

// ── Core: version, build key, hashes, SHA-256 ──────────────────────
#include "detail/version.hpp"
#include "detail/hashes.hpp"
#include "detail/sha256.hpp"

// ── String encryption + RAII guards ────────────────────────────────
#include "detail/encryption.hpp"
#include "detail/guards.hpp"
#include "detail/secure_string.hpp"

// ── Encoding utilities ─────────────────────────────────────────────
#include "encoding/encoding.hpp"

// ── Memory utilities ───────────────────────────────────────────────
#include "memory/memory.hpp"

// ── Anti-debug detection ───────────────────────────────────────────
#include "detection/debug.hpp"
#include "detection/signals.hpp"

// ── VM detection ───────────────────────────────────────────────────
#include "vmdetect/vmdetect.hpp"

// ── PE parsing + API resolution (Windows-only) ─────────────────────
#ifdef _WIN32
#include "pe/pe_layout.hpp"
#include "pe/pe_parser.hpp"
#endif

// ── Integrity checks (IAT/EAT/prologue) ────────────────────────────
#include "integrity/integrity.hpp"

// ── S() / SW() macros ──────────────────────────────────────────────
// Passes the literal by const-array reference so the compiler can
// constexpr-fold the encryption and elide the literal in .rodata;
// only ciphertext remains.
#define S(str)  ::stealth::stealth_encrypted_char<sizeof(str) - 1, __COUNTER__>{str}
#define SW(str) ::stealth::stealth_encrypted_wchar<((sizeof(str) - 1) / sizeof(wchar_t)), __COUNTER__>{str}

#ifndef STEALTH_HASH_AUTO
#define STEALTH_HASH_AUTO(name) ::stealth::hashes::fnv(name, sizeof(name) - 1)
#endif

#endif // STEALTH_HPP
