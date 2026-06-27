#pragma once
#ifndef STEALTH_DETAIL_VERSION_HPP
#define STEALTH_DETAIL_VERSION_HPP

#define STEALTH_VERSION_MAJOR 2
#define STEALTH_VERSION_MINOR 2
#define STEALTH_VERSION_PATCH 0
#define STEALTH_VERSION_STRING "2.2.0"

#ifndef STEALTH_BUILD_KEY
#error "STEALTH_BUILD_KEY is not defined. Build via CMake (it auto-generates from git SHA + timestamp)."
#endif
static_assert(STEALTH_BUILD_KEY != 0, "STEALTH_BUILD_KEY must be non-zero.");

namespace stealth {
constexpr const char* version() noexcept { return STEALTH_VERSION_STRING; }
constexpr uint64_t build_key() noexcept { return STEALTH_BUILD_KEY; }
} // namespace stealth

#endif // STEALTH_DETAIL_VERSION_HPP
