#pragma once
#ifndef STEALTH_DETECTION_SIGNALS_HPP
#define STEALTH_DETECTION_SIGNALS_HPP

#include "debug.hpp"
#include "../detail/version.hpp"

namespace stealth::detection {

struct signals {
    bool peb_debug_flag;
    bool remote_debugger;
    bool timing_anomaly;
    bool hardware_breakpoints;
    int hwbp_count;
    uint64_t build_key_match;
    [[nodiscard]] bool any() const noexcept {
        return peb_debug_flag || remote_debugger || timing_anomaly || (hwbp_count > 0);
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

} // namespace stealth::detection

#endif // STEALTH_DETECTION_SIGNALS_HPP
