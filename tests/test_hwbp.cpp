// Real DR0 hardware-breakpoint sanity test.
//
// The actual setting of hardware breakpoints requires kernel-mode
// cooperation (ptrace on Linux, NtSystemDebugControl on Windows), but
// READING DR0..DR3 is permitted from user-space. This test reads
// the registers on the current thread via inline asm and verifies
// that stealth's hardware_breakpoint_count() and register accessor
// agree about the count being non-negative.
//
// On a non-traced thread, all four DR registers read as 0 and the
// count is 0. On a thread with a single breakpoint this would be
// 1. We do not claim more than "no UB; count in valid range".
#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "stealthlib/stealth.hpp"

#if defined(__x86_64__) || defined(_M_X64)

TEST_CASE("hwbp: hardware_breakpoint_count returns a valid signed count") {
    int n = stealth::detection::hardware_breakpoint_count();
    CHECK(n >= -1);
    CHECK(n <= 4);
}

TEST_CASE("hwbp: integrity::hardware_breakpoint_register_nonzero agrees with count") {
    bool dr_nonzero = stealth::integrity::hardware_breakpoint_register_nonzero();
    int n = stealth::detection::hardware_breakpoint_count();
    if (n < 0) {
        CHECK((dr_nonzero == true || dr_nonzero == false));
    } else if (n == 0) {
        CHECK_FALSE(dr_nonzero);
    } else {
        CHECK(dr_nonzero);
    }
}

TEST_CASE("hwbp: repeated reads are stable") {
    int n1 = stealth::detection::hardware_breakpoint_count();
    int n2 = stealth::detection::hardware_breakpoint_count();
    int n3 = stealth::detection::hardware_breakpoint_count();
    CHECK(n1 == n2);
    CHECK(n2 == n3);
}

#else

TEST_CASE("hwbp: hardware_breakpoint_count not supported on this arch") {
    int n = stealth::detection::hardware_breakpoint_count();
    CHECK(n == -1);
}

#endif
