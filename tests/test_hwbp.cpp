#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "stealthlib/stealth.hpp"

#ifdef _WIN32

TEST_CASE("hwbp: DR7 enabled slots are counted") {
    CONTEXT context{};
    context.Dr0 = 0x1234;
    context.Dr1 = 0x5678;
    CHECK(stealth::detection::hardware_breakpoint_count_from_context(context) == 0);

    context.Dr7 = 0x1;
    CHECK(stealth::detection::hardware_breakpoint_count_from_context(context) == 1);

    context.Dr7 = 0xCu;
    CHECK(stealth::detection::hardware_breakpoint_count_from_context(context) == 1);

    context.Dr7 = 0xFFu;
    CHECK(stealth::detection::hardware_breakpoint_count_from_context(context) == 4);
}

TEST_CASE("hwbp: current thread reports unavailable context") {
    CHECK(stealth::detection::hardware_breakpoint_count() == -1);
}

TEST_CASE("hwbp: pseudo handle cannot provide its running context") {
    CHECK(stealth::detection::hardware_breakpoint_count_for_suspended_thread(GetCurrentThread()) == -1);
}

#else

TEST_CASE("hwbp: hardware_breakpoint_count not supported on this arch") {
    int n = stealth::detection::hardware_breakpoint_count();
    CHECK(n == -1);
}

#endif
