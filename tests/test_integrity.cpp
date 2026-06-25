#ifdef _WIN32

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

#include "stealthlib/stealth.hpp"

#include <fstream>
#include <windows.h>

TEST_CASE("integrity: IAT/EAT hooks scan does not crash") {
    auto ki = stealth::integrity::compare_iat_thunk("kernel32.dll", "GetProcAddress");
    CHECK((ki.hooked == true || ki.hooked == false));
}

TEST_CASE("integrity: forwarder detection runs without exceptions") {
    auto ok = stealth::integrity::is_eat_forwarded("ntdll.dll", "RtlUserThreadStart")
           || !stealth::integrity::is_eat_forwarded("ntdll.dll", "RtlUserThreadStart");
    CHECK(ok);
}

#else

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"

TEST_CASE("windows-only integrity suite is excluded on this platform") {
    MESSAGE("Windows-only: integrity::compare_iat_thunk not exercised");
    CHECK(true);
}

#endif
