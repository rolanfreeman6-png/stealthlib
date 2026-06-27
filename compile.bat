@echo off
REM StealthLib quick-compile helper (MSVC). Run from project root.
REM Uses CMake-generated STEALTH_BUILD_KEY if available, else a fixed key.
if not defined STEALTH_BUILD_KEY set STEALTH_BUILD_KEY=0xC0FFEE42DEADBEEFULL
cl.exe /nologo /std:c++20 /EHsc /W4 /I. /DSTEALTH_BUILD_KEY=%STEALTH_BUILD_KEY% examples/full_demo.cpp /Fe:build\full_demo.exe /link user32.lib
