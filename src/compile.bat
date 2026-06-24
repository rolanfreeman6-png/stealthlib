@echo off
setlocal

where cl >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] MSVC compiler not found. Run from Developer Command Prompt.
    exit /b 1
)

echo [*] Compiling StealthLib comprehensive test...
cl /EHsc /std:c++20 /W4 /Zc:__cplusplus /I".\" /Fe:stealth_test.exe comprehensive_test.cpp /link kernel32.lib user32.lib
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Compilation failed.
    exit /b 1
)

echo [*] Running 95 tests...
stealth_test.exe
echo.
echo [*] Done.
endlocal
