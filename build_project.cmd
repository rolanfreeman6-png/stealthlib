@echo off
cd C:\Users\asad\stealthlib
if not exist build mkdir build
cd build
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
"C:\Program Files\CMake\bin\cmake.exe" .. -G "Visual Studio 17 2022" -A x64 -DSTEALTH_BUILD_EXAMPLES=ON -DSTEALTH_BUILD_TESTS=ON
"C:\Program Files\CMake\bin\cmake.exe" --build . --config Release