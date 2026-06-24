@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\vcvars64.bat"
cd C:\Users\asad\stealthlib
cl.exe /std:c++20 /EHsc /W4 /I./stealthlib examples/full_demo.cpp /Fe:build/full_demo.exe