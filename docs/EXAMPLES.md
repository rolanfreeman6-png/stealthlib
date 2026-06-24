# Examples

This directory contains Windows example programs demonstrating StealthLib features.

## minimal_test.cpp

Basic functionality test:
- String encryption
- Base64/Hex encoding
- PEB walking
- Module loading
- Secure memory operations

## full_demo.cpp

Complete demonstration of all features:
- Compile-time string encryption
- PEB walking for API resolution
- XOR/Base64/Hex encoding
- Debugger detection
- Secure memory operations
- `stealth_api` template
- Module loader class

## game_protection.cpp

Game development use case:
- Protect game server IP
- Protect mod API keys
- Protect database passwords
- Dynamic API resolution
- Debugger detection

## server_protection.cpp

Server software use case:
- Protect DB credentials
- Protect JWT secrets
- Protect AWS keys
- Protect encryption keys
- Dynamic API resolution

## Building Examples

```bash
mkdir build && cd build
cmake .. -DSTEALTH_BUILD_EXAMPLES=ON
cmake --build .
```

## Running On Windows

```bash
./examples/Release/minimal_test.exe
./examples/Release/full_demo.exe
./examples/Release/game_protection.exe
./examples/Release/server_protection.exe
```
