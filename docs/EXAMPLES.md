# Examples (v2.0)

Each example compiles standalone against the header-only library.

## minimal_test.cpp

The simplest end-to-end smoke test:

- String encryption (`S("...")`)
- Base64 / Hex encoding
- PEB walking + `get_function`
- Module loader
- Secure memory and constant-time compare

Build & run:

```cmd
minimal_test.exe
```

## full_demo.cpp

A long walkthrough of every feature with a section header for each.
Useful as a documentation reference for users learning the API.

## game_protection.cpp

Game-server use case:

- API keys
- Database passwords
- Mod integration secrets

## server_protection.cpp

Server-side use case:

- DB connection strings
- JWT secrets
- AWS access / secret keys
- SMTP credentials

## hash_resolution.cpp (v2.0 — killer feature)

Demonstrates hash-based API resolution. Module and function names are
folded into 64-bit FNV-1a constants at compile time; only the hashes
appear in the compiled binary.

```text
[+] StealthLib v2.0.0: hash-based API resolution demo
[*] module hash(user32.dll)   = 0xcbf29ce484222325 + int
[*] func   hash(MessageBoxW)  = ...
[+] MessageBoxW resolved by hash at <ptr>
[+] GetTickCount64 resolved by hash: uptime=<ms>ms
[+] Anti-debug signals scan
[+] RAII unlock demo
```

A static reverse engineer running `strings examples/hash_resolution.exe`
will not find `"user32.dll"`, `"kernel32.dll"`, `"MessageBoxW"`,
`"GetTickCount64"` or `"GetComputerNameW"` anywhere in the binary.

## unlock_demo.cpp (v2.0)

Demonstrates RAII narrow window:

```text
[+] StealthLib unlock demo v2.0.0
[*] 'api' identity: <plaintext>
[*] locked within scope: <plaintext>
[+] scope exited -> ciphertext restored
[+] still decryptable after re-encryption
```

After the inner block, the plaintext is no longer recoverable from
heap dumps: the encryption byte stream plus an empty plaintext buffer
are all that remains; on the next `c_str()` call, the string is
decrypted fresh from the encrypted form.

## Building all examples

```bash
cmake -S . -B build -DSTEALTH_BUILD_EXAMPLES=ON
cmake --build build --parallel
./build/examples/minimal_test
./build/examples/full_demo
./build/examples/game_protection
./build/examples/server_protection
./build/examples/hash_resolution
./build/examples/unlock_demo
```

On Windows MSVC the binaries live under
`build/examples/Release/`; on Linux under `build/examples/`.
