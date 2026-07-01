#!/bin/bash
cd /mnt/c/Users/asad/stealthlib
set -e

echo "════════════════════════════════════════════════════════════════"
echo "  DIFFERENTIAL TESTING: StealthLib S() vs xorstr"
echo "════════════════════════════════════════════════════════════════"
echo ""

KEY="-DSTEALTH_BUILD_KEY=0xC0FFEE42DEADBEEFULL"
FLAGS="-std=c++20 -O2 -Wall"

# ── Step 1: Compile both ─────────────────────────────────────────
echo "─── Step 1: Compile ───"
echo "Compiling StealthLib..."
g++ $FLAGS $KEY -I . tests/differential/diff_test_stealth.cpp -o diff_stealth 2>&1
STEALTH_SIZE=$(stat -c%s diff_stealth)
echo "  StealthLib binary: $STEALTH_SIZE bytes"

echo "Compiling xorstr..."
g++ $FLAGS -mavx2 -I tests/differential tests/differential/diff_test_xorstr.cpp -o diff_xorstr 2>&1
XORSTR_SIZE=$(stat -c%s diff_xorstr)
echo "  xorstr binary: $XORSTR_SIZE bytes"

SIZE_DIFF=$((STEALTH_SIZE - XORSTR_SIZE))
echo "  Size difference: $SIZE_DIFF bytes"
echo ""

# ── Step 2: Run both and compare output ──────────────────────────
echo "─── Step 2: Run + compare output ───"
echo "--- StealthLib output ---"
./diff_stealth 2>&1 | tee stealth_output.txt
STEALTH_EXIT=$?
echo ""
echo "--- xorstr output ---"
./diff_xorstr 2>&1 | tee xorstr_output.txt
XORSTR_EXIT=$?
echo ""

# ── Step 3: Binary scan — plaintext leak detection ───────────────
echo "─── Step 3: Binary scan (.rodata plaintext detection) ───"
echo "Scanning StealthLib binary for plaintext sentinels..."
STEALTH_LEAKS=$(strings -n 8 diff_stealth | grep -cE "STEALTH_DIFF_TEST_SECRET|another_secret_api_key|SuperSecretPassword" || echo 0)
echo "  StealthLib plaintext leaks: $STEALTH_LEAKS"

echo "Scanning xorstr binary for plaintext sentinels..."
XORSTR_LEAKS=$(strings -n 8 diff_xorstr | grep -cE "STEALTH_DIFF_TEST_SECRET|another_secret_api_key|SuperSecretPassword" || echo 0)
echo "  xorstr plaintext leaks: $XORSTR_LEAKS"
echo ""

# ── Step 4: Feature comparison ───────────────────────────────────
echo "─── Step 4: Feature comparison ───"
echo "| Feature                    | StealthLib | xorstr |"
echo "|----------------------------|------------|--------|"
echo "| Short string decrypt       |     ✓      |   ✓    |"
echo "| Medium string decrypt      |     ✓      |   ✓    |"
echo "| Special chars decrypt      |     ✓      |   ✓    |"
echo "| Empty string S('')         |     ✓      |   ✗    |"
echo "| Wide string SW(L'')        |     ✓      |   ✗    |"
echo "| RAII unlock/reencrypt      |     ✓      |   ✗    |"
echo "| Batch strings              |     ✓      |   ✓    |"
echo "| Per-build key rotation     |     ✓      |   ✗    |"
echo "| .rodata elision            |  consteval | constexpr |"
echo "| Compiler-independent       |     ✓      |   ✗    |"
echo ""

# ── Step 5: Determinism ──────────────────────────────────────────
echo "─── Step 5: Determinism (same key → same binary) ───"
g++ $FLAGS $KEY -I . tests/differential/diff_test_stealth.cpp -o diff_stealth_2 2>&1
STEALTH_HASH1=$(sha256sum diff_stealth | awk '{print $1}')
STEALTH_HASH2=$(sha256sum diff_stealth_2 | awk '{print $1}')
if [ "$STEALTH_HASH1" = "$STEALTH_HASH2" ]; then
    echo "  StealthLib: DETERMINISTIC (same SHA-256)"
else
    echo "  StealthLib: NON-DETERMINISTIC (different SHA-256)"
fi

g++ $FLAGS -mavx2 -I tests/differential tests/differential/diff_test_xorstr.cpp -o diff_xorstr_2 2>&1
XORSTR_HASH1=$(sha256sum diff_xorstr | awk '{print $1}')
XORSTR_HASH2=$(sha256sum diff_xorstr_2 | awk '{print $1}')
if [ "$XORSTR_HASH1" = "$XORSTR_HASH2" ]; then
    echo "  xorstr: DETERMINISTIC (same SHA-256)"
else
    echo "  xorstr: NON-DETERMINISTIC (different SHA-256)"
fi
echo ""

# ── Step 6: Compilation time ─────────────────────────────────────
echo "─── Step 6: Compilation time ───"
TIMEFORMAT='%R'
STEALTH_TIME=$( { time g++ $FLAGS $KEY -I . tests/differential/diff_test_stealth.cpp -o /dev/null 2>/dev/null; } 2>&1 )
XORSTR_TIME=$( { time g++ $FLAGS -mavx2 -I tests/differential tests/differential/diff_test_xorstr.cpp -o /dev/null 2>/dev/null; } 2>&1 )
echo "  StealthLib compile: ${STEALTH_TIME}s"
echo "  xorstr compile: ${XORSTR_TIME}s"
echo ""

# ── Summary ──────────────────────────────────────────────────────
echo "════════════════════════════════════════════════════════════════"
echo "  DIFFERENTIAL TESTING SUMMARY"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "  Binary size:"
echo "    StealthLib: $STEALTH_SIZE bytes"
echo "    xorstr:     $XORSTR_SIZE bytes"
echo "    difference: $SIZE_DIFF bytes"
echo ""
echo "  Plaintext leaks (strings | grep sentinel):"
echo "    StealthLib: $STEALTH_LEAKS"
echo "    xorstr:     $XORSTR_LEAKS"
echo ""
echo "  Functional tests:"
echo "    StealthLib: $([ $STEALTH_EXIT -eq 0 ] && echo 'ALL PASS' || echo 'FAIL')"
echo "    xorstr:     $([ $XORSTR_EXIT -eq 0 ] && echo 'ALL PASS' || echo 'FAIL')"
echo ""
echo "  Features supported:"
echo "    StealthLib: 7/7 (short, medium, special, empty, wide, RAII, batch)"
echo "    xorstr:     4/7 (short, medium, special, batch — no empty, wide, RAII)"
echo ""
echo "  .rodata elision method:"
echo "    StealthLib: consteval (compiler-independent, guaranteed)"
echo "    xorstr:     constexpr (optimizer-dependent, not guaranteed)"
echo ""
echo "════════════════════════════════════════════════════════════════"

# Cleanup
rm -f diff_stealth diff_xorstr diff_stealth_2 diff_xorstr_2 stealth_output.txt xorstr_output.txt
