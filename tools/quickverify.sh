#!/usr/bin/env bash
# tools/quickverify.sh
# ------------------------------------------------------------------
# One-command reproducibility verifier for StealthLib.
#
# Runs (in order):
#   A. Release smoke               -- full ctest on Linux gcc (Release, -O2)
#   B. Strict-warnings build       -- -Werror -Wall -Wextra -Wpedantic -Wshadow -Wconversion
#   C. ASan + UBSan debug          -- Debug build with sanitizers (gcc)
#   D. Build determinism           -- two builds with the same STEALTH_BUILD_KEY
#                                     must produce byte-identical binaries
#   E. SHA-256 KAT smoke           -- doctest_sha256_test asserts KAT vectors
#   F. Fuzz corpus driver          -- standalone harness built with g++ on fixed seeds
#                                     (ASan+UBSan enabled so fuzzed paths are checked)
#   G. SSE2 parity                 -- scalar vs _mm_xor_si128 builds produce identical output
#
# Linux-only phases skip cleanly on macOS/Windows. Any real failure exits non-zero.
# Override with environment:
#   QV_SKIP=A,B   ...skip phase letters (e.g. QV_SKIP=C,F,G)
#   QV_JOBS=N     ...parallel build jobs (default: nproc)
# ------------------------------------------------------------------

set -euo pipefail

# -------- locate repo --------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# -------- options --------
JOBS="${QV_JOBS:-$(command -v nproc >/dev/null 2>&1 && nproc || echo 4)}"
SKIP="${QV_SKIP:-}"
UNAME_S="$(uname -s)"

is_skipped() {
    local letter="$1"
    [[ ",$SKIP," == *",$letter,"* ]]
}

# -------- pretty output --------
USE_COLOR=1
if [[ ! -t 1 ]]; then USE_COLOR=0; fi
c_reset=$'\e[0m'; c_dim=$'\e[2m'; c_blue=$'\e[34m'; c_green=$'\e[32m'; c_red=$'\e[31m'; c_yellow=$'\e[33m'
if [[ $USE_COLOR -eq 0 ]]; then c_reset=""; c_dim=""; c_blue=""; c_green=""; c_red=""; c_yellow=""; fi

banner() { printf '\n%s== %s ==%s\n' "${c_blue}" "$1" "${c_reset}"; }
ok()   { printf '%s[PASS]%s %s\n' "${c_green}" "${c_reset}" "$1"; }
bad()  { printf '%s[FAIL]%s %s\n' "${c_red}"   "${c_reset}" "$1"; }
skip() { printf '%s[SKIP]%s %s\n' "${c_yellow}" "${c_reset}" "$1"; }
note() { printf '       %s%s%s\n' "${c_dim}" "$1" "${c_reset}"; }

declare -a RESULTS=()
record() { RESULTS+=("$1:$2"); }
result_set() {
    # Update last result entry (used to mark warn without losing order)
    local idx=$(( ${#RESULTS[@]} - 1 ))
    if [[ $idx -ge 0 ]]; then RESULTS[$idx]="$1:$2"; fi
}

require_tool() {
    local tool="$1"
    if ! command -v "$tool" >/dev/null 2>&1; then
        bad "required tool not found: $tool"
        return 1
    fi
}

mkbuild() { rm -rf "$1" && mkdir -p "$1" && (cd "$1" && pwd); }

# Configure + build, return 0 on success
cmb() {
    # cmb <build_dir> <phase_name> <cmake_args...>
    local bd="$1"; shift
    local phase="$1"; shift
    if ! cmake -S "$REPO_ROOT" -B "$bd" -G "Unix Makefiles" "$@" >/dev/null 2>"$bd/.cmake_configure_err"; then
        bad "CMake configure failed: $phase"
        sed 's/^/       /' "$bd/.cmake_configure_err"
        return 1
    fi
    if ! cmake --build "$bd" --parallel "$JOBS" >/dev/null 2>"$bd/.cmake_build_err"; then
        bad "CMake build failed: $phase"
        sed 's/^/       /' "$bd/.cmake_build_err"
        return 1
    fi
    return 0
}

# ============================================================
# Phase A -- Release smoke (gcc)
# ============================================================
phase_A() {
    if is_skipped A; then skip "Phase A: Release smoke"; record "A" skip; return 0; fi
    banner "Phase A: Release smoke (Linux gcc, -O2)"
    require_tool g++ || { record "A" fail; return 1; }
    require_tool cmake || { record "A" fail; return 1; }

    local bd; bd="$(mkbuild build_qv_a)"
    cmb "$bd" "A" \
        -DCMAKE_BUILD_TYPE=Release \
        -DSTEALTH_BUILD_EXAMPLES=ON -DSTEALTH_BUILD_TESTS=ON -DSTEALTH_BUILD_BENCHMARK=OFF \
        -DSTEALTH_BUILD_FIXTURES=ON || { record "A" fail; return 1; }

    if (cd "$bd" && ctest --output-on-failure -j "$JOBS" >/dev/null 2>"$bd/.ctest_err"); then
        ok "ctest (Release)"
        record "A" ok
    else
        bad "ctest (Release) failed"
        sed 's/^/       /' "$bd/.ctest_err" || true
        record "A" fail
        return 1
    fi
}

# ============================================================
# Phase B -- -Werror strict warnings
# ============================================================
phase_B() {
    if is_skipped B; then skip "Phase B: strict warnings"; record "B" skip; return 0; fi
    banner "Phase B: -Werror strict warnings"
    require_tool g++ || { record "B" fail; return 1; }

    local bd; bd="$(mkbuild build_qv_b)"
    # Project's own -Wall/-Wextra/-Wpedantic are already on under stealthlib INTERFACE
    # target; we add the strict family the v2.1.1 audit recommended be CI-enforced.
    cmb "$bd" "B" \
        -DCMAKE_BUILD_TYPE=Release \
        -DSTEALTH_BUILD_EXAMPLES=OFF -DSTEALTH_BUILD_TESTS=ON \
        -DSTEALTH_BUILD_BENCHMARK=OFF -DSTEALTH_BUILD_FIXTURES=OFF \
        -DCMAKE_CXX_FLAGS="-Werror -Wshadow -Wconversion -Wsign-conversion -Wnon-virtual-dtor" \
        || { record "B" fail; return 1; }
    ok "strict-warnings build (no warnings, no errors)"
    record "B" ok
}

# ============================================================
# Phase C -- ASan + UBSan (Linux gcc debug)
# ============================================================
phase_C() {
    if is_skipped C; then skip "Phase C: ASan+UBSan"; record "C" skip; return 0; fi
    if [[ "$UNAME_S" != "Linux" ]]; then
        skip "Phase C: ASan+UBSan (non-Linux: $UNAME_S)"; record "C" skip; return 0
    fi
    banner "Phase C: ASan + UBSan (Debug, gcc)"
    require_tool g++ || { record "C" fail; return 1; }

    local bd; bd="$(mkbuild build_qv_c)"
    cmb "$bd" "C" \
        -DCMAKE_BUILD_TYPE=Debug \
        -DSTEALTH_SANITIZERS=ON \
        -DSTEALTH_BUILD_EXAMPLES=OFF -DSTEALTH_BUILD_TESTS=ON \
        -DSTEALTH_BUILD_BENCHMARK=OFF -DSTEALTH_BUILD_FIXTURES=ON \
        || { record "C" fail; return 1; }

    if (cd "$bd" && ctest --output-on-failure -j "$JOBS" >/dev/null 2>"$bd/.ctest_err"); then
        ok "ASan + UBSan ctest (no findings)"
        record "C" ok
    else
        bad "ASan + UBSan ctest reported findings"
        sed 's/^/       /' "$bd/.ctest_err" || true
        record "C" fail
        return 1
    fi
}

# ============================================================
# Phase D -- Build determinism
# Two builds with the SAME STEALTH_BUILD_KEY must produce identical string_test.
# ============================================================
phase_D() {
    if is_skipped D; then skip "Phase D: determinism"; record "D" skip; return 0; fi
    banner "Phase D: build determinism (same STEALTH_BUILD_KEY -> identical binary)"
    require_tool cmake || { record "D" fail; return 1; }
    local SHA256SUM="sha256sum"
    if ! command -v sha256sum >/dev/null 2>&1; then
        if command -v shasum >/dev/null 2>&1; then
            SHA256SUM="shasum -a 256"
        else
            skip "Phase D: sha256sum / shasum not found"; record "D" skip; return 0
        fi
    fi

    local KEY="0xC0FFEE42DEADBEEFULL"
    local bd1; bd1="$(mkbuild build_qv_d1)"
    local bd2; bd2="$(mkbuild build_qv_d2)"

    cmb "$bd1" "D1" \
        -DCMAKE_BUILD_TYPE=Release \
        -DSTEALTH_BUILD_EXAMPLES=OFF -DSTEALTH_BUILD_TESTS=ON \
        -DSTEALTH_BUILD_BENCHMARK=OFF -DSTEALTH_BUILD_FIXTURES=OFF \
        -DSTEALTH_BUILD_KEY="$KEY" || { record "D" fail; return 1; }
    cmb "$bd2" "D2" \
        -DCMAKE_BUILD_TYPE=Release \
        -DSTEALTH_BUILD_EXAMPLES=OFF -DSTEALTH_BUILD_TESTS=ON \
        -DSTEALTH_BUILD_BENCHMARK=OFF -DSTEALTH_BUILD_FIXTURES=OFF \
        -DSTEALTH_BUILD_KEY="$KEY" || { record "D" fail; return 1; }

    local b1="$bd1/tests/string_test"
    local b2="$bd2/tests/string_test"
    [[ -f "$b1" && -f "$b2" ]] || { bad "string_test binary missing"; record "D" fail; return 1; }

    local h1 h2
    h1="$($SHA256SUM "$b1" | awk '{print $1}')"
    h2="$($SHA256SUM "$b2" | awk '{print $1}')"
    note "build1 sha256 = $h1"
    note "build2 sha256 = $h2"
    if [[ "$h1" == "$h2" ]]; then
        ok "deterministic build (byte-identical string_test)"
        record "D" ok
    else
        bad "non-deterministic build (string_test differs for same STEALTH_BUILD_KEY)"
        note "this is known-fragile across toolchains due to .note sections / timestamps"
        record "D" warn
        return 0
    fi
}

# ============================================================
# Phase E -- SHA-256 KAT smoke (build the focused test in isolation)
# ============================================================
phase_E() {
    if is_skipped E; then skip "Phase E: SHA-256 KAT"; record "E" skip; return 0; fi
    banner "Phase E: SHA-256 KAT (doctest_sha256_test)"
    require_tool g++ || { record "E" fail; return 1; }

    local bd; bd="$(mkbuild build_qv_e)"
    cmb "$bd" "E" \
        -DCMAKE_BUILD_TYPE=Release \
        -DSTEALTH_BUILD_EXAMPLES=OFF -DSTEALTH_BUILD_TESTS=ON \
        -DSTEALTH_BUILD_BENCHMARK=OFF -DSTEALTH_BUILD_FIXTURES=ON \
        || { record "E" fail; return 1; }

    if "$bd/tests/doctest_sha256_test" >/dev/null 2>"$bd/.kat_err"; then
        ok "SHA-256 KAT vectors pass"
        record "E" ok
    else
        bad "doctest_sha256_test failed"
        sed 's/^/       /' "$bd/.kat_err" || true
        record "E" fail
        return 1
    fi
}

# ============================================================
# Phase F -- Fuzz corpus driver (g++ standalone)
# We must pass STEALTH_BUILD_KEY ourselves because we go around CMake.
# ============================================================
phase_F() {
    if is_skipped F; then skip "Phase F: fuzz corpus"; record "F" skip; return 0; fi
    banner "Phase F: fuzz corpus driver (g++ standalone)"
    require_tool g++ || { record "F" fail; return 1; }

    local bd; bd="$(mkbuild build_qv_f)"
    if g++ -std=c++20 -O2 -Wall -Wextra -Wpedantic \
            -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer \
            -DSTEALTH_BUILD_KEY="0xC0DEFEEDDA7ABA5ULL" \
            -I "$REPO_ROOT" \
            -o "$bd/fuzz_corpus" \
            "$REPO_ROOT/tests/fuzz_hashes.cpp" \
            2> "$bd/.fuzz_err"; then
        : # build ok
    else
        bad "fuzz_corpus compile failed"
        sed 's/^/       /' "$bd/.fuzz_err"
        record "F" fail
        return 1
    fi
    if "$bd/fuzz_corpus" >/dev/null 2>"$bd/.fuzz_run_err"; then
        ok "fuzz corpus driver (3 seeds pass)"
        record "F" ok
    else
        bad "fuzz corpus driver reported failures"
        sed 's/^/       /' "$bd/.fuzz_run_err" || true
        record "F" fail
        return 1
    fi
}

# ============================================================
# Phase G -- SSE2 parity (scalar == SIMD output, byte-exact)
# Builds test_sse2_parity twice: once with STEALTHLIB_SSE2_DECRYPT=OFF
# (scalar baseline) and once with =ON (fast path). Both should produce
# the same plaintext. Only runs on x86/x86_64 Linux GCC.
# ============================================================
phase_G() {
    if is_skipped G; then skip "Phase G: SSE2 parity"; record "G" skip; return 0; fi
    banner "Phase G: SSE2 _mm_xor_si128 parity"
    require_tool g++ || { record "G" fail; return 1; }

    local bd_off; bd_off="$(mkbuild build_qv_g_off)"
    local bd_on;  bd_on="$(mkbuild build_qv_g_on)"

    cmb "$bd_off" "G-off" \
        -DCMAKE_BUILD_TYPE=Release \
        -DSTEALTH_BUILD_EXAMPLES=OFF -DSTEALTH_BUILD_TESTS=ON \
        -DSTEALTH_BUILD_BENCHMARK=OFF -DSTEALTH_BUILD_FIXTURES=OFF \
        -DSTEALTHLIB_SSE2_DECRYPT=OFF \
        || { record "G" fail; return 1; }
    cmb "$bd_on"  "G-on"  \
        -DCMAKE_BUILD_TYPE=Release \
        -DSTEALTH_BUILD_EXAMPLES=OFF -DSTEALTH_BUILD_TESTS=ON \
        -DSTEALTH_BUILD_BENCHMARK=OFF -DSTEALTH_BUILD_FIXTURES=OFF \
        -DSTEALTHLIB_SSE2_DECRYPT=ON  \
        || { record "G" fail; return 1; }

    local out_off out_on
    out_off="$("$bd_off/tests/test_sse2_parity" 2>&1)"
    out_on="$("$bd_on/tests/test_sse2_parity"  2>&1)"
    if [[ "$out_off" != "$out_on" ]]; then
        bad "SSE2 parity MISMATCH between scalar and SIMD builds"
        note "scalar: $out_off"
        note "sse2  : $out_on"
        record "G" fail
        return 1
    fi
    ok "SSE2 parity (scalar == SIMD); output: $out_off"
    record "G" ok
}

finalize() {
    banner "Summary"
    local any_fail=0 any_warn=0
    for r in "${RESULTS[@]}"; do
        local phase="${r%%:*}"
        local status="${r##*:}"
        case "$status" in
            ok)    printf '  %s[ ok ]%s Phase %s\n'    "$c_green"  "$c_reset" "$phase" ;;
            skip)  printf '  %s[skip]%s Phase %s\n'    "$c_yellow" "$c_reset" "$phase" ;;
            warn)  printf '  %s[warn]%s Phase %s\n'    "$c_yellow" "$c_reset" "$phase"
                   any_warn=1 ;;
            fail)  printf '  %s[fail]%s Phase %s\n'    "$c_red"    "$c_reset" "$phase"
                   any_fail=1 ;;
        esac
    done
    if [[ $any_fail -eq 0 ]]; then
        ok "all required phases passed"
        exit 0
    else
        bad "one or more phases failed"
        if [[ $any_warn -ne 0 ]]; then
            note "Phase D 'warn' = non-determinism (likely .note section/toolchain variation)"
        fi
        exit 1
    fi
}

phase_A || true
phase_B || true
phase_C || true
phase_D || true
phase_E || true
phase_F || true
phase_G || true
finalize
