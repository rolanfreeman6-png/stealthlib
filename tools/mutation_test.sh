#!/bin/bash
set +e
cd /builds/rolanfreeman6/stealthlib 2>/dev/null || cd /mnt/c/Users/asad/stealthlib

KEY="-DSTEALTH_BUILD_KEY=${BUILD_KEY:-0xC0FFEE42DEADBEEFULL}"
INC="-I . -I tests/third_party"
FLAGS="-std=c++20 -O1 $KEY $INC"
FAST="string_test portable_smoke_test"

total=0; killed=0; survived=0

run_mut() {
    total=$((total + 1))
    cp "$2" /tmp/mut_bak.hpp
    sed -i "s|$3|$4|g" "$2" 2>/dev/null
    if [ $? -ne 0 ]; then total=$((total-1)); cp /tmp/mut_bak.hpp "$2"; return; fi
    
    any_fail=0; any_compile=0
    for t in $FAST; do
        g++ $FLAGS tests/${t}.cpp -o /tmp/${t}_m 2>/dev/null
        if [ $? -eq 0 ]; then
            any_compile=1
            /tmp/${t}_m >/dev/null 2>&1
            rc=$?
            if [ $rc -ne 0 ]; then any_fail=1; fi
            rm -f /tmp/${t}_m
        fi
    done
    
    if [ $any_compile -eq 0 ]; then
        killed=$((killed+1))
    elif [ $any_fail -eq 1 ]; then
        killed=$((killed+1))
    else
        survived=$((survived+1))
    fi
    cp /tmp/mut_bak.hpp "$2"
}

run_mut "enc_xor" "stealthlib/detail/encryption.hpp" "b \^= static_cast<uint8_t>(var_mask" "b += static_cast<uint8_t>(var_mask"
run_mut "enc_mask" "stealthlib/detail/encryption.hpp" "0xA5,0xB6,0xC7,0xD8" "0x00,0xB6,0xC7,0xD8"
run_mut "hash_fnv_prime" "stealthlib/detail/hashes.hpp" "0x100000001B3ULL" "0x100000001B4ULL"
run_mut "hash_fnv_basis" "stealthlib/detail/hashes.hpp" "0xCBF29CE484222325ULL" "0xCBF29CE484222326ULL"
run_mut "hash_djb2_shift" "stealthlib/detail/hashes.hpp" "(h << 5) + h" "(h << 4) + h"
run_mut "sha_K0" "stealthlib/detail/sha256.hpp" "0x428a2f98" "0x428a2f99"
run_mut "sha_h0" "stealthlib/detail/sha256.hpp" "h\[0\]=0x6a09e667" "h[0]=0x6a09e668"
run_mut "sha_bits" "stealthlib/detail/sha256.hpp" "total_bytes \* 8" "total_bytes * 4"
run_mut "mem_zero" "stealthlib/memory/memory.hpp" "\*p\+\+ = 0" "*p++ = 1"
run_mut "mem_cmp" "stealthlib/memory/memory.hpp" "return diff == 0" "return diff != 0"
run_mut "enc_b64" "stealthlib/encoding/encoding.hpp" "\"ABCDEFGHIJKLMNOPQRSTUVWXYZ" "\"BBCDEFGHIJKLMNOPQRSTUVWXYZ"
run_mut "enc_hex" "stealthlib/encoding/encoding.hpp" "\"0123456789ABCDEF\"" "\"1123456789ABCDEF\""
run_mut "enc_rot13" "stealthlib/encoding/encoding.hpp" "(ch - 'a' + 13) % 26" "(ch - 'a' + 14) % 26"
run_mut "enc_xor_crypt" "stealthlib/encoding/encoding.hpp" "d\[i\] \^= key\[i\]" "d[i] += key[i]"
run_mut "sha_offby1" "stealthlib/detail/sha256.hpp" "i < 16" "i <= 16"
run_mut "sha_offby1_64" "stealthlib/detail/sha256.hpp" "i < 64" "i <= 64"
run_mut "b64_remove_check" "stealthlib/encoding/encoding.hpp" "if (str.size() % 4 != 0) return std::nullopt;" "/* removed */"
run_mut "hex_remove_check" "stealthlib/encoding/encoding.hpp" "if (str.size() % 2 != 0) return std::nullopt;" "/* removed */"
run_mut "sha_delete_block" "stealthlib/detail/sha256.hpp" "process_block(buf);" "/* deleted */"
run_mut "sha_double_pad" "stealthlib/detail/sha256.hpp" "buf\[buf_used++\] = 0x80" "buf[buf_used++] = 0x80; buf[buf_used++] = 0x80"

echo "MUTATION_TOTAL=$total"
echo "MUTATION_KILLED=$killed"
echo "MUTATION_SURVIVED=$survived"
echo "MUTATION_SCORE=$(echo "scale=1; $killed * 100 / $total" | bc)%"

echo "=== Mutation Testing Results ===" > mutation_results.txt
echo "Total: $total" >> mutation_results.txt
echo "Killed: $killed" >> mutation_results.txt
echo "Survived: $survived" >> mutation_results.txt
echo "Score: $(echo "scale=1; $killed * 100 / $total" | bc)%" >> mutation_results.txt

rm -f /tmp/mut_bak.hpp
exit 0
