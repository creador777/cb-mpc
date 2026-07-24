#!/usr/bin/env bash
# =============================================================================
# build_poc.sh — compila poc_refresh_dos.cpp (PoC mínimo, SIN fuzzer/RNG hook).
# Reusa la libcbmpc.a con ASan/UBSan que ya construyó build_fuzz_malicious.sh.
# =============================================================================
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
: "${CBMPC_OPENSSL_ROOT:=/usr/local/opt/openssl@3.6.1}"
CXX="${CXX:-clang++}"

OSSL_LIB="$(find "$CBMPC_OPENSSL_ROOT" -name libcrypto.a | head -n1)"
OSSL_INC="$CBMPC_OPENSSL_ROOT/include"
CBMPC_LIB="$(find "$ROOT/build/fuzz" "$ROOT/lib" -name libcbmpc.a 2>/dev/null | head -n1)"
[ -n "$CBMPC_LIB" ] || { echo "ERROR: no encontré libcbmpc.a. Corré primero: bash build_fuzz_malicious.sh"; exit 1; }
[ -n "$OSSL_LIB" ] || { echo "ERROR: no encontré libcrypto.a en $CBMPC_OPENSSL_ROOT"; exit 1; }

echo "[*] Compilando PoC (ASan/UBSan, sin libFuzzer)..."
"$CXX" -g -O1 -std=c++17 \
  -fsanitize=address,undefined -fno-sanitize=enum -fno-omit-frame-pointer \
  -I"$ROOT/include" -I"$OSSL_INC" \
  "$HERE/poc_refresh_dos.cpp" \
  "$CBMPC_LIB" "$OSSL_LIB" -lpthread -ldl \
  -o "$HERE/poc_refresh_dos"

echo "OK -> $HERE/poc_refresh_dos"
echo "Corré:  ASAN_OPTIONS=abort_on_error=1 ./poc_refresh_dos"