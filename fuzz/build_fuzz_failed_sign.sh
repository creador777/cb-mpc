#!/usr/bin/env bash
# =============================================================================
# build_fuzz_failed_sign.sh — compila fuzz_failed_sign.cpp contra cb-mpc
# (mismo patron que build_fuzz_schnorr.sh, verificado en la granja)
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

: "${CBMPC_OPENSSL_ROOT:=/usr/local/opt/openssl@3.6.1}"
export CBMPC_OPENSSL_ROOT
CC="${CC:-clang}"
CXX="${CXX:-clang++}"
COVSAN="-fsanitize=fuzzer-no-link,address,undefined -fno-sanitize=enum -fno-omit-frame-pointer"

echo "[1/4] OpenSSL estatico propio (si falta)..."
if ! find "$CBMPC_OPENSSL_ROOT" -name libcrypto.a 2>/dev/null | grep -q .; then make openssl-linux; fi
OSSL_LIB="$(find "$CBMPC_OPENSSL_ROOT" -name libcrypto.a | head -n1)"
OSSL_INC="$CBMPC_OPENSSL_ROOT/include"
[ -n "$OSSL_LIB" ] || { echo "ERROR: no encontre libcrypto.a"; exit 1; }

echo "[2/4] cb-mpc (Debug + ASan/UBSan + cobertura de fuzzer)..."
cmake -S . -B build/fuzz \
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_BUILD_TYPE=Debug -DCBMPC_PLATFORM_DEP_OUTPUT_DIR=ON \
  -DCMAKE_C_FLAGS="-g -O1 $COVSAN" -DCMAKE_CXX_FLAGS="-g -O1 $COVSAN" >/dev/null
cmake --build build/fuzz --target cbmpc -j"$(nproc)"
CBMPC_LIB="$(find "$ROOT/build/fuzz" "$ROOT/lib" -name libcbmpc.a 2>/dev/null | head -n1)"
[ -n "$CBMPC_LIB" ] || { echo "ERROR: no encontre libcbmpc.a"; exit 1; }

echo "[3/4] FuzzedDataProvider.h (vendor en fuzzer/ si falta)..."
mkdir -p "$HERE/fuzzer"
if [ ! -f "$HERE/fuzzer/FuzzedDataProvider.h" ]; then
  curl -sSL -o "$HERE/fuzzer/FuzzedDataProvider.h" \
    https://raw.githubusercontent.com/llvm/llvm-project/main/compiler-rt/include/fuzzer/FuzzedDataProvider.h
fi

echo "[4/4] link -> fuzz_failed_sign ..."
"$CXX" -g -O1 -std=c++17 \
  -fsanitize=fuzzer,address,undefined -fno-sanitize=enum -fno-omit-frame-pointer \
  -I"$ROOT/include" -I"$OSSL_INC" -I"$HERE" \
  "$HERE/fuzz_failed_sign.cpp" \
  "$CBMPC_LIB" "$OSSL_LIB" -lpthread -ldl \
  -o "$HERE/fuzz_failed_sign"

echo
echo "OK -> $HERE/fuzz_failed_sign"
