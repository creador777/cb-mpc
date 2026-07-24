#!/usr/bin/env bash
# =============================================================================
# build_fuzz.sh — compila fuzz_harness_elite.cpp contra cb-mpc con
#                 libFuzzer + AddressSanitizer + UBSan. Correr en WSL2/Linux.
#
# Clave: cb-mpc se recompila con `-fsanitize=fuzzer-no-link,address,undefined`
# para que (a) ASan vea DENTRO de la librería y (b) libFuzzer tenga cobertura
# del código de cb-mpc y guíe las mutaciones hacia adentro. Sin esto, el fuzzer
# vuela a ciegas y NO encuentra bugs profundos.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

: "${CBMPC_OPENSSL_ROOT:=/usr/local/opt/openssl@3.6.1}"
export CBMPC_OPENSSL_ROOT
CXX="${CXX:-clang++}"

# fuzzer-no-link = instrumentación de cobertura SIN el main de libFuzzer (para la lib)
COVSAN="-fsanitize=fuzzer-no-link,address,undefined -fno-sanitize=enum -fno-omit-frame-pointer"

echo "[1/4] OpenSSL estático propio (si falta)..."
if ! find "$CBMPC_OPENSSL_ROOT" -name libcrypto.a 2>/dev/null | grep -q .; then
  make openssl-linux
fi
OSSL_LIB="$(find "$CBMPC_OPENSSL_ROOT" -name libcrypto.a | head -n1)"
OSSL_INC="$CBMPC_OPENSSL_ROOT/include"
[ -n "$OSSL_LIB" ] || { echo "ERROR: no encontré libcrypto.a en $CBMPC_OPENSSL_ROOT"; exit 1; }

echo "[2/4] cb-mpc (Debug + ASan/UBSan + cobertura de fuzzer)..."
cmake -S . -B build/fuzz \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCBMPC_PLATFORM_DEP_OUTPUT_DIR=ON \
  -DCMAKE_C_FLAGS="-g -O1 $COVSAN" \
  -DCMAKE_CXX_FLAGS="-g -O1 $COVSAN" >/dev/null
cmake --build build/fuzz --target cbmpc -j"$(nproc)"

CBMPC_LIB="$(find "$ROOT/build/fuzz" "$ROOT/lib" -name libcbmpc.a 2>/dev/null | head -n1)"
[ -n "$CBMPC_LIB" ] || { echo "ERROR: no encontré libcbmpc.a tras el build"; exit 1; }
echo "     libcbmpc.a -> $CBMPC_LIB"

echo "[3/4] FuzzedDataProvider.h (vendor si falta)..."
cd "$HERE"
if [ ! -f FuzzedDataProvider.h ]; then
  curl -sSLO https://raw.githubusercontent.com/llvm/llvm-project/main/compiler-rt/include/fuzzer/FuzzedDataProvider.h
fi

echo "[4/4] link del harness -> fuzz_elite ..."
"$CXX" -g -O1 -std=c++17 \
  -fsanitize=fuzzer,address,undefined -fno-sanitize=enum -fno-omit-frame-pointer \
  -I"$ROOT/include" -I"$OSSL_INC" -I"$HERE" \
  "$HERE/fuzz_harness_elite.cpp" \
  "$CBMPC_LIB" "$OSSL_LIB" \
  -lpthread -ldl \
  -o "$HERE/fuzz_elite"

echo
echo "OK -> $HERE/fuzz_elite"
echo "Corré (con corpus semilla y límites sanos):"
echo "   mkdir -p corpus"
echo "   ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \\"
echo "   UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \\"
echo "   ./fuzz_elite -rss_limit_mb=4096 -timeout=25 -print_final_stats=1 corpus"