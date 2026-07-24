#!/usr/bin/env bash
# =============================================================================
# build_fuzz_schnorr.sh — compila fuzz_schnorr_party.cpp (harness de Schnorr/BIP340 2P)
# contra cb-mpc con libFuzzer + ASan + UBSan. Correr en WSL2/Linux, raíz del repo.
# Reusa el mismo build/fuzz de cb-mpc que build_fuzz_malicious.sh (la lib es la misma).
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

echo "[1/4] OpenSSL estático propio (si falta)..."
if ! find "$CBMPC_OPENSSL_ROOT" -name libcrypto.a 2>/dev/null | grep -q .; then make openssl-linux; fi
OSSL_LIB="$(find "$CBMPC_OPENSSL_ROOT" -name libcrypto.a | head -n1)"
OSSL_INC="$CBMPC_OPENSSL_ROOT/include"
[ -n "$OSSL_LIB" ] || { echo "ERROR: no encontré libcrypto.a"; exit 1; }

echo "[2/4] cb-mpc (Debug + ASan/UBSan + cobertura de fuzzer)..."
# (si alguna vez cmake se queja de "compiler changed", borrá build/fuzz a mano una vez)
cmake -S . -B build/fuzz \
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_BUILD_TYPE=Debug -DCBMPC_PLATFORM_DEP_OUTPUT_DIR=ON \
  -DCMAKE_C_FLAGS="-g -O1 $COVSAN" -DCMAKE_CXX_FLAGS="-g -O1 $COVSAN" >/dev/null
cmake --build build/fuzz --target cbmpc -j"$(nproc)"
CBMPC_LIB="$(find "$ROOT/build/fuzz" "$ROOT/lib" -name libcbmpc.a 2>/dev/null | head -n1)"
[ -n "$CBMPC_LIB" ] || { echo "ERROR: no encontré libcbmpc.a"; exit 1; }
echo "     libcbmpc.a -> $CBMPC_LIB"

echo "[3/4] FuzzedDataProvider.h (vendor en fuzzer/ si falta)..."
mkdir -p "$HERE/fuzzer"
if [ ! -f "$HERE/fuzzer/FuzzedDataProvider.h" ]; then
  curl -sSL -o "$HERE/fuzzer/FuzzedDataProvider.h" \
    https://raw.githubusercontent.com/llvm/llvm-project/main/compiler-rt/include/fuzzer/FuzzedDataProvider.h
fi

echo "[4/4] link -> fuzz_schnorr ..."
"$CXX" -g -O1 -std=c++17 \
  -fsanitize=fuzzer,address,undefined -fno-sanitize=enum -fno-omit-frame-pointer \
  -I"$ROOT/include" -I"$OSSL_INC" -I"$HERE" \
  "$HERE/fuzz_schnorr_party.cpp" \
  "$CBMPC_LIB" "$OSSL_LIB" -lpthread -ldl \
  -o "$HERE/fuzz_schnorr"

echo
echo "OK -> $HERE/fuzz_schnorr"
echo "Corré (usá corpus_schnorr aparte del de ecdsa):"
echo "   cd fuzz && mkdir -p corpus_schnorr"
echo "   ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \\"
echo "   ./fuzz_schnorr -fork=4 -ignore_crashes=1 -rss_limit_mb=4096 -timeout=25 corpus_schnorr"
echo "   # (el DKG de Schnorr se genera 1 vez y queda en cbmpc_schnorr_key1.bin/key2.bin)"