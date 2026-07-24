#!/usr/bin/env bash
# =============================================================================
# build_fuzz_tdh2.sh — compila fuzz_tdh2.cpp (harness de TDH2 Threshold Decryption)
# contra cb-mpc con libFuzzer + ASan + UBSan.
#
# TDH2 = Threshold Encryption, protocolo NO INTERACTIVO post-DKG.
# El harness corre dkg_additive (interactivo) UNA vez en bootstrap,
# y después fuzzea encrypt/partial_decrypt/combine_additive LOCALMENTE.
#
# Uso: bash fuzz/build_fuzz_tdh2.sh
# Correr en WSL2/Linux, raíz del repo cb-mpc.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

: "${CBMPC_OPENSSL_ROOT:=/usr/local/opt/openssl@3.6.1}"
export CBMPC_OPENSSL_ROOT

CC="${CC:-clang-20}"
CXX="${CXX:-clang++-20}"

# Fallback if clang-20 not available
if ! command -v "$CC" &>/dev/null; then CC=clang; fi
if ! command -v "$CXX" &>/dev/null; then CXX=clang++; fi

echo "[TDH2 FUZZ] Using CC=$CC CXX=$CXX"

# Sanitizer flags — NO sanitize=enum (cb-mpc usa enum comparisons extensivamente)
COVSAN="-fsanitize=fuzzer-no-link,address,undefined -fno-sanitize=enum -fno-omit-frame-pointer"

echo "[1/4] OpenSSL estático propio (si falta)..."
if ! find "$CBMPC_OPENSSL_ROOT" -name libcrypto.a 2>/dev/null | grep -q .; then
  echo "       OpenSSL no encontrado en $CBMPC_OPENSSL_ROOT, compilando..."
  make openssl-linux 2>/dev/null || {
    echo "ERROR: No se pudo compilar OpenSSL. Instalalo manualmente:"
    echo "  CBMPC_OPENSSL_ROOT=/path/to/openssl make openssl-linux"
    exit 1
  }
fi

OSSL_LIB="$(find "$CBMPC_OPENSSL_ROOT" -name libcrypto.a 2>/dev/null | head -n1)"
OSSL_INC="$CBMPC_OPENSSL_ROOT/include"

if [ -z "$OSSL_LIB" ]; then
  echo "ERROR: no encontré libcrypto.a en $CBMPC_OPENSSL_ROOT"
  echo "  Buildéalo con: make openssl-linux"
  exit 1
fi
echo "       libcrypto.a -> $OSSL_LIB"

echo "[2/4] cb-mpc (Debug + ASan/UBSan + cobertura de fuzzer)..."
# Si cmake se queja de "compiler changed", borrá build/fuzz a mano
if [ ! -f build/fuzz/build.ninja ] && [ ! -f build/fuzz/Makefile ]; then
  cmake -S . -B build/fuzz \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_BUILD_TYPE=Debug -DCBMPC_PLATFORM_DEP_OUTPUT_DIR=ON \
    -DCMAKE_C_FLAGS="-g -O1 $COVSAN" -DCMAKE_CXX_FLAGS="-g -O1 $COVSAN" >/dev/null
fi

cmake --build build/fuzz --target cbmpc -j"$(nproc)"

CBMPC_LIB="$(find "$ROOT/build/fuzz" "$ROOT/lib" -name libcbmpc.a 2>/dev/null | head -n1)"
if [ -z "$CBMPC_LIB" ]; then
  echo "ERROR: no encontré libcbmpc.a en build/fuzz/ ni lib/"
  echo "  Compilá cb-mpc primero: make build"
  exit 1
fi
echo "       libcbmpc.a -> $CBMPC_LIB"

echo "[3/4] FuzzedDataProvider.h (vendor en fuzzer/ si falta)..."
mkdir -p "$HERE/fuzzer"
if [ ! -f "$HERE/fuzzer/FuzzedDataProvider.h" ]; then
  curl -sSL -o "$HERE/fuzzer/FuzzedDataProvider.h" \
    https://raw.githubusercontent.com/llvm/llvm-project/main/compiler-rt/include/fuzzer/FuzzedDataProvider.h
  echo "       descargado FuzzedDataProvider.h"
fi

echo "[4/4] link -> fuzz_tdh2 ..."

LINK_FLAGS="-fsanitize=fuzzer,address,undefined -fno-sanitize=enum -fno-omit-frame-pointer"

"$CXX" -g -O1 -std=c++17 \
  $LINK_FLAGS \
  -I"$ROOT/include" -I"$OSSL_INC" -I"$HERE" \
  "$HERE/fuzz_tdh2.cpp" \
  "$CBMPC_LIB" "$OSSL_LIB" -lpthread -ldl \
  -o "$HERE/fuzz_tdh2"

echo
echo "============================================"
echo " BUILD OK → $HERE/fuzz_tdh2"
echo "============================================"
echo
echo "Para correr toda la noche:"
echo
echo "  cd fuzz && mkdir -p corpus_tdh2"
echo
echo "  # Limpiar cache de DKG si querés regenerar:"
echo "  # rm -f cbmpc_tdh2_pk.bin cbmpc_tdh2_sk*.bin cbmpc_tdh2_ps*.bin"
echo
echo "  ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \\"
echo "  UBSAN_OPTIONS=halt_on_error=1 \\"
echo "  ./fuzz_tdh2 -fork=4 -rss_limit_mb=4096 -timeout=25 \\"
echo "      -max_total_time=28800 corpus_tdh2"
echo
echo "  # Con más cores:"
echo "  # ./fuzz_tdh2 -fork=$(nproc) -rss_limit_mb=4096 -timeout=25 corpus_tdh2"
echo
echo "NOTA: El DKG bootstrap se cachea en cbmpc_tdh2_*.bin."
echo "      Borrá esos archivos si querés regenerar las claves."
