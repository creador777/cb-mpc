#!/usr/bin/env bash
# =============================================================================
# build_fuzz_malicious.sh — compila fuzz_malicious_party.cpp (harness v2)
# contra cb-mpc con libFuzzer + ASan + UBSan. Correr en WSL2/Linux, raíz del repo.
#
# Targets:
#   fuzz_malicious      — 2P ECDSA (sign + refresh)
#   fuzz_malicious_mp   — 2P + 3P Multi-Party ECDSA (sign + refresh additive)
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

echo "[1/5] OpenSSL estático propio (si falta)..."
if ! find "$CBMPC_OPENSSL_ROOT" -name libcrypto.a 2>/dev/null | grep -q .; then make openssl-linux; fi
OSSL_LIB="$(find "$CBMPC_OPENSSL_ROOT" -name libcrypto.a | head -n1)"
OSSL_INC="$CBMPC_OPENSSL_ROOT/include"
[ -n "$OSSL_LIB" ] || { echo "ERROR: no encontré libcrypto.a"; exit 1; }

echo "[2/5] cb-mpc (Debug + ASan/UBSan + cobertura de fuzzer)..."
cmake -S . -B build/fuzz \
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_BUILD_TYPE=Debug -DCBMPC_PLATFORM_DEP_OUTPUT_DIR=ON \
  -DCMAKE_C_FLAGS="-g -O1 $COVSAN" -DCMAKE_CXX_FLAGS="-g -O1 $COVSAN" >/dev/null
cmake --build build/fuzz --target cbmpc -j"$(nproc)"
CBMPC_LIB="$(find "$ROOT/build/fuzz" "$ROOT/lib" -name libcbmpc.a 2>/dev/null | head -n1)"
[ -n "$CBMPC_LIB" ] || { echo "ERROR: no encontré libcbmpc.a"; exit 1; }
echo "     libcbmpc.a -> $CBMPC_LIB"

echo "[3/5] FuzzedDataProvider.h (vendor en fuzzer/ si falta)..."
mkdir -p "$HERE/fuzzer"
if [ ! -f "$HERE/fuzzer/FuzzedDataProvider.h" ]; then
  curl -sSL -o "$HERE/fuzzer/FuzzedDataProvider.h" \
    https://raw.githubusercontent.com/llvm/llvm-project/main/compiler-rt/include/fuzzer/FuzzedDataProvider.h
fi

LINK_FLAGS="-fsanitize=fuzzer,address,undefined -fno-sanitize=enum -fno-omit-frame-pointer"
INCLUDES="-I\"$ROOT/include\" -I\"$OSSL_INC\" -I\"$HERE\""

echo "[4/5] link -> fuzz_malicious (2P) ..."
"$CXX" -g -O1 -std=c++17 \
  $LINK_FLAGS \
  -I"$ROOT/include" -I"$OSSL_INC" -I"$HERE" \
  "$HERE/fuzz_malicious_party.cpp" \
  "$CBMPC_LIB" "$OSSL_LIB" -lpthread -ldl \
  -o "$HERE/fuzz_malicious"

echo "[5/5] link -> fuzz_malicious_mp (2P + 3P Multi-Party) ..."
"$CXX" -g -O1 -std=c++17 \
  $LINK_FLAGS \
  -DFUZZ_ECDSA_MP \
  -I"$ROOT/include" -I"$OSSL_INC" -I"$HERE" \
  "$HERE/fuzz_malicious_party.cpp" \
  "$CBMPC_LIB" "$OSSL_LIB" -lpthread -ldl \
  -o "$HERE/fuzz_malicious_mp"

echo
echo "=== BUILD OK ==="
echo "  2P target  -> $HERE/fuzz_malicious"
echo "  MP target  -> $HERE/fuzz_malicious_mp"
echo
echo "=== CORRER TODA LA NOCHE (pegar en terminal WSL2): ==="
echo
echo "  cd $HERE && mkdir -p corpus corpus_mp"
echo
echo "  # --- 2P (4 cores) ---"
echo "  ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \\"
echo "  ./fuzz_malicious -fork=4 -rss_limit_mb=4096 -timeout=25 -max_total_time=28800 corpus &"
echo
echo "  # --- MP (4 cores) ---"
echo "  ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \\"
echo "  ./fuzz_malicious_mp -fork=4 -rss_limit_mb=4096 -timeout=25 -max_total_time=28800 corpus_mp &"
echo
echo "  wait  # espera a ambos"