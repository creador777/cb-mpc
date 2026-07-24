#!/usr/bin/env bash
# =============================================================================
# run_all.sh — LANZADOR MULTI-HARNESS. En vez de 16 cores martillando ECDSA
# (que ya llegó a meseta), reparte la máquina entre ECDSA + Schnorr en paralelo
# = el DOBLE de superficie de ataque con la misma electricidad.
#
#   cd fuzz && bash run_all.sh
#   (después, en OTRA ventana: bash fuzz_status.sh   para ver cómo va)
#
# Requisitos: haber compilado antes:
#   bash build_fuzz_malicious.sh   -> crea ./fuzz_malicious   (ECDSA)
#   bash build_fuzz_schnorr.sh     -> crea ./fuzz_schnorr     (Schnorr)
# =============================================================================
set -u
cd "$(dirname "$0")" || exit 1

# --- cuántos cores por harness (16 lógicas: 6+6=12, deja 4 para Windows+monitor) ---
FORKS_ECDSA="${FORKS_ECDSA:-6}"
FORKS_SCHNORR="${FORKS_SCHNORR:-6}"

COMMON="-ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 -rss_limit_mb=4096 -timeout=25 -max_len=2048"
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1"
export UBSAN_OPTIONS="halt_on_error=1"

launched=0

if [ -x ./fuzz_malicious ]; then
  mkdir -p corpus
  nohup ./fuzz_malicious -fork="$FORKS_ECDSA" -artifact_prefix=ecdsa_ $COMMON corpus \
    > run_ecdsa.log 2>&1 &
  echo "  [ECDSA]    PID $!  -> $FORKS_ECDSA cores, log: run_ecdsa.log"
  launched=$((launched+1))
else
  echo "  [ECDSA]    NO existe ./fuzz_malicious — compilá con build_fuzz_malicious.sh"
fi

if [ -x ./fuzz_schnorr ]; then
  mkdir -p corpus_schnorr
  nohup ./fuzz_schnorr -fork="$FORKS_SCHNORR" -artifact_prefix=schnorr_ $COMMON corpus_schnorr \
    > run_schnorr.log 2>&1 &
  echo "  [SCHNORR]  PID $!  -> $FORKS_SCHNORR cores, log: run_schnorr.log"
  launched=$((launched+1))
else
  echo "  [SCHNORR]  NO existe ./fuzz_schnorr — compilá con build_fuzz_schnorr.sh"
fi

echo
if [ "$launched" -eq 0 ]; then
  echo "  Nada lanzado. Compilá los harness primero."
  exit 1
fi
echo "  $launched harness corriendo en paralelo."
echo "  Crashes de ECDSA salen como  ecdsa_crash-*   y los de Schnorr como  schnorr_crash-*"
echo
echo "  Para verlo en vivo (otra ventana):   bash fuzz_status.sh"
echo "  Para parar TODO:                     pkill -f 'fuzz_malicious|fuzz_schnorr'"