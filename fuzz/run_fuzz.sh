#!/usr/bin/env bash
# =============================================================================
# run_fuzz.sh — Orquestador de campaña para fuzz_malicious (cb-mpc red-team)
# -----------------------------------------------------------------------------
# Qué hace, y por qué cada cosa sube el rendimiento:
#   1) DISCO ext4: copia el binario + claves + corpus a ~/cbmpc-fuzz (disco Linux
#      nativo). Fuzzear en /mnt/c (disco Windows) es 5-10x más lento por el I/O
#      de los miles de archivos chicos del corpus. Esto lo arregla.
#   2) CORPUS SEMILLA: si el corpus está vacío, siembra inputs variados para que
#      libFuzzer arranque "caliente" en vez de gastar tiempo aprendiendo a pasar
#      la deserialización desde cero.
#   3) CORRE los N jobs por un tiempo dado (default 1h).
#   4) AUTO-TRIAGE: para cada crash/oom/timeout, reproduce y CLASIFICA el frame
#      culpable:
#         [HARNESS]   -> el fallo está en fuzz_malicious_party.cpp  = bug NUESTRO,
#                        NO es bounty. Se arregla y a seguir.
#         [CANDIDATO] -> el fallo está en src/cbmpc / include/cbmpc = MIRAR YA.
#                        Puede ser bounty-eligible.
#      Regla de oro que aprendimos a los golpes: no todo lo rojo es plata.
#
# Uso:
#   bash run_fuzz.sh                 # 9 jobs, 1 hora
#   bash run_fuzz.sh -t 28800        # 8 horas
#   bash run_fuzz.sh -j 4 -t 600     # 4 jobs, 10 min (prueba rápida)
#   bash run_fuzz.sh --triage-only   # solo re-clasificar crashes ya existentes
# =============================================================================
set -uo pipefail

# ----------------------------- Config ----------------------------------------
JOBS="$( (nproc 2>/dev/null || echo 4) )"
TOTAL_TIME=3600                 # segundos de campaña
RSS_MB=4096
UNIT_TIMEOUT=25                 # seg por input (bajo ASan el sign es lento)
SEED_COUNT=64                   # inputs semilla a generar si el corpus está vacío
WORK_DEFAULT="$HOME/cbmpc-fuzz" # disco ext4 nativo
TRIAGE_ONLY=0

HERE="$(cd "$(dirname "$0")" && pwd)"   # .../fuzz en /mnt/c
BIN_SRC="$HERE/fuzz_malicious"

while getopts ":j:t:w:s:h-:" opt; do
  case "$opt" in
    j) JOBS="$OPTARG" ;;
    t) TOTAL_TIME="$OPTARG" ;;
    w) WORK_DEFAULT="$OPTARG" ;;
    s) SEED_COUNT="$OPTARG" ;;
    -) case "$OPTARG" in triage-only) TRIAGE_ONLY=1 ;; esac ;;
    h) grep -E '^# (Uso:|  )' "$0" | sed 's/^# //'; exit 0 ;;
    *) ;;
  esac
done

WORK="$WORK_DEFAULT"
CORPUS="$WORK/corpus"
ART="$WORK/artifacts"          # crash-*/oom-*/timeout-* van acá
LOGS="$WORK/logs"

[ -x "$BIN_SRC" ] || { echo "ERROR: no existe el binario $BIN_SRC. Compilá primero: bash build_fuzz_malicious.sh"; exit 1; }

mkdir -p "$WORK" "$CORPUS" "$ART" "$LOGS"

# ----------------------- Setup del workdir ext4 ------------------------------
# Copiamos binario + claves (el harness lee cbmpc_key*.bin desde el CWD).
cp -f "$BIN_SRC" "$WORK/fuzz_malicious"
for k in cbmpc_key1.bin cbmpc_key2.bin; do
  [ -f "$HERE/$k" ] && cp -f "$HERE/$k" "$WORK/$k"
done
BIN="$WORK/fuzz_malicious"

cd "$WORK"

# Si no hay claves, generarlas una vez (bootstrap DKG limpio).
if [ ! -f cbmpc_key1.bin ] || [ ! -f cbmpc_key2.bin ]; then
  echo "[*] Generando claves de referencia (1 vez)..."
  ASAN_OPTIONS=detect_leaks=0 "$BIN" -runs=1 >/dev/null 2>&1 || true
  [ -f cbmpc_key1.bin ] || { echo "ERROR: no se pudieron generar las claves"; exit 1; }
fi

# =============================================================================
# CLASIFICADOR: reproduce un artefacto y decide HARNESS vs CANDIDATO.
# =============================================================================
classify() {
  local f="$1" out frame verdict loc
  out="$(ASAN_OPTIONS=detect_leaks=0:symbolize=1:abort_on_error=1 \
         UBSAN_OPTIONS=print_stacktrace=1:symbolize=1 \
         timeout -s KILL "$UNIT_TIMEOUT" "$BIN" "$f" 2>&1)"

  # Primer frame de "aplicación" (saltando internals de asan/ubsan/libfuzzer/std/libc).
  frame="$(printf '%s\n' "$out" \
    | grep -aE '^[[:space:]]*#[0-9]+ ' \
    | grep -avE '(__asan|__ubsan|__sanitizer|fuzzer::|__interceptor|__libc|libc\.so|_start|operator new|std::|__cxa|abort|raise)' \
    | head -n1)"

  if printf '%s' "$frame" | grep -qE 'fuzz_malicious_party\.cpp'; then
    verdict="HARNESS"    # bug nuestro
  elif printf '%s' "$frame" | grep -qE '(src/cbmpc|include/cbmpc|include-internal/cbmpc)'; then
    verdict="CANDIDATO"  # cb-mpc -> mirar
  elif printf '%s' "$out" | grep -qaE 'CRITICAL \[(SIGN-BREAK|REFRESH-BREAK|NONCE-REUSE|KEY-LEAK)\]'; then
    verdict="CANDIDATO"  # oráculo lógico disparó
  else
    verdict="REVISAR"    # no clasificable automáticamente
  fi
  loc="$(printf '%s' "$frame" | sed -E 's/^[[:space:]]*#[0-9]+[[:space:]]+0x[0-9a-f]+[[:space:]]+in[[:space:]]+//; s/ \(.*//' | cut -c1-90)"
  printf '%s\t%s\t%s\n' "$verdict" "$f" "$loc"
}

triage() {
  echo
  echo "=========================================================================="
  echo " AUTO-TRIAGE de crashes"
  echo "=========================================================================="
  shopt -s nullglob
  local arts=( "$ART"/crash-* "$ART"/oom-* "$ART"/timeout-* "$WORK"/crash-* "$WORK"/oom-* "$WORK"/timeout-* )
  shopt -u nullglob
  if [ "${#arts[@]}" -eq 0 ]; then
    echo "Sin crashes. El fuzzer barrió sin encontrar nada que rompiera (lo más común contra un target blindado)."
    return
  fi
  local report="$WORK/triage.tsv"; : > "$report"
  local seen_harness=0 seen_cand=0 seen_rev=0
  # dedup por hash de firma para no repetir el mismo bug N veces
  declare -A seen_sig
  for f in "${arts[@]}"; do
    [ -f "$f" ] || continue
    local line sig
    line="$(classify "$f")"
    sig="$(printf '%s' "$line" | cut -f1,3)"   # verdicto+loc como firma
    if [ -n "${seen_sig[$sig]:-}" ]; then continue; fi
    seen_sig[$sig]=1
    printf '%s\n' "$line" >> "$report"
    case "$line" in
      HARNESS*)   seen_harness=$((seen_harness+1)) ;;
      CANDIDATO*) seen_cand=$((seen_cand+1)) ;;
      *)          seen_rev=$((seen_rev+1)) ;;
    esac
  done

  echo
  echo "Grupos únicos encontrados:"
  echo "  [HARNESS]   bugs nuestros (ignorar/arreglar): $seen_harness"
  echo "  [CANDIDATO] posibles cb-mpc (MIRAR):          $seen_cand"
  echo "  [REVISAR]   no clasificados:                  $seen_rev"
  echo
  echo "Detalle (verdicto  |  archivo  |  función culpable):"
  sort "$report" | awk -F'\t' '{printf "  %-10s %s\n              %s\n", $1, $2, $3}'
  echo
  if [ "$seen_cand" -gt 0 ] || [ "$seen_rev" -gt 0 ]; then
    echo ">>> Hay CANDIDATO/REVISAR. Traé esos archivos a Claude ANTES de reportar nada."
  else
    echo ">>> Todos los crashes son del harness (nuestros). NADA que reportar a Coinbase."
  fi
  echo "TSV completo: $report"
}

if [ "$TRIAGE_ONLY" -eq 1 ]; then triage; exit 0; fi

# ----------------------- Corpus semilla --------------------------------------
if [ -z "$(ls -A "$CORPUS" 2>/dev/null)" ]; then
  echo "[*] Sembrando corpus ($SEED_COUNT inputs variados) en $CORPUS ..."
  # Inputs de tamaños variados con /dev/urandom. El CustomMutator del harness les
  # da estructura; tener semillas no-vacías de tamaños diversos acelera el arranque.
  sizes=(8 16 24 32 48 64 96 128 192 256 384 512)
  for i in $(seq 1 "$SEED_COUNT"); do
    sz=${sizes[$((i % ${#sizes[@]}))]}
    head -c "$sz" /dev/urandom > "$CORPUS/seed_$i.bin"
  done
fi

# ----------------------- Campaña ---------------------------------------------
echo "=========================================================================="
echo " Campaña de fuzzing"
echo "   binario : $BIN   (ejecutando desde ext4: $WORK)"
echo "   jobs    : $JOBS   tiempo: ${TOTAL_TIME}s   timeout/input: ${UNIT_TIMEOUT}s"
echo "   corpus  : $CORPUS   artefactos: $ART"
echo "=========================================================================="
echo "[*] Disparando. Progreso en vivo:  tail -f $LOGS/fuzz-0.log"
echo

ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  "$BIN" -jobs="$JOBS" -workers="$JOBS" \
         -max_total_time="$TOTAL_TIME" -rss_limit_mb="$RSS_MB" -timeout="$UNIT_TIMEOUT" \
         -artifact_prefix="$ART/" \
         -print_final_stats=1 \
         "$CORPUS" || true

# libFuzzer deja fuzz-N.log en el CWD ($WORK). Los movemos a logs/.
mv -f "$WORK"/fuzz-*.log "$LOGS/" 2>/dev/null || true

triage