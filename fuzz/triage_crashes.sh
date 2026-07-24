#!/usr/bin/env bash
# =============================================================================
# triage_crashes.sh — Bucketing/triage de crashes de libFuzzer para cb-mpc
# -----------------------------------------------------------------------------
# Reproduce cada crash-* contra el harness, extrae una FIRMA estable del fallo,
# agrupa por firma y reporta:
#   "Encontrados N crashes. X del bug A (assert ...). Y del bug B (heap-overflow)..."
#
# Diseño clave (por qué es rápido y correcto):
#   * PARALELO: -P $(nproc). 100k reproducciones en 1 proceso c/u NO se puede
#     batchear en libFuzzer (aborta en el primer crash), así que forkeamos por
#     archivo pero saturamos todos los cores.
#   * SIN SIMBOLIZAR en el barrido masivo (ASAN symbolize=0): llvm-symbolizer es
#     lo caro. La firma se saca de texto independiente de símbolos:
#        1) mensaje de assert de cb-mpc / what() de la excepción  -> distingue asserts
#        2) linea "SUMMARY: AddressSanitizer: <tipo> (modulo+offset)" -> bugs de memoria
#        3) primeros frames "(modulo+offset)"                     -> SIGSEGV puros
#     module+offset es estable entre corridas (relativo a la base del modulo).
#   * SIMBOLIZAR SOLO los representantes (un archivo por bucket): pasada 2, barata.
#
# Uso:
#   ./triage_crashes.sh [-j N] [-t SEG] <binario_fuzzer> <dir_crashes> [dir_salida]
# Ejemplo:
#   ./triage_crashes.sh ./fuzz_elite ./crashes ./triage_out
# =============================================================================

set -uo pipefail

# ----------------------------- Configuración ---------------------------------
JOBS="$( (nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4) )"
TIMEOUT_S=20                       # kill-switch por reproducción (anti-hang)
CRASH_GLOBS=( 'crash-*' 'oom-*' 'timeout-*' 'leak-*' )  # prefijos libFuzzer
RARE_THRESHOLD=50                  # buckets con <= este conteo se marcan RAROS

# ASAN/UBSAN para el barrido masivo: sin simbolizar, sin LSan, aborta limpio.
FAST_ASAN="symbolize=0:detect_leaks=0:abort_on_error=1:handle_abort=1:handle_segv=1:print_summary=1:exitcode=1"
FAST_UBSAN="print_stacktrace=1:symbolize=0"
# Para la pasada de representantes: simbolizado completo.
SYM_ASAN="symbolize=1:detect_leaks=0:abort_on_error=1:handle_abort=1:handle_segv=1:print_summary=1:exitcode=1"
SYM_UBSAN="print_stacktrace=1:symbolize=1"

# =============================================================================
# extract_sig <log_text_file>  ->  imprime una firma en una sola línea
# Prioridad: bug de memoria (valioso) > assert (flood) > señal pura > nada.
# =============================================================================
extract_sig() {
  local log="$1" s

  # (1) Error REAL de sanitizer (heap-overflow, UAF, etc.) — los de $50k.
  #     Excluimos "deadly signal" (genérico de abort/terminate) para NO mezclar
  #     todos los asserts en un mismo balde.
  s="$(grep -aE 'SUMMARY: (AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|ThreadSanitizer):' "$log" \
        | grep -aviE 'deadly signal' | head -n1)"
  if [ -n "$s" ]; then
    printf 'MEM  %s\n' "$(printf '%s' "$s" \
      | sed -E 's/^SUMMARY: //; s/0x[0-9a-fA-F]+/0xADDR/g; s/[[:space:]]+/ /g')"
    return
  fi

  # (2) Assertion de cb-mpc: throw assertion_failed_t -> terminate. El mensaje
  #     lleva la expresión exacta (#expr), p.ej.  false && "mod_t::random_masking_inv failed".
  #     Es INDEPENDIENTE de símbolos y distingue cada assert por separado.
  s="$(grep -aoE 'what\(\):[[:space:]]*.*' "$log" | head -n1 | sed -E 's/^what\(\):[[:space:]]*//')"
  [ -z "$s" ] && s="$(grep -aoE 'Assertion failed:.*' "$log" | head -n1 | sed -E 's/^Assertion failed:[[:space:]]*//')"
  if [ -n "$s" ]; then
    printf 'ASSERT  %s\n' "$(printf '%s' "$s" | sed -E 's/0x[0-9a-fA-F]+/0xADDR/g; s/[[:space:]]+/ /g')"
    return
  fi

  # (3) Señal pura (SIGSEGV/SIGABRT sin reporte de sanitizer): primeros 3 frames
  #     como (modulo+offset). Estable sin simbolizar.
  s="$(grep -aoE '\([^()]*\+0x[0-9a-fA-F]+\)' "$log" | head -n3 | tr '\n' ' ' | sed -E 's/[[:space:]]+$//')"
  if [ -n "$s" ]; then
    printf 'SIGNAL  %s\n' "$s"
    return
  fi

  # (4) Frames simbolizados sin "(modulo+offset)" (por si el barrido corrió con símbolos)
  s="$(grep -aE '^[[:space:]]*#[0-9]+ ' "$log" \
        | grep -aviE ' in (fuzzer::|__sanitizer|__asan|__ubsan|__interceptor|__cxa|__gnu_cxx::|std::terminate|abort|raise|_start|__libc)' \
        | head -n1 \
        | sed -E 's/^[[:space:]]*#[0-9]+[[:space:]]+0x[0-9a-fA-F]+[[:space:]]+in[[:space:]]+//; s/0x[0-9a-fA-F]+/0xADDR/g; s/\+0x[0-9a-fA-F]+//g; s/[[:space:]]+/ /g')"
  if [ -n "$s" ]; then
    printf 'FRAME  %s\n' "$s"
    return
  fi

  printf 'NOCRASH/flaky\n'
}

# =============================================================================
# run_worker <fuzzer> <results_tsv> <crash_file>
# Reproduce un crash y anexa "<firma>\t<archivo>" al TSV compartido.
# Escrituras <4096 bytes con O_APPEND son atómicas en Linux -> sin flock.
# =============================================================================
run_worker() {
  local fuzzer="$1" results="$2" file="$3"
  local tmp rc sig
  tmp="$(mktemp)"

  ASAN_OPTIONS="$FAST_ASAN" UBSAN_OPTIONS="$FAST_UBSAN" \
    timeout -s KILL "$TIMEOUT_S" "$fuzzer" "$file" >"$tmp" 2>&1
  rc=$?

  if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
    sig="TIMEOUT/HANG (>${TIMEOUT_S}s)"
  else
    sig="$(extract_sig "$tmp")"
  fi
  rm -f "$tmp"

  # firma en una línea; TAB separa firma de archivo
  printf '%s\t%s\n' "$sig" "$file" >>"$results"
}

# ---- Dispatch de worker (self-invocación desde xargs) -----------------------
if [ "${1:-}" = "--worker" ]; then
  shift
  run_worker "$@"
  exit 0
fi

# ============================== MAIN =========================================
usage() { grep -E '^# (Uso:|Ejemplo:|  )' "$0" | sed 's/^# //'; exit 1; }

while getopts ":j:t:h" opt; do
  case "$opt" in
    j) JOBS="$OPTARG" ;;
    t) TIMEOUT_S="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))

FUZZER="${1:-}"
CRASH_DIR="${2:-}"
OUT_DIR="${3:-./triage_out}"

[ -n "$FUZZER" ] && [ -n "$CRASH_DIR" ] || usage
[ -x "$FUZZER" ] || { echo "ERROR: fuzzer no ejecutable: $FUZZER" >&2; exit 1; }
[ -d "$CRASH_DIR" ] || { echo "ERROR: dir de crashes inexistente: $CRASH_DIR" >&2; exit 1; }

FUZZER="$(readlink -f "$FUZZER")"
CRASH_DIR="$(readlink -f "$CRASH_DIR")"
mkdir -p "$OUT_DIR"
OUT_DIR="$(readlink -f "$OUT_DIR")"
RESULTS="$OUT_DIR/results.tsv"
SUMMARY="$OUT_DIR/summary.txt"
UNIQ_DIR="$OUT_DIR/unique"
mkdir -p "$UNIQ_DIR"
: > "$RESULTS"

# --- Reunir archivos de crash (NUL-delimitado, tolera nombres raros) ---------
FILELIST="$OUT_DIR/filelist.0"
: > "$FILELIST"
findargs=(); first=1
for g in "${CRASH_GLOBS[@]}"; do
  if [ "$first" -eq 1 ]; then findargs+=( -name "$g" ); first=0
  else findargs+=( -o -name "$g" ); fi
done
find "$CRASH_DIR" -maxdepth 1 -type f \( "${findargs[@]}" \) -print0 >"$FILELIST"

TOTAL="$(tr -cd '\0' <"$FILELIST" | wc -c | tr -d ' ')"
if [ "$TOTAL" -eq 0 ]; then
  echo "No se encontraron archivos ($(IFS='|'; echo "${CRASH_GLOBS[*]}")) en $CRASH_DIR" >&2
  exit 1
fi

echo "=========================================================================="
echo " Triage de crashes cb-mpc"
echo "   fuzzer : $FUZZER"
echo "   crashes: $CRASH_DIR  ($TOTAL archivos)"
echo "   jobs   : $JOBS   timeout/reproducción: ${TIMEOUT_S}s"
echo "   salida : $OUT_DIR"
echo "=========================================================================="
echo "[*] Pasada 1: reproduciendo en paralelo (sin simbolizar)..."

# --- Monitor de progreso en background --------------------------------------
( while :; do
    n="$(wc -l <"$RESULTS" 2>/dev/null || echo 0)"
    printf '\r    procesados %s / %s' "$n" "$TOTAL" >&2
    [ "$n" -ge "$TOTAL" ] && break
    sleep 2
  done ) &
MON=$!

# --- Barrido paralelo --------------------------------------------------------
xargs -0 -P "$JOBS" -n1 "$0" --worker "$FUZZER" "$RESULTS" <"$FILELIST"

kill "$MON" 2>/dev/null; wait "$MON" 2>/dev/null
printf '\r    procesados %s / %s\n' "$TOTAL" "$TOTAL" >&2

# --- Agregación --------------------------------------------------------------
# Conteo por firma (campo 1). Firma completa incluye el prefijo MEM/ASSERT/...
echo "[*] Pasada 2: agrupando y aislando representantes..."

# tabla: <conteo>\t<firma>   (ordenada desc)
COUNTS="$OUT_DIR/counts.tsv"
cut -d$'\t' -f1 "$RESULTS" | sort | uniq -c | sort -rn \
  | sed -E 's/^[[:space:]]*([0-9]+)[[:space:]]/\1\t/' >"$COUNTS"

# representante (primer archivo visto) por firma
REPS="$OUT_DIR/reps.tsv"
awk -F'\t' '!seen[$1]++ {print $1"\t"$2}' "$RESULTS" >"$REPS"

NUM_BUCKETS="$(wc -l <"$COUNTS" | tr -d ' ')"

# --- Reporte -----------------------------------------------------------------
{
  echo "=========================================================================="
  echo " RESUMEN DE TRIAGE"
  echo "=========================================================================="
  echo "Encontrados $TOTAL crashes en $NUM_BUCKETS grupo(s) distinto(s)."
  echo

  # Clasificación de severidad por firma
  sev_of() {
    case "$1" in
      MEM*heap-buffer-overflow*|MEM*heap-use-after-free*|MEM*use-after-free*|\
      MEM*stack-buffer-overflow*|MEM*global-buffer-overflow*|MEM*double-free*|MEM*stack-overflow*)
        echo "CRITICO-MEMORIA" ;;
      MEM*SEGV*|SIGNAL*) echo "CRITICO-SEGV" ;;
      MEM*) echo "SANITIZER" ;;
      ASSERT*) echo "DoS-assert" ;;
      TIMEOUT*) echo "DoS-hang" ;;
      NOCRASH*) echo "no-reproduce" ;;
      *) echo "otro" ;;
    esac
  }

  idx=0
  while IFS=$'\t' read -r count sig; do
    idx=$((idx+1))
    sev="$(sev_of "$sig")"
    rep="$(awk -F'\t' -v s="$sig" '$1==s{print $2; exit}' "$REPS")"
    tag=""
    if [ "$count" -le "$RARE_THRESHOLD" ] && [ "$sev" != "DoS-assert" ]; then tag="  <== RARO / REVISAR"; fi
    case "$sev" in CRITICO*) tag="  <== ALTO VALOR / REVISAR YA";; esac
    printf 'Bug %-2s | %8s crashes | %-16s | %s%s\n' "$idx" "$count" "$sev" "$sig" "$tag"
    printf '        representante: %s\n' "$rep"
  done <"$COUNTS"

  echo
  echo "Detalle simbolizado de cada representante -> $UNIQ_DIR/"
  echo "TSV completo (firma\\tarchivo)             -> $RESULTS"
} | tee "$SUMMARY"

# --- Simbolizar UN representante por bucket (barato) -------------------------
i=0
while IFS=$'\t' read -r sig rep; do
  i=$((i+1))
  base="bucket_$(printf '%02d' "$i")"
  # traza completa simbolizada
  ASAN_OPTIONS="$SYM_ASAN" UBSAN_OPTIONS="$SYM_UBSAN" \
    timeout -s KILL "$TIMEOUT_S" "$FUZZER" "$rep" >"$UNIQ_DIR/$base.trace.txt" 2>&1
  { echo "# firma : $sig"; echo "# input : $rep"; } >"$UNIQ_DIR/$base.info.txt"
  cp -f "$rep" "$UNIQ_DIR/$base.input" 2>/dev/null || true
done <"$REPS"

echo
echo "[OK] Listo. Empezá por los buckets marcados ALTO VALOR / RARO en:"
echo "     $SUMMARY"
echo
echo "TIP (más rápido/mejor a escala): la herramienta estándar de industria para"
echo "esto es CASR (casr-libfuzzer). Hace exactamente este flujo + clustering por"
echo "hash de stack + ranking de explotabilidad, en una linea:"
echo "     casr-libfuzzer -i \"$CRASH_DIR\" -o \"$OUT_DIR/casr\" -- \"$FUZZER\""
echo "Para stripped binaries, simbolizá manualmente un offset con:"
echo "     addr2line -f -e \"$FUZZER\" 0x<offset>"