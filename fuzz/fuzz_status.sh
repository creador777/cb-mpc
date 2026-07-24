#!/usr/bin/env bash
# =============================================================================
# fuzz_status.sh — Dashboard EN VIVO del fuzzing. Corré esto en OTRA ventana de
# WSL mientras fuzz_malicious/fuzz_schnorr corre en la primera.
#   cd fuzz && bash fuzz_status.sh
# Se refresca cada 5s. Ctrl+C para salir (NO mata el fuzzer, solo el monitor).
# =============================================================================
cd "$(dirname "$0")" || exit 1
INTERVAL="${1:-5}"

while true; do
  clear
  echo "==================== FUZZING STATUS ($(date '+%H:%M:%S')) ===================="
  echo

  # --- ¿corre el fuzzer? ---
  if pgrep -f "fuzz_malicious|fuzz_schnorr" >/dev/null 2>&1; then
    N=$(pgrep -f "fuzz_malicious|fuzz_schnorr" | wc -l)
    echo "  [ESTADO]   VIVO  ($N procesos corriendo)"
  else
    echo "  [ESTADO]   DETENIDO (no hay fuzzer corriendo)"
  fi
  echo

  # --- última línea de progreso (cov/ft/corp/exec) ---
  LAST=$(grep -hE "cov: [0-9]+" run.log fuzz-*.log 2>/dev/null | tail -n1)
  if [ -n "$LAST" ]; then
    COV=$(echo "$LAST"  | grep -oE "cov: [0-9]+"     | grep -oE "[0-9]+")
    FT=$(echo "$LAST"   | grep -oE "ft: [0-9]+"      | grep -oE "[0-9]+")
    CORP=$(echo "$LAST" | grep -oE "corp: [0-9]+"    | grep -oE "[0-9]+")
    EXEC=$(echo "$LAST" | grep -oE "exec/s: [0-9]+"  | grep -oE "[0-9]+")
    TIME=$(echo "$LAST" | grep -oE "time: [0-9]+"    | grep -oE "[0-9]+")
    echo "  [COBERTURA] $COV ramas   |  features: $FT   |  corpus: $CORP entradas"
    echo "  [VELOCIDAD] ${EXEC:-?} exec/seg           |  tiempo corrido: ${TIME:-?}s"
  else
    echo "  [COBERTURA] (sin logs todavía — esperá a que arranque)"
  fi
  echo

  # --- crashes NUEVOS (de hoy) ---
  TODAY=$(date '+%Y-%m-%d')
  NEW=$(find . -maxdepth 1 -name "*crash-*" -newermt "$TODAY 00:00" 2>/dev/null | wc -l)
  TOTAL=$(find . -maxdepth 1 -name "*crash-*" 2>/dev/null | wc -l)
  echo "  [CRASHES]  nuevos hoy: $NEW    |    total en carpeta: $TOTAL"
  if [ "$NEW" -gt 0 ]; then
    echo "  --- últimos crashes de hoy (mirá el tipo con: ./fuzz_schnorr <archivo>) ---"
    find . -maxdepth 1 -name "*crash-*" -newermt "$TODAY 00:00" -printf "     %TH:%TM  %f\n" 2>/dev/null | sort | tail -5
  fi
  echo
  echo "=============================================================================="
  echo "  refresca cada ${INTERVAL}s | Ctrl+C corta el monitor (NO el fuzzer)"
  sleep "$INTERVAL"
done