#!/usr/bin/env bash
# =============================================================================
# check_power.sh — ¿REALMENTE está usando toda la máquina? Evidencia real.
#   bash check_power.sh
# =============================================================================
echo "==================== ¿CUÁNTO PODER SE ESTÁ USANDO? ===================="
echo

echo "--- 1. Núcleos que ve Linux/WSL ---"
NPROC=$(nproc)
echo "    nproc = $NPROC núcleos disponibles para el fuzzer"
echo

echo "--- 2. Procesos fuzzer VIVOS ahora mismo ---"
CNT=$(pgrep -f "fuzz_malicious|fuzz_schnorr" | wc -l)
echo "    $CNT procesos de fuzzing corriendo"
if [ "$CNT" -eq 0 ]; then echo "    (ninguno — el fuzzer no está corriendo)"; fi
echo

echo "--- 3. Uso de CPU por esos procesos (deberían sumar ~${NPROC}00% si usa todo) ---"
ps -C fuzz_malicious,fuzz_schnorr -o pid,%cpu,%mem,etime,comm 2>/dev/null | head -20
TOTAL=$(ps -C fuzz_malicious,fuzz_schnorr -o %cpu= 2>/dev/null | awk '{s+=$1} END {printf "%.0f", s}')
echo "    ---> CPU TOTAL usada por el fuzzer: ${TOTAL:-0}%   (100% = 1 núcleo lleno)"
echo

echo "--- 4. RAM libre / usada (WSL) ---"
free -h | awk 'NR==1||/Mem/'
echo

echo "--- 5. ¿Cuánta RAM le asignó Windows a WSL? ---"
TOTAL_MEM=$(free -g | awk '/Mem/{print $2}')
echo "    WSL tiene ${TOTAL_MEM} GB de RAM. Si tu PC tiene más, Windows le está capando."
echo "    (Para darle más: editar C:\\Users\\victor\\.wslconfig -> [wsl2] memory=..., processors=...)"
echo
echo "======================================================================="