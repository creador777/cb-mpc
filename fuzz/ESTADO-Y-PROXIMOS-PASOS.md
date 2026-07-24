# ESTADO — dónde quedamos (2026-07-17)

## ✅ LO QUE LOGRAMOS: primer bug real, reproducible, en cb-mpc

- **9 crashes, TODOS el mismo bug**, 100% reproducibles (RNG determinista).
- **Assert:** `is_in_range(a) && "out of range for constant-time operations"`
- **Ubicación:** `src/cbmpc/protocol/ecdsa_2p.cpp:210` — función `refresh`
- **Alcanzable por:** API pública (`api::ecdsa_2p::refresh`), parte honesta P1 sin modificar.
- **Cumple el modelo de amenaza del bounty.** Es un [CANDIDATO] legítimo.

## 🔎 CAUSA RAÍZ (verificada leyendo el código)

En `refresh`:
- Línea 179: P2 (malicioso) manda `rho2` a P1.
- Líneas 192-206: las validaciones ZK las corre P2, NO P1.
- Línea 210: P1 hace `MODULO(q) { rho = rho1 + rho2; }` **sin validar que rho2 < q**.
- rho2 fuera de rango → `mod_t::check` → assert → abort() de la parte honesta.
- Las otras validaciones del mismo refresh (líneas 162/166/170) devuelven error LIMPIO
  con `mpc_abort`. Esta crashea con SIGABRT. Esa inconsistencia = el argumento del bug.

## 💰 VALOR REALISTA (honesto)

- **Tier Low = $200** (crash/DoS no-criptográfico). NO es Medium/$2000.
- **Chance real de $0**: Coinbase puede argüir "el assert es la defensa funcionando".
- Argumento a favor: input de red malformado debería dar `error_t`, no matar el proceso.

## 📁 ARCHIVOS CLAVE (guardados, no se pierden)

- Crash PoC: `~/cbmpc-fuzz/artifacts/crash-1060b41a117ec1e4a62c34cfc2cfcac033345807`
  (y 8 más, todos el mismo bug — copiados en `~/cbmpc-hallazgos/`)
- Harness: `fuzz/fuzz_malicious_party.cpp`
- Handoff técnico: `fuzz/HANDOFF.md`

## Reproducir el crash cuando vuelvas (1 comando)
```bash
cd ~/cbmpc-fuzz
ASAN_OPTIONS=symbolize=1 ./fuzz_malicious artifacts/crash-1060b41a117ec1e4a62c34cfc2cfcac033345807 2>&1 | grep -E "Assertion|ecdsa_2p.cpp:210"
```

## 🎯 PRÓXIMOS PASOS (cuando vuelvas, en orden)

1. **PoC mínimo limpio** (Claude lo arma): P1 honesto con RNG real SIN tocar, P2 que manda
   rho2 fuera de rango. SIN fuzzer, SIN hooks. Es lo que el triager quiere ver y neutraliza
   la objeción "modificaste el entorno". ~30 min.
2. **Escribir el reporte** con causa raíz + fix sugerido + contraargumento neutralizado.
3. **NO hay urgencia real**: los duplicados se deciden por quién reportó PRIMERO en la
   historia, no en las próximas horas. Hacerlo bien > hacerlo rápido.
4. Verificar en HackerOne / issues del repo si este assert ya fue reportado (evitar duplicado).
5. Enviar a HackerOne (cuenta de Victor).

## 🚀 DESPUÉS (seguir cazando)
- Harness Multi-Party (MP) — superficie menos auditada, mayor EV.
- Mutador estructura-consciente.
- El fix sugerido para el reporte: añadir `if (!q.is_in_range(rho2)) return mpc_abort(...)`
  en P1 antes de la línea 210 (igual que las otras validaciones del refresh).