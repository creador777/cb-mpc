# HANDOFF — Campaña de fuzzing cb-mpc (Coinbase) — 2026-07-16

Documento de traspaso para IA colaboradora. Estado real, sin adornos.

---

## 1. Objetivo

Encontrar bugs bounty-eligible en la librería MPC de Coinbase (`cb-mpc`, repo público,
programa en HackerOne). Modelo de amenaza alineado con `BUG_BOUNTY.md`:
- **P1 = parte HONESTA**, corre la librería SIN MODIFICAR, vía la **API pública**
  (`include/cbmpc/api/`).
- **P2 = parte MALICIOSA**: solo interactúa por el límite del protocolo; sus mensajes
  P2→P1 se mutan en tránsito. NO se toca `include-internal/` como entry point.
- Un crash/estado-corrupto de la parte honesta = PoC submittible.

Tiers del bounty: Low $200 (crash/DoS no-cripto) · Medium $2k (ZK/commitments) ·
High $15k · Critical $50k · Extreme hasta $1M (key compromise / RCE).

---

## 2. Arquitectura del harness (`fuzz/fuzz_malicious_party.cpp`, ~588 líneas)

Harness libFuzzer + AddressSanitizer + UBSan. Fusión de dos versiones previas
(Codex 5.3 + DeepSeek v4) con bugs críticos de ambas ya corregidos.

### Componentes
- **Transporte 2P en memoria** (`network_t` + canales con mutex/cv). P1 honesto registra
  su tráfico saliente; P2 malicioso muta P2→P1.
- **Mutador semántico** (`malicious_transport_t`): puntúa regiones "bigint-ish"
  (`score_bigintish`) y aplica corrupciones dirigidas — zeroize campo, constante chica
  (degeneración Paillier), flip de endianness, NOT de subrango, `force_paillier_degenerate`
  (mete `1` en módulo Paillier), `force_share_null` (share = 0), reorden de mensajes.
- **CustomMutator gramático** + **CustomCrossOver**: generan inputs que decodifican en
  secuencias de operaciones válidas (para llegar a estados profundos del protocolo).
- **Oráculos (SOLO centrados en la parte honesta)** — disparan `abort()` únicamente ante
  corrupción irrefutable:
  - `SIGN-BREAK`: P1 devuelve SUCCESS con firma que NO verifica bajo Q (oráculo OpenSSL).
  - `REFRESH-BREAK`: refresh atacado que cambia la clave pública de P1.
  - `NONCE-REUSE` (detector de $1M): mismo R con distinto hash ⇒ clave privada extraíble.
  - `KEY-LEAK`: el escalar privado aparece literal en el tráfico saliente honesto.
  - Memoria: ASan/UBSan capturan heap-overflow / UAF / SEGV automáticamente.
- **AUTO-TRIAGE** (`run_fuzz.sh`): reproduce cada crash y lo clasifica por el frame culpable:
  `[HARNESS]` (bug nuestro, ignorar) vs `[CANDIDATO]` (frame en `src/cbmpc/…`, mirar).

---

## 3. Mejoras aplicadas (cronológico) — el "nivel" del código

Cada una arregló un falso positivo o cuello de botella real, verificado con evidencia:

1. **Eliminado el check "divergent success"** — la versión previa abortaba cuando P1 y P2
   diferían en éxito. ERROR: con parte maliciosa, que P2 "tenga éxito" mientras P1 aborta
   es NORMAL (lo confirma el test oficial `SignRound4NullCurvePointFromP2Rejected`). Habría
   inundado de falsos positivos.
2. **Caché de clave de referencia** — DKG limpio UNA vez (persistido en `cbmpc_key*.bin`),
   luego cada input ataca sign/refresh. Sube de ~1 exec/s a miles.
3. **Fix heap-overflow en CustomCrossOver** — leía 32 bytes de un input de 1 byte.
   Verificado con simulación de aritmética en todos los casos límite.
4. **Fix deadlock del reorden** — `flush_delayed` era probabilístico y se tragaba mensajes
   ⇒ las dos partes se esperaban para siempre. Ahora es determinista (entrega todo lo
   retenido antes de que P2 bloquee). Backstop de recv a 8s (< 25s de libFuzzer).
5. **Fix `abort_all` solo ante error** — antes se llamaba al terminar CUALQUIER parte,
   sacando a la otra de su espera antes de su último paso ⇒ crashes flaky (carrera).
6. **RNG DETERMINISTA (la mejora clave)** — `fuzzrng` (xoshiro256\*\*) sembrado desde el
   input, instalado vía `RAND_set_rand_method`. cb-mpc saca su aleatoriedad de OpenSSL;
   ahora ese stream queda atado al input ⇒ **mismo input = misma ejecución = los crashes
   REPRODUCEN**. Sin esto, ningún hallazgo era reportable (bounty exige PoC reproducible).

Build: `build_fuzz_malicious.sh` fuerza `clang`, recompila cb-mpc con
`-fsanitize=fuzzer-no-link,address,undefined` (cobertura DENTRO de la lib), linkea con el
OpenSSL estático propio (`/usr/local/opt/openssl@3.6.1`, `lib64/libcrypto.a`). Compila
limpio (solo 7 warnings de OpenSSL deprecated, inofensivos).

Infra: `run_fuzz.sh` mueve todo a disco ext4 nativo (`~/cbmpc-fuzz`, 5-10× I/O vs /mnt/c),
siembra corpus, corre N jobs, y auto-triagea al final.

---

## 4. Estado actual (resultados reales)

- **Antes del RNG determinista:** aparecían asserts (`random_masking_inv`, `refresh` en
  `ecdsa_2p.cpp:210` con `rho1+rho2` fuera de rango). TODOS resultaron **flaky / no
  reproducibles** = no reportables. Muchos eran artefactos del propio harness.
- **Después del RNG determinista (corrida de 30 min):** `703 runs`, `cov: 3369`,
  `corp: 515`, 37 caminos nuevos. **AUTO-TRIAGE: cero crashes.**
  - Interpretación: al eliminar el ruido de RNG+timing, cb-mpc procesa el path 2P sin
    romperse. Habla bien del blindaje de cb-mpc (Cure53 + fuzzing propio de Coinbase +
    hardening reciente de serialización). Ningún oráculo de alto valor (SIGN-BREAK,
    NONCE-REUSE, KEY-LEAK) disparó nunca.

**Veredicto honesto:** hasta ahora, cero hallazgos reportables. El path ECDSA-2P (el más
auditado) no rinde en barridos cortos. Esto es el escenario esperado contra un target
blindado, no un fallo del harness.

---

## 5. Plan

- **AHORA (en curso):** corrida overnight de 8h sobre el path 2P
  (`bash run_fuzz.sh -t 28800`). Más tiempo = más chance de estados raros. Revisar
  AUTO-TRIAGE en la mañana.
- **SIGUIENTE (mayor EV):** clonar el harness para **ECDSA-Multi-Party** (`api/ecdsa_mp.h`:
  `dkg_additive/dkg_ac/refresh_*/sign_additive/sign_ac`). MP tiene MUCHOS menos ojos encima
  que 2P ⇒ mayor probabilidad de bug vivo. Requiere transporte n-party (no solo 2).
- **DESPUÉS:** mutador estructura-consciente (parsear el `convert_len` real de cb-mpc para
  producir mensajes que pasen el deser y golpeen la lógica matemática, en vez de que el
  deser los rechace limpio). También: atacar el diff de hardening reciente, y las primitivas
  ZK/commitments (Medium-eligible cuando son alcanzables desde la API).

---

## 6. Reglas de oro (aprendidas a los golpes)

1. **NO todo lo rojo es plata.** Antes de festejar/reportar, mirar el frame `#1` del stack:
   `fuzz_malicious_party.cpp` ⇒ bug NUESTRO; `src/cbmpc/…` ⇒ CANDIDATO.
2. **Sin PoC reproducible no hay bounty.** Reproducir un `crash-*` ≥5 veces ANTES de
   escribir cualquier reporte. (El RNG determinista es lo que ahora lo permite.)
3. **Un assert que aborta ante un peer tramposo suele ser el diseño correcto, no un bug.**
   Puede ser Low ($200) o $0. No sobrevender.
4. Reportar un falso positivo quema reputación en HackerOne. Verificar siempre.

---

## 7. Archivos

- `fuzz/fuzz_malicious_party.cpp` — harness principal (2P).
- `fuzz/build_fuzz_malicious.sh` — build (clang + ASan/UBSan + cobertura).
- `fuzz/run_fuzz.sh` — orquestador (ext4 + corpus + campaña + auto-triage).
- `fuzz/triage_crashes.sh` — triage standalone de un directorio de crashes.
- `~/cbmpc-fuzz/` — workdir en disco Linux (binario, claves, corpus, artifacts, logs).
- `~/cbmpc-hallazgos/` — copia de seguridad de crashes de interés.