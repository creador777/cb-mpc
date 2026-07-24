# TASK FOR CODEX (GPT-5): Add a BIP340 forgery oracle to a Schnorr-2P fuzz harness

You are editing an EXISTING, WORKING libFuzzer harness for Coinbase's `cb-mpc`
library. Your ONLY job is to add ONE new oracle: a **BIP340 signature-verification
(forgery) oracle** that detects a LOGIC break — the honest party (P1) returning
`SUCCESS` with a signature that does NOT actually verify under the real public key.

This is the high-value oracle: a forgery in a threshold-signing protocol is a
Critical/Extreme-tier bug. Crashes are already caught by ASan; you are adding
detection of *silent cryptographic incorrectness*, which ASan cannot see.

## HARD RULES (violating these wastes the whole task)

1. **DO NOT invent library functions.** Only use the APIs and facts listed in the
   "VERIFIED FACTS" section below. If you think you need something not listed,
   STOP and write a `// TODO: verify <X>` comment instead of guessing.
2. **DO NOT modify any cb-mpc source.** P1 must run the unmodified public API. You
   only edit the harness file `fuzz/fuzz_schnorr_party.cpp`.
3. **DO NOT change** the transport classes, the RNG seeding (`fuzzrng`), the
   `run_2pc` helper, the mutation config, or the `LLVMFuzzerCustomMutator` /
   `CustomCrossOver` functions. They work. Leave them alone.
4. **The oracle must be HONEST-PARTY-CENTRIC.** Only assert on P1's own output.
   Never compare P1 vs P2 results — a malicious P2 diverging is NORMAL, not a bug.
   (The harness already had a bug from this; do not reintroduce it.)
5. **Only `abort()` on a REAL forgery**, i.e. P1 returned `SUCCESS` AND produced a
   64-byte signature AND that signature FAILS BIP340 verification under the
   reference public key. A failed sign (P1 returns error) is CORRECT behavior —
   never abort on that.
6. **Self-contained verification.** The verifier must be INDEPENDENT of cb-mpc's
   own signing math (do not call cb-mpc's internal `bip340::verify`). Implement
   BIP340 verification directly with OpenSSL primitives so a bug in cb-mpc cannot
   hide a bug in the oracle.

## VERIFIED FACTS (these are real — I checked them against the headers/source)

### Public API (namespace is aliased as `e2` in the harness):
```cpp
namespace e2 = coinbase::api::schnorr_2p;
// This wrapper is BIP340 over secp256k1 ONLY. Curve is always secp256k1.

error_t e2::sign(const job_2p_t& job, mem_t key_blob, mem_t msg, buf_t& sig);
//   msg  MUST be exactly 32 bytes (BIP340 digest).
//   sig  output is 64 bytes: r_x (32 bytes) || s (32 bytes). Returned on P1 only;
//        on P2 sig may be empty on success.

error_t e2::extract_public_key_xonly(mem_t key_blob, buf_t& pub_key_xonly);
//   returns the BIP340 x-only public key = 32 bytes.

error_t e2::get_public_key_compressed(mem_t key_blob, buf_t& pub_key_compressed);
//   returns SEC1 compressed 33 bytes: 0x02/0x03 || x(32).
```
`SUCCESS` is the success `error_t`. The harness already `using namespace coinbase;`.

### BIP340 verification algorithm (implement this with OpenSSL, secp256k1):
Given x-only pubkey `px` (32 bytes), message `m` (32 bytes), signature `r||s`
(each 32 bytes), over secp256k1 with group order `n` and generator `G`:
1. Lift pubkey: `P` = point with x-coordinate `px` and EVEN y (BIP340 convention).
   If no valid point exists, verification fails.
2. Reject if `r >= p` (field prime) or `s >= n`.
3. `e = int(tagged_hash("BIP0340/challenge", r || px || m)) mod n`, where
   `tagged_hash(tag, data) = SHA256( SHA256(tag) || SHA256(tag) || data )`.
4. Compute `R = s*G - e*P`.
5. Verification SUCCEEDS iff `R` is not infinity, `R.y` is EVEN, and `R.x == r`.

Use these OpenSSL primitives (all available; the harness already includes
`<openssl/bn.h>`, `<openssl/ec.h>`, `<openssl/obj_mac.h>`; add `<openssl/sha.h>`
if needed): `EC_GROUP_new_by_curve_name(NID_secp256k1)`, `EC_POINT_*`,
`BN_*`, `EC_POINT_mul`, `EC_POINT_get_affine_coordinates`,
`EC_POINT_set_compressed_coordinates` (for the even-y lift, prefix byte 0x02),
`SHA256`. Manage all `BN`/`EC_POINT`/`BN_CTX`/`EC_GROUP` with proper free on every
path (no leaks — the harness runs under ASan).

### Reference public key is already available as a global:
The harness bootstraps a clean key once. There is a global `buf_t g_key1` (honest
P1's key blob) and `buf_t g_pub` (its compressed pubkey). For BIP340 you will want
the x-only key: call `e2::extract_public_key_xonly(g_key1, <buf_t>)` ONCE at
bootstrap (add a global `buf_t g_pub_xonly;` and fill it in `bootstrap()` right
after the pubkey is obtained), so the hot path does not recompute it.

## WHERE TO ADD CODE (exact locations in fuzz/fuzz_schnorr_party.cpp)

- Add a `static bool bip340_verify(mem_t px32, mem_t msg32, const buf_t& sig64)`
  helper near the top, replacing the now-unused `ossl_verify`/`extract_r32`
  functions (those are ECDSA-DER specific and dead in this file — you may delete
  them and the unused `nonce_oracle_t`).
- In `bootstrap()`: after `g_pub` is filled, also fill a new global
  `buf_t g_pub_xonly;` via `extract_public_key_xonly(g_key1, g_pub_xonly)`.
- In `LLVMFuzzerTestOneInput`, in the SIGN branch, the current code is:
  ```cpp
  if (r1 == SUCCESS && sig1.size() > 0) leak_oracle(g_key1, transcript, trmtx);
  ```
  Replace with: keep the leak_oracle call, AND add — if P1 SUCCESS and sig1 is
  64 bytes, run `bip340_verify(g_pub_xonly, mh, sig1)`; if it returns false,
  print `CRITICAL [SCHNORR-FORGERY] P1 SUCCESS con firma BIP340 que NO verifica`
  to stderr and `std::abort()`.

## DELIVERABLE
Output the COMPLETE modified `fuzz_schnorr_party.cpp`. Do not output prose,
explanations, or diffs — just the full file, ready to compile with the existing
`build_fuzz_schnorr.sh`. Keep all existing includes; add only what BIP340 needs.
It must compile with clang++ -std=c++17 under -fsanitize=fuzzer,address,undefined.