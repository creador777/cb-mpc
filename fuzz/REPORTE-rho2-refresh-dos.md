# Denial of Service in ECDSA-2P `refresh`: missing range validation of peer-supplied `rho2` aborts the honest party

**Severity (per program tiers): Low — "crashes … reachable through the supported public APIs"**

## Summary

In the two-party ECDSA key-refresh protocol (`coinbase::mpc::ecdsa2pc::refresh`, exposed
through the public API `coinbase::api::ecdsa_2p::refresh`), the honest party **P1** does not
validate the scalar `rho2` it receives from the counterparty **P2** before using it in a
modular addition. A malicious P2 can send a `rho2` value outside the range `[0, q)`. When the
honest P1 computes `MODULO(q) { rho = rho1 + rho2; }`, the low-level constant-time guard
`mod_t::check` fails its assertion and the process is terminated via `abort()` (SIGABRT).

This lets a malicious co-signer crash the honest party's signing process purely by sending a
single malformed protocol message through the supported public API — a remotely triggerable
denial of service against the honest party.

## Affected code

- Public entry point: `include/cbmpc/api/ecdsa_2p.h` → `ecdsa_2p::refresh(...)`
  (impl `src/cbmpc/api/ecdsa2pc.cpp:148`)
- Protocol: `src/cbmpc/protocol/ecdsa_2p.cpp`
  - `job.p2_to_p1(rho2, pi1_V_tag, pi2_V)` — P1 receives `rho2` from P2 (line ~179)
  - **No range validation of `rho2` follows.**
  - `MODULO(q) { rho = rho1 + rho2; }` — crash site (line ~210)
- Assertion: `src/cbmpc/crypto/base_mod.cpp:79`
  `cb_assert(is_in_range(a) && "out of range for constant-time operations")`

## Root cause

The `refresh` protocol already validates other values received from the counterparty using the
library's clean-error convention. For example, when P2 receives `N_tag` from P1 it rejects
malformed values with `job.mpc_abort(E_CRYPTO, ...)` (a graceful error return, process stays
alive). The `rho2` value P1 receives from P2 has **no equivalent check** — so instead of a clean
protocol abort, a malformed `rho2` propagates into a low-level constant-time routine whose
defensive assertion terminates the whole process.

This is an input-validation gap, not intended fail-closed behavior: the library's own pattern is
to return `E_CRYPTO` on malicious peer input, not to `abort()`.

## Impact

- The honest party's process is terminated (`abort()` / SIGABRT).
- Trigger is a single protocol message from the counterparty, through the supported public API.
- In a server deployment of the refresh protocol, a malicious counterparty can crash the honest
  signing node on demand (availability impact). No memory corruption or key disclosure is
  demonstrated — impact is limited to denial of service, consistent with the **Low** tier.

## Threat-model / scope compliance

- The honest party (P1) runs **unmodified** library code, invoked only through the supported
  public API `ecdsa_2p::refresh`.
- The malicious party (P2) interacts **only through the protocol boundary**: it emits a
  `rho2` value outside `[0, q)` in its normal `p2_to_p1` message.
- No `include-internal/` entry point is used to trigger the issue.

## Proof of concept

Reproducer input (libFuzzer testcase): `crash-3ee59ba7187b31d98d7c908bd1779efc7d49ad3a`

Observed crash (honest party P1, via public `ecdsa_2p::refresh`):

```
Assertion failed: is_in_range(a) && "out of range for constant-time operations"
terminate called after throwing an instance of 'coinbase::assertion_failed_t'
  what():  is_in_range(a) && "out of range for constant-time operations"
==...== ERROR: libFuzzer: deadly signal
  #11 coinbase::assert_failed(...)                     src/cbmpc/core/error.cpp:91
  #12 coinbase::crypto::mod_t::check(...)              src/cbmpc/crypto/base_mod.cpp:79
  #13 coinbase::crypto::mod_t::_add(...)               src/cbmpc/crypto/base_mod.cpp:89
  #15 coinbase::crypto::operator+(bn_t, bn_t)          src/cbmpc/crypto/base_bn.cpp:282
  #16 coinbase::mpc::ecdsa2pc::refresh(...)            src/cbmpc/protocol/ecdsa_2p.cpp:210
  #17 coinbase::api::ecdsa_2p::refresh(...)            src/cbmpc/api/ecdsa2pc.cpp:148
  #18 <harness: honest party P1 calls ecdsa_2p::refresh>
```

The honest party P1 (frame #18, unmodified public API) crashes while adding the malicious
`rho2` supplied by P2.

> Note for reviewers: a minimal, deterministic PoC (malicious P2 sets `rho2 = q` before its
> `p2_to_p1` send; honest P1 uses the unmodified public API) reproduces the crash 100% of the
> time and is available on request.

## Suggested fix

Validate `rho2` against the curve order after receiving it, using the same clean-error
convention already used for other peer-supplied values:

```cpp
if (rv = job.p2_to_p1(rho2, pi1_V_tag, pi2_V)) return rv;

// P1 receives rho2 from the (possibly malicious) counterparty; reject out-of-range values
// cleanly instead of letting the low-level constant-time guard abort the process.
if (job.is_p1() && !q.is_in_range(rho2))
  return rv = job.mpc_abort(E_CRYPTO, "rho2 out of range");
```