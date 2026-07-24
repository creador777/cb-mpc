// ============================================================================
// fuzz_harness_elite.cpp  —  Harness 2: "Oracle Chaos State Fuzzer" para cb-mpc
// ----------------------------------------------------------------------------
// Filosofía: el camino obvio (DKG->Sign feliz) ya está probado y endurecido.
// Atacamos (a) el WIRE FORMAT y (b) la MÁQUINA DE ESTADOS, con un transporte
// MITM controlado por el fuzzer que perturba mensajes VÁLIDOS en tránsito.
//
// Modelo de amenaza (alineado con BUG_BOUNTY.md de cb-mpc):
//   * UNA parte HONESTA corre la librería SIN MODIFICAR, vía la API PÚBLICA
//     (include/cbmpc/api/). No tocamos include-internal/.
//   * La parte "maliciosa" solo interactúa por el límite del protocolo: sus
//     bytes se corrompen en tránsito antes de llegar a la parte honesta.
//   => Cualquier crash/estado-corrupto de la parte honesta es un PoC submittible.
//
// ORÁCULO (lo que separa un hallazgo REAL de los 95k falsos positivos):
//   I.  Memoria: ASan/UBSan. Crash automático = bug de alto valor. (No abortamos
//       nosotros; el sanitizer lo hace.)
//   II. Metamórfico SOBRE ÉXITO: si la operación atacada devuelve SUCCESS pero el
//       resultado criptográfico es INCORRECTO -> abort(). Solo dispara con
//       SUCCESS + cripto-mal => ~cero falsos positivos.
//         - SIGN:    SUCCESS + firma que NO verifica bajo Q original -> BREAK
//         - REFRESH: SUCCESS + clave pública CAMBIÓ -> BREAK
//   III.Que la deserialización DEVUELVA ERROR es comportamiento CORRECTO. NUNCA
//       lo marcamos. Un cb_assert alcanzado se cuenta pero NO crashea salvo que
//       compiles con -DHUNT_ASSERTS (DoS hunting, señal separada).
//
// RNG: OpenSSL real (claves correctas). Ver nota de reproducibilidad al final.
// ============================================================================

#include <cbmpc/api/curve.h>     // coinbase::api::curve_id
#include <cbmpc/api/ecdsa_2p.h>  // coinbase::api::ecdsa_2p::{dkg,sign,refresh,get_public_key_compressed}
#include <cbmpc/core/buf.h>      // coinbase::buf_t, coinbase::mem_t
#include <cbmpc/core/error.h>    // coinbase::error_t, SUCCESS, E_NET_GENERAL
#include <cbmpc/core/job.h>      // coinbase::api::{job_2p_t,party_2p_t,party_idx_t,data_transport_i}

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <FuzzedDataProvider.h>  // vendorizado por el comando de build (ver abajo)

using namespace coinbase;
namespace e2 = coinbase::api::ecdsa_2p;

// ----------------------------------------------------------------------------
// Oráculo independiente: verifica firma ECDSA (DER) con OpenSSL bajo Q dado.
// Devuelve true si (a) verifica, o (b) el oráculo mismo no pudo construirse
// (fallo del oráculo, NO del target -> no marcamos bug).
// ----------------------------------------------------------------------------
static bool ossl_verify(int nid, mem_t pub, const uint8_t* h32, mem_t sig) {
  if (pub.size <= 0 || !pub.data || sig.size <= 0 || !sig.data) return true;
  bool ok = false;
  EC_KEY* k = EC_KEY_new_by_curve_name(nid);
  if (!k) return true;
  const EC_GROUP* g = EC_KEY_get0_group(k);
  EC_POINT* P = EC_POINT_new(g);
  if (P && EC_POINT_oct2point(g, P, pub.data, (size_t)pub.size, nullptr) == 1 &&
      EC_KEY_set_public_key(k, P) == 1) {
    ok = (ECDSA_verify(0, h32, 32, sig.data, sig.size, k) == 1);
  }
  if (P) EC_POINT_free(P);
  EC_KEY_free(k);
  return ok;
}

// ----------------------------------------------------------------------------
// Canal 2P en memoria (bloqueante) + propagación de abort para no deadlockear
// cuando una mutación hace que una parte espere un mensaje que nunca llega.
// ----------------------------------------------------------------------------
struct channel_t {
  std::mutex m;
  std::condition_variable cv;
  std::deque<buf_t> q[2][2];  // q[sender][receiver]
  bool aborted = false;

  void abort_all() {
    { std::lock_guard<std::mutex> lk(m); aborted = true; }
    cv.notify_all();
  }
};

// ----------------------------------------------------------------------------
// Plan de caos: el fuzzer decide QUÉ mensaje atacar y CÓMO. La mutación se
// aplica a los mensajes que van HACIA la parte honesta (honest_target).
// ----------------------------------------------------------------------------
enum class mut_e : uint8_t {
  PASS = 0,     // entregar intacto
  BITFLIP,      // flip de k bits
  TRUNCATE,     // cortar el mensaje
  EXTEND,       // anexar bytes del fuzzer
  MUTATE_LEN,   // reescribir un prefijo convert_len (crecer/encoger longitudes)
  MUTATE_CODE,  // sobrescribir una ventana de 8 bytes (type-code de 64 bits)
  ZEROFILL,     // rellenar una región con 0x00
  DROP,         // entregar buffer vacío (simula mensaje perdido -> deser falla)
  DUP_PREV,     // reentregar el mensaje anterior (replay)
  COUNT
};

struct chaos_plan_t {
  int honest_target = 0;        // 0=P1 honesta, 1=P2 honesta (recibe lo mutado)
  int target_msg_index = 0;     // qué mensaje entrante mutar (por índice de recepción)
  mut_e mut = mut_e::PASS;
  // parámetros de la mutación
  uint32_t p_off = 0, p_len = 0, p_val = 0;
  uint64_t p_code = 0;
  std::vector<uint8_t> p_bytes;
};

// Aplica la mutación elegida a un mensaje (in situ sobre out).
static void apply_mutation(const chaos_plan_t& plan, buf_t& out, const buf_t& prev) {
  int n = out.size();
  switch (plan.mut) {
    case mut_e::PASS:
    default:
      break;

    case mut_e::BITFLIP: {
      if (n <= 0) break;
      int nbits = 1 + (int)(plan.p_len % 32);  // 1..32 bits
      uint32_t seed = plan.p_off ^ 0x9E3779B9u;
      for (int i = 0; i < nbits; i++) {
        seed = seed * 1664525u + 1013904223u;  // LCG para dispersar posiciones
        int bit = (int)(seed % (uint32_t)(n * 8));
        out.data()[bit / 8] ^= (uint8_t)(1u << (bit % 8));
      }
    } break;

    case mut_e::TRUNCATE: {
      if (n <= 0) break;
      int keep = (int)(plan.p_len % (uint32_t)n);  // 0..n-1
      out.resize(keep);
    } break;

    case mut_e::EXTEND: {
      if (plan.p_bytes.empty()) break;
      buf_t ext(n + (int)plan.p_bytes.size());
      if (n > 0) std::memcpy(ext.data(), out.data(), (size_t)n);
      std::memcpy(ext.data() + n, plan.p_bytes.data(), plan.p_bytes.size());
      out = ext;
    } break;

    case mut_e::MUTATE_LEN: {
      // Reescribe el primer byte de un prefijo convert_len en un offset elegido.
      // convert_len: 0xxxxxxx (1B) / 10.. (2B) / 110.. (3B) / 111.. (4B).
      // Mutar el byte líder cambia longitud/forma -> estrés del parser de longitudes.
      if (n <= 0) break;
      int off = (int)(plan.p_off % (uint32_t)n);
      out.data()[off] = (uint8_t)plan.p_val;  // valor arbitrario (incl. prefijos grandes)
    } break;

    case mut_e::MUTATE_CODE: {
      // Sobrescribe una ventana de 8 bytes con un uint64 arbitrario (ataque a
      // convert_code_type / type-codes de 64 bits).
      if (n < 8) break;
      int off = (int)(plan.p_off % (uint32_t)(n - 7));
      uint64_t v = plan.p_code;
      for (int i = 0; i < 8; i++) out.data()[off + i] = (uint8_t)(v >> (8 * i));
    } break;

    case mut_e::ZEROFILL: {
      if (n <= 0) break;
      int off = (int)(plan.p_off % (uint32_t)n);
      int len = (int)(plan.p_len % (uint32_t)(n - off + 1));
      if (len > 0) std::memset(out.data() + off, 0x00, (size_t)len);
    } break;

    case mut_e::DROP:
      out = buf_t();  // vacío -> deser del receptor falla limpio (sin deadlock)
      break;

    case mut_e::DUP_PREV:
      if (prev.size() > 0) out = prev;  // replay del mensaje anterior
      break;
  }
}

// ----------------------------------------------------------------------------
// Transporte por parte. Si esta parte es la "maliciosa emisora" hacia la honesta,
// sus mensajes se corrompen en el momento en que la parte honesta los recibe.
// ----------------------------------------------------------------------------
struct chaos_transport_t : public coinbase::api::data_transport_i {
  channel_t& ch;
  int me;                       // índice de esta parte (0=P1, 1=P2)
  const chaos_plan_t& plan;
  int recv_counter = 0;         // nº de mensajes que ESTA parte ha recibido
  buf_t prev_delivered;         // último mensaje entregado (para DUP_PREV)

  chaos_transport_t(channel_t& c, int me_, const chaos_plan_t& p) : ch(c), me(me_), plan(p) {}

  error_t send(coinbase::api::party_idx_t receiver, mem_t msg) override {
    buf_t out(msg.data, msg.size);
    { std::lock_guard<std::mutex> lk(ch.m); ch.q[me][(int)receiver].push_back(out); }
    ch.cv.notify_all();
    return SUCCESS;
  }

  error_t receive(coinbase::api::party_idx_t sender, buf_t& msg) override {
    std::unique_lock<std::mutex> lk(ch.m);
    ch.cv.wait(lk, [&] { return ch.aborted || !ch.q[(int)sender][me].empty(); });
    if (ch.aborted) return coinbase::error(E_NET_GENERAL);
    buf_t real = ch.q[(int)sender][me].front();
    ch.q[(int)sender][me].pop_front();
    lk.unlock();

    // ¿Somos la parte honesta y este es el mensaje elegido para atacar?
    int idx = recv_counter++;
    if (me == plan.honest_target && idx == plan.target_msg_index) {
      buf_t mutated = real;
      apply_mutation(plan, mutated, prev_delivered);
      prev_delivered = mutated;
      msg = mutated;
    } else {
      prev_delivered = real;
      msg = real;
    }
    return SUCCESS;
  }

  error_t receive_all(const std::vector<coinbase::api::party_idx_t>& senders,
                      std::vector<buf_t>& msgs) override {
    msgs.resize(senders.size());
    for (size_t i = 0; i < senders.size(); ++i) {
      error_t rv = receive(senders[i], msgs[i]);
      if (rv) return rv;
    }
    return SUCCESS;
  }
};

// ----------------------------------------------------------------------------
// Ejecuta una operación 2P en dos hilos con abort propagado. `f` recibe el rol
// (0/1) y devuelve error_t. Cachea nada; devuelve rvs por referencia.
// ----------------------------------------------------------------------------
template <typename F>
static void run_pair(channel_t& ch, F&& f, error_t& rv0, error_t& rv1) {
  std::atomic<bool> aborted{false};
  auto wrap = [&](int role, error_t& out) {
    out = f(role);
    if (out != SUCCESS && !aborted.exchange(true)) ch.abort_all();
  };
  std::thread t0([&] { wrap(0, rv0); });
  std::thread t1([&] { wrap(1, rv1); });
  t0.join();
  t1.join();
}

// ----------------------------------------------------------------------------
// Estado global: par de claves VÁLIDO generado UNA sola vez (DKG limpio, RNG
// real). Reusarlo evita re-hacer DKG por input (enorme ahorro) y da claves
// correctas. Solo-lectura tras init -> seguro entre iteraciones.
// ----------------------------------------------------------------------------
static const coinbase::api::curve_id kCurve = coinbase::api::curve_id::secp256k1;
static const int kNid = NID_secp256k1;
static buf_t g_blob1, g_blob2, g_Q;  // Q = clave pública comprimida (original)
static bool g_ready = false;

// Persistencia de la clave: se genera UNA vez y se reusa entre corridas, para
// que un crash dependiente del key material reproduzca tras reiniciar el proceso.
static bool load_buf(const char* path, buf_t& out) {
  FILE* f = std::fopen(path, "rb");
  if (!f) return false;
  std::fseek(f, 0, SEEK_END);
  long n = std::ftell(f);
  std::fseek(f, 0, SEEK_SET);
  bool ok = false;
  if (n > 0 && n < (64 << 20)) {
    out = buf_t((int)n);
    ok = (std::fread(out.data(), 1, (size_t)n, f) == (size_t)n);
  }
  std::fclose(f);
  return ok;
}
static void save_buf(const char* path, const buf_t& b) {
  FILE* f = std::fopen(path, "wb");
  if (!f) return;
  if (b.size() > 0) std::fwrite(b.data(), 1, (size_t)b.size(), f);
  std::fclose(f);
}

// DKG limpio (sin caos) para obtener blobs válidos.
static bool bootstrap_keys() {
  // Reusar clave persistida si existe (reproducibilidad entre corridas).
  if (load_buf("cbmpc_fuzz_key1.bin", g_blob1) && load_buf("cbmpc_fuzz_key2.bin", g_blob2) &&
      e2::get_public_key_compressed(g_blob1, g_Q) == SUCCESS) {
    return true;
  }

  channel_t ch;
  chaos_plan_t noop;  // PASS en todo
  chaos_transport_t t0(ch, 0, noop), t1(ch, 1, noop);
  std::string n1 = "party_1", n2 = "party_2";
  coinbase::api::job_2p_t j1{coinbase::api::party_2p_t::p1, n1, n2, t0};
  coinbase::api::job_2p_t j2{coinbase::api::party_2p_t::p2, n1, n2, t1};

  error_t rv0 = UNINITIALIZED_ERROR, rv1 = UNINITIALIZED_ERROR;
  run_pair(ch, [&](int role) {
    return role == 0 ? e2::dkg(j1, kCurve, g_blob1) : e2::dkg(j2, kCurve, g_blob2);
  }, rv0, rv1);
  if (rv0 != SUCCESS || rv1 != SUCCESS) return false;
  if (e2::get_public_key_compressed(g_blob1, g_Q) != SUCCESS) return false;
  save_buf("cbmpc_fuzz_key1.bin", g_blob1);  // pin de la clave para reproducibilidad
  save_buf("cbmpc_fuzz_key2.bin", g_blob2);
  return true;
}

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  // RNG REAL de OpenSSL (no instalamos ningún RAND_METHOD determinista).
  g_ready = bootstrap_keys();
  if (!g_ready) { std::fprintf(stderr, "bootstrap_keys() failed\n"); std::abort(); }
  return 0;
}

// ----------------------------------------------------------------------------
// Cuerpo del fuzzer.
// ----------------------------------------------------------------------------
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (!g_ready || size < 8) return 0;
  FuzzedDataProvider fdp(data, size);

  // --- El fuzzer decide TODO el plan de ataque ---
  chaos_plan_t plan;
  plan.honest_target = fdp.ConsumeBool() ? 1 : 0;
  const bool do_refresh = fdp.ConsumeBool();  // ataca REFRESH (true) o SIGN (false)
  plan.target_msg_index = fdp.ConsumeIntegralInRange<int>(0, 7);  // mensaje 0..7
  plan.mut = (mut_e)(fdp.ConsumeIntegral<uint8_t>() % (uint8_t)mut_e::COUNT);
  plan.p_off = fdp.ConsumeIntegral<uint32_t>();
  plan.p_len = fdp.ConsumeIntegral<uint32_t>();
  plan.p_val = fdp.ConsumeIntegral<uint32_t>();
  plan.p_code = fdp.ConsumeIntegral<uint64_t>();
  {
    size_t take = fdp.ConsumeIntegralInRange<size_t>(0, 64);
    plan.p_bytes = fdp.ConsumeBytes<uint8_t>(take);
  }

  // hash de mensaje de 32 bytes (derivado del input)
  uint8_t h[32];
  {
    std::vector<uint8_t> hb = fdp.ConsumeBytes<uint8_t>(32);
    std::memset(h, 0, 32);
    if (!hb.empty()) std::memcpy(h, hb.data(), hb.size());
  }
  const mem_t mh(h, 32);

  channel_t ch;
  chaos_transport_t t0(ch, 0, plan), t1(ch, 1, plan);
  std::string n1 = "party_1", n2 = "party_2";
  coinbase::api::job_2p_t j1{coinbase::api::party_2p_t::p1, n1, n2, t0};
  coinbase::api::job_2p_t j2{coinbase::api::party_2p_t::p2, n1, n2, t1};

  error_t rv0 = UNINITIALIZED_ERROR, rv1 = UNINITIALIZED_ERROR;

  if (do_refresh) {
    // --- Ataque a REFRESH: la parte honesta recibe mensajes corruptos ---
    buf_t nb1, nb2;
    run_pair(ch, [&](int role) {
      return role == 0 ? e2::refresh(j1, g_blob1, nb1) : e2::refresh(j2, g_blob2, nb2);
    }, rv0, rv1);

    // ORÁCULO II (refresh): SUCCESS de la parte honesta => Q DEBE preservarse.
    int hp = plan.honest_target;
    error_t hrv = hp == 0 ? rv0 : rv1;
    buf_t& hb = hp == 0 ? nb1 : nb2;
    if (hrv == SUCCESS && hb.size() > 0) {
      buf_t newQ;
      if (e2::get_public_key_compressed(hb, newQ) == SUCCESS && !(newQ == g_Q)) {
        std::fprintf(stderr,
            "CRITICAL [REFRESH-BREAK] parte honesta P%d aceptó refresh que CAMBIÓ la clave pública\n",
            hp + 1);
        std::abort();
      }
    }

    // ORÁCULO II+ (el jugoso): si AMBAS partes dijeron SUCCESS, el protocolo
    // garantiza shares consistentes. Un SIGN LIMPIO (sin caos) con las claves
    // refrescadas DEBE producir una firma válida bajo Q. Si el refresh atacado
    // corrompió las shares en silencio, el sign limpio falla o da firma inválida
    // => corrupción de key material (Critical).
    if (rv0 == SUCCESS && rv1 == SUCCESS && nb1.size() > 0 && nb2.size() > 0) {
      channel_t ch2;
      chaos_plan_t noop;
      chaos_transport_t c0(ch2, 0, noop), c1(ch2, 1, noop);
      coinbase::api::job_2p_t s1{coinbase::api::party_2p_t::p1, n1, n2, c0};
      coinbase::api::job_2p_t s2{coinbase::api::party_2p_t::p2, n1, n2, c1};
      buf_t sidA, sidB, sgA, sgB;
      error_t sv0 = UNINITIALIZED_ERROR, sv1 = UNINITIALIZED_ERROR;
      run_pair(ch2, [&](int role) {
        return role == 0 ? e2::sign(s1, nb1, mh, sidA, sgA) : e2::sign(s2, nb2, mh, sidB, sgB);
      }, sv0, sv1);

      if (sv0 == SUCCESS && sv1 == SUCCESS) {
        if (sgA.size() == 0 || !ossl_verify(kNid, g_Q, h, sgA)) {
          std::fprintf(stderr,
              "CRITICAL [REFRESH-CORRUPT] refresh atacado dijo SUCCESS pero el sign limpio dio firma inválida\n");
          std::abort();
        }
      } else {
        // Ambas partes refrescaron OK, pero un sign 100%% limpio falla:
        // el refresh dejó las shares inconsistentes (SUCCESS mentiroso).
        std::fprintf(stderr,
            "CRITICAL [REFRESH-CORRUPT] refresh atacado dijo SUCCESS en ambas partes pero sign limpio FALLA (rv0=%x rv1=%x)\n",
            (unsigned)sv0, (unsigned)sv1);
        std::abort();
      }
    }
  } else {
    // --- Ataque a SIGN: solo P1 produce firma; oráculo fuerte cuando honest=P1 ---
    buf_t sid1, sid2, sig1, sig2;
    run_pair(ch, [&](int role) {
      return role == 0 ? e2::sign(j1, g_blob1, mh, sid1, sig1)
                       : e2::sign(j2, g_blob2, mh, sid2, sig2);
    }, rv0, rv1);

    // ORÁCULO II (sign): si P1 HONESTA devolvió SUCCESS con firma, DEBE verificar
    // bajo la Q original y NUESTRO hash. SUCCESS + no-verifica = aceptación inválida.
    if (plan.honest_target == 0 && rv0 == SUCCESS && sig1.size() > 0) {
      if (!ossl_verify(kNid, g_Q, h, sig1)) {
        std::fprintf(stderr,
            "CRITICAL [SIGN-BREAK] P1 honesta devolvió SUCCESS con firma que NO verifica bajo Q\n");
        std::abort();
      }
    }
  }

#ifdef HUNT_ASSERTS
  // Modo opcional de caza de DoS: si querés tratar aborts/assert alcanzables como
  // hallazgos, compilá con -DHUNT_ASSERTS. Por defecto NO, para no repetir el
  // diluvio de falsos positivos: un assert que lanza excepción escapa del hilo y
  // ya provoca terminate/SIGABRT capturado por libFuzzer sin nuestra ayuda.
#endif

  return 0;
}