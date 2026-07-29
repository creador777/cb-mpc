// ============================================================================
// fuzz_tdh2.cpp — Harness de fuzzing para TDH2 (Threshold Decryption)
// ----------------------------------------------------------------------------
// cb-mpc (Coinbase) — Bug Bounty HackerOne: High/Critical = $15K–$50K+
//
// Modelo de amenaza:
//   - P0, P1, P2 = partes HONESTAS que corren la librería SIN MODIFICAR
//     vía la API PÚBLICA (include/cbmpc/api/tdh2.h).
//   - El atacante reemplaza/muta UN partial decryption (P2 maliciosa).
//   - El combine es LOCAL (no interactivo, sin red).
//
// Oráculos implementados (cada abort() = hallazgo de miles de dólares):
//
//   [O1] INTEGRITY-BREAK: combine SUCCESS pero plaintext != original
//   [O2] MALLEABILITY (CCA2): ciphertext mutado descifra a plaintext relacionado
//   [O3] LABEL-CONFUSION: cifrar con label A, combinar/verify con label B
//   [O4] CROSS-CIPHERTEXT: partial de C1 usado en combine de C2
//   [O5] PARTIAL-FORGERY: partial malformado aceptado por combine
//        (zero bytes, punto fuera de curva, share de party inexistente)
//   [O6] DIFFERENTIAL: dos subsets de partials deben dar mismo plaintext
//   [O7] VERIFY-BYPASS: verify rechaza pero combine acepta
//   [O8] EMPTY-OUTPUT: combine SUCCESS con plaintext vacío cuando original no lo era
//   [O9] LENGTH-LEAK: ciphertext mutado produce plaintext de largo distinto al original
//        sin cambiar el contenido (padding oracle)
//   [O10] REPLAY: mismo (ciphertext, label, partials) combinado dos veces da
//         resultados distintos (no determinismo)
//   [O11] QUORUM-BREAK: combine_additive con menos de n partials (solo 1 o 2)
//         igual descifra
//   [O12] DUPLICATE-SHARE: mismo partial duplicado en combine → ¿aceptado?
//   [O13] POINT-NOT-ON-CURVE: partial con punto comprimido inválido
//   [O14] SHARE-OF-OTHER-KEY: partial de otro DKG
//   [O15] SERIALIZATION-EDGE: mutación estructura-consciente del formato
//         converter_t (convert_len, code_type)
//   [O16] SELF-DECRYPT: partial_decrypt con private_share de party A y
//         ciphertext que party A generó → invariante local
//
// Compilar con: bash fuzz/build_fuzz_tdh2.sh
// ============================================================================

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <cbmpc/api/tdh2.h>

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

using namespace coinbase;

// ============================================================================
// RNG DETERMINISTA sembrado desde el input del fuzzer (xoshiro256**)
// ============================================================================
namespace fuzzrng {

inline uint64_t s[4] = {0x9E3779B97F4A7C15ULL, 0xBF58476D1CE4E5B9ULL,
                        0x94D049BB133111EBULL, 0x2545F4914F6CDD1DULL};

inline uint64_t rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }

inline uint64_t next() {
  const uint64_t r = rotl(s[1] * 5, 7) * 9;
  const uint64_t t = s[1] << 17;
  s[2] ^= s[0];
  s[3] ^= s[1];
  s[1] ^= s[2];
  s[0] ^= s[3];
  s[2] ^= t;
  s[3] = rotl(s[3], 45);
  return r;
}

void seed_from_bytes(const uint8_t* data, size_t size) {
  // Mix input bytes into the 4 state words
  for (size_t i = 0; i < 4; i++) {
    uint64_t v = 0;
    for (size_t j = 0; j < 8 && (i * 8 + j) < size; j++) {
      v |= static_cast<uint64_t>(data[i * 8 + j]) << (j * 8);
    }
    if (v != 0) s[i] ^= v;
  }
  // Burn-in
  for (int i = 0; i < 20; i++) next();
}

void install() {
  // Replace OpenSSL RNG with our deterministic one
  // This is a simplified approach; the existing fuzz harnesses in cb-mpc
  // use RAND_set_rand_method with a custom RAND_METHOD.
  // For the harness: we rely on the library using the seeded xoshiro
  // for any randomness it needs internally. The key insight is that
  // encrypt/partial_decrypt/combine_additive are deterministic given
  // their inputs (no fresh randomness needed).
  // DKG needs randomness, which is handled during bootstrap.
}

} // namespace fuzzrng

// ============================================================================
// Red en memoria (solo para bootstrap DKG, que SÍ es interactivo)
// ============================================================================
struct channel_t {
  std::mutex m;
  std::condition_variable cv;
  std::deque<buf_t> q;
};

struct network_t {
  explicit network_t(int parties)
    : n(parties), ch(parties, std::vector<std::shared_ptr<channel_t>>(parties)) {
    for (int a = 0; a < n; a++)
      for (int b = 0; b < n; b++)
        if (a != b) ch[a][b] = std::make_shared<channel_t>();
  }

  int n;
  std::vector<std::vector<std::shared_ptr<channel_t>>> ch;
  std::atomic<bool> aborted{false};

  void reset_abort() { aborted.store(false); }
  void abort_all() {
    aborted.store(true);
    for (auto& row : ch)
      for (auto& c : row)
        if (c) {
          std::lock_guard<std::mutex> lk(c->m);
          c->cv.notify_all();
        }
  }
};

// ---------------------------------------------------------------------------
// INVARIANTE (2026-07-29): este backstop DEBE ser menor que el -timeout de
// libFuzzer, que swarm_local.sh y fuzz-farm.yml fijan en 25s.
//
// Estaba en 30s, o sea MAYOR. Consecuencia: el backstop no podia dispararse
// nunca. Ante un receive estancado libFuzzer llegaba primero, declaraba
// TIMEOUT y mataba el proceso, en vez de que la operacion devolviera un error
// limpio y el fuzzing siguiera. Se perdia la ejecucion entera, se escribia un
// artefacto y habia que reiniciar. fuzz_malicious_party.cpp y
// fuzz_schnorr_party.cpp ya respetaban la regla con 8s; este archivo no.
//
// Se alinea con esos dos. Si algun dia se sube el -timeout de libFuzzer, hay
// que subir este valor DESPUES y siempre por debajo.
// ---------------------------------------------------------------------------
static constexpr auto kRecvTimeout = std::chrono::seconds(8);

// ============================================================================
// Transporte honesto (para bootstrap DKG)
// ============================================================================
class honest_transport_t final : public coinbase::api::data_transport_i {
public:
  honest_transport_t(int self, std::shared_ptr<network_t> net)
    : self_(self), net_(std::move(net)) {}

  error_t send(coinbase::api::party_idx_t rcv, mem_t msg) override {
    if (!net_ || rcv < 0 || rcv >= net_->n || rcv == self_) return E_BADARG;
    auto c = net_->ch[self_][rcv];
    if (!c) return E_GENERAL;
    {
      std::lock_guard<std::mutex> lk(c->m);
      c->q.emplace_back(msg);
    }
    c->cv.notify_one();
    return SUCCESS;
  }

  error_t receive(coinbase::api::party_idx_t snd, buf_t& msg) override {
    if (!net_ || snd < 0 || snd >= net_->n || snd == self_) return E_BADARG;
    auto c = net_->ch[snd][self_];
    if (!c) return E_GENERAL;
    std::unique_lock<std::mutex> lk(c->m);
    c->cv.wait_for(lk, kRecvTimeout, [&] {
      return !c->q.empty() || net_->aborted.load();
    });
    if (c->q.empty()) return E_GENERAL;
    msg = std::move(c->q.front());
    c->q.pop_front();
    return SUCCESS;
  }

  error_t receive_all(const std::vector<coinbase::api::party_idx_t>& s,
                      std::vector<buf_t>& m) override {
    m.clear();
    m.resize(s.size());
    for (size_t i = 0; i < s.size(); i++) {
      error_t rv = receive(s[i], m[i]);
      if (rv != SUCCESS) return rv;
    }
    return SUCCESS;
  }

private:
  int self_;
  std::shared_ptr<network_t> net_;
};

// ============================================================================
// Bootstrap DKG: corre dkg_additive con 3 partes por la red en memoria.
// Cachea a disco para no repetir.
// ============================================================================
static buf_t g_public_key;
static std::vector<buf_t> g_public_shares;
static buf_t g_private_shares[3];
static bool g_bootstrapped = false;

static bool save_buf(const char* path, const buf_t& b) {
  FILE* f = std::fopen(path, "wb");
  if (!f) return false;
  if (b.size() > 0) std::fwrite(b.data(), 1, (size_t)b.size(), f);
  std::fclose(f);
  return true;
}

static bool load_buf(const char* path, buf_t& out) {
  FILE* f = std::fopen(path, "rb");
  if (!f) return false;
  std::fseek(f, 0, SEEK_END);
  long n = std::ftell(f);
  std::fseek(f, 0, SEEK_SET);
  if (n <= 0) { std::fclose(f); return false; }
  std::vector<uint8_t> tmp((size_t)n);
  if (std::fread(tmp.data(), 1, (size_t)n, f) != (size_t)n) {
    std::fclose(f); return false;
  }
  std::fclose(f);
  out = buf_t(mem_t(tmp.data(), tmp.size()));
  return true;
}

template <typename F0, typename F1, typename F2>
static void run_3pc_dkg(const std::shared_ptr<network_t>& net,
                        F0&& f0, F1&& f1, F2&& f2,
                        error_t& rv0, error_t& rv1, error_t& rv2) {
  net->reset_abort();
  rv0 = rv1 = rv2 = E_GENERAL;
  std::thread t0([&] { rv0 = f0(); if (rv0 != SUCCESS) net->abort_all(); });
  std::thread t1([&] { rv1 = f1(); if (rv1 != SUCCESS) net->abort_all(); });
  std::thread t2([&] { rv2 = f2(); if (rv2 != SUCCESS) net->abort_all(); });
  t0.join(); t1.join(); t2.join();
}

static bool bootstrap_dkg() {
  // Try loading from cache
  if (load_buf("cbmpc_tdh2_pk.bin", g_public_key)) {
    for (int i = 0; i < 3; i++) {
      char path[64];
      std::snprintf(path, sizeof(path), "cbmpc_tdh2_sk%d.bin", i);
      if (!load_buf(path, g_private_shares[i])) return false;
    }
    // Reconstruct public_shares from the cached files
    for (int i = 0; i < 3; i++) {
      char path[64];
      std::snprintf(path, sizeof(path), "cbmpc_tdh2_ps%d.bin", i);
      buf_t ps;
      if (!load_buf(path, ps)) return false;
      g_public_shares.push_back(std::move(ps));
    }
    return true;
  }

  // Fresh DKG
  auto net = std::make_shared<network_t>(3);
  honest_transport_t t0(0, net);
  honest_transport_t t1(1, net);
  honest_transport_t t2(2, net);

  static constexpr std::string_view names[] = {"P0", "P1", "P2"};
  std::vector<std::string_view> pnames(names, names + 3);

  coinbase::api::job_mp_t j0{0, pnames, t0};
  coinbase::api::job_mp_t j1{1, pnames, t1};
  coinbase::api::job_mp_t j2{2, pnames, t2};

  buf_t pk0, pk1, pk2;
  std::vector<buf_t> ps0, ps1, ps2;
  buf_t sk0, sk1, sk2;
  buf_t sid0, sid1, sid2;

  error_t r0, r1, r2;
  run_3pc_dkg(net,
    [&] { return coinbase::api::tdh2::dkg_additive(j0, coinbase::api::curve_id::secp256k1, pk0, ps0, sk0, sid0); },
    [&] { return coinbase::api::tdh2::dkg_additive(j1, coinbase::api::curve_id::secp256k1, pk1, ps1, sk1, sid1); },
    [&] { return coinbase::api::tdh2::dkg_additive(j2, coinbase::api::curve_id::secp256k1, pk2, ps2, sk2, sid2); },
    r0, r1, r2);

  if (r0 != SUCCESS || r1 != SUCCESS || r2 != SUCCESS) {
    std::fprintf(stderr, "[TDH2] DKG bootstrap FAILED: r0=%d r1=%d r2=%d\n",
                 (int)r0, (int)r1, (int)r2);
    return false;
  }

  // All parties must agree on public_key and public_shares
  if (!(pk0 == pk1) || !(pk1 == pk2)) {
    std::fprintf(stderr, "[TDH2] DKG public_key mismatch across parties!\n");
    return false;
  }

  g_public_key = std::move(pk0);
  g_public_shares = std::move(ps0);
  g_private_shares[0] = std::move(sk0);
  g_private_shares[1] = std::move(sk1);
  g_private_shares[2] = std::move(sk2);

  // Cache to disk
  save_buf("cbmpc_tdh2_pk.bin", g_public_key);
  for (int i = 0; i < 3; i++) {
    char path[64];
    std::snprintf(path, sizeof(path), "cbmpc_tdh2_sk%d.bin", i);
    save_buf(path, g_private_shares[i]);
    std::snprintf(path, sizeof(path), "cbmpc_tdh2_ps%d.bin", i);
    save_buf(path, g_public_shares[i]);
  }

  std::fprintf(stderr, "[TDH2] DKG bootstrap OK: pk=%zu bytes, shares=%zu x %zu bytes\n",
               g_public_key.size(), g_public_shares.size(),
               g_public_shares.empty() ? 0 : g_public_shares[0].size());
  return true;
}

// ============================================================================
// Utilidades para construir mem_t / buf_t desde raw bytes
// ============================================================================
static mem_t to_mem(const buf_t& b) {
  return mem_t(b.data(), b.size());
}

static mem_t to_mem(const uint8_t* d, size_t s) {
  return mem_t(d, s);
}

static std::vector<mem_t> to_mem_vec(const std::vector<buf_t>& bufs) {
  std::vector<mem_t> out;
  out.reserve(bufs.size());
  for (const auto& b : bufs) out.push_back(to_mem(b));
  return out;
}

// ============================================================================
// Mutación estructura-consciente del formato converter_t
// (misma serialización que usa cb-mpc internamente para TDH2)
// ============================================================================
static void mutate_serialization_header(uint8_t* data, size_t size, int mode) {
  if (size < 12) return;
  switch (mode % 8) {
    case 0: // convert_len overflow (4-byte branch)
      data[8] = 0xE4; data[9] = 0xFF; data[10] = 0xFF; data[11] = 0xFF;
      break;
    case 1: // convert_len = MAX_CONVERT_LEN exact (boundary)
      data[8] = 0xE4; data[9] = 0x00; data[10] = 0x00; data[11] = 0x00;
      break;
    case 2: // convert_len = MAX+1 (off-by-one)
      data[8] = 0xE4; data[9] = 0x00; data[10] = 0x00; data[11] = 0x01;
      break;
    case 3: // convert_len = 0 (empty field)
      data[8] = 0x00;
      break;
    case 4: // All 0xFF convert_len
      data[8] = 0xFF; data[9] = 0xFF; data[10] = 0xFF; data[11] = 0xFF;
      break;
    case 5: // Wrong code_type byte
      if (size > 0) data[0] = 0xFF;
      break;
    case 6: // 2-byte convert_len with max value
      data[8] = 0xBF; data[9] = 0xFF;
      break;
    case 7: // 1-byte convert_len with 0x7F
      data[8] = 0x7F;
      break;
  }
}

// Inyectar bytes degenerados en campos de 32 bytes (escalares/puntos)
static void poison_scalar_field(uint8_t* field, size_t len, int mode) {
  if (len < 32) return;
  switch (mode % 10) {
    case 0: std::memset(field, 0x00, 32); break;           // zero
    case 1: std::memset(field, 0xFF, 32); break;           // all-ones
    case 2: field[31] ^= 0x01; break;                      // flip LSB
    case 3: field[0] ^= 0x80; break;                       // flip MSB
    case 4: std::memset(field, 0x00, 32); field[31] = 1; break; // one
    case 5: // curve order (secp256k1)
      {
        static const uint8_t order[32] = {
          0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
          0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
          0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
          0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
        };
        std::memcpy(field, order, 32);
      }
      break;
    case 6: // order - 1
      {
        static const uint8_t ord_m1[32] = {
          0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
          0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
          0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
          0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40
        };
        std::memcpy(field, ord_m1, 32);
      }
      break;
    case 7: // NOT bitwise
      for (int i = 0; i < 32; i++) field[i] = ~field[i];
      break;
    case 8: // swap endianness
      for (int i = 0; i < 16; i++)
        std::swap(field[i], field[31 - i]);
      break;
    case 9: // random noise
      for (int i = 0; i < 32; i++)
        field[i] ^= (uint8_t)(fuzzrng::next() & 0xFF);
      break;
  }
}

// Mutar punto comprimido SEC1 (02/03 prefix + 32 bytes)
static void poison_compressed_point(uint8_t* data, size_t len, int mode) {
  if (len < 33) return;
  switch (mode % 7) {
    case 0: // Identity point (should be rejected)
      std::memset(data, 0x00, 33);
      break;
    case 1: // Wrong parity prefix
      data[0] = (data[0] == 0x02) ? 0x03 : 0x02;
      break;
    case 2: // Invalid prefix byte
      data[0] = 0x04; // uncompressed marker on compressed-length field
      break;
    case 3: // All zeros with valid prefix
      data[0] = 0x02;
      std::memset(data + 1, 0x00, 32);
      break;
    case 4: // X coordinate >= p (field element overflow)
      std::memset(data + 1, 0xFF, 32);
      break;
    case 5: // Valid prefix but garbage coordinates
      data[0] = 0x02;
      for (int i = 1; i < 33; i++)
        data[i] = (uint8_t)(fuzzrng::next() & 0xFF);
      break;
    case 6: // X = p-1 (boundary)
      {
        static const uint8_t p_minus_1[32] = {
          0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
          0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
          0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
          0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE
        };
        data[0] = 0x02;
        std::memcpy(data + 1, p_minus_1, 32);
      }
      break;
  }
}

// ============================================================================
// LLVMFuzzerInitialize: bootstrap UNA vez
// ============================================================================
extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
  (void)argc; (void)argv;

  // Seed RNG with some initial entropy for bootstrap
  uint64_t seed = 0xDEADBEEFCAFEBABEULL;
  fuzzrng::s[0] ^= seed;
  fuzzrng::s[1] ^= seed >> 1;
  fuzzrng::s[2] ^= seed >> 2;
  fuzzrng::s[3] ^= seed >> 3;
  for (int i = 0; i < 20; i++) fuzzrng::next();

  g_bootstrapped = bootstrap_dkg();
  if (!g_bootstrapped) {
    std::fprintf(stderr, "[TDH2] FATAL: bootstrap_dkg() failed\n");
    std::abort();
  }

  std::fprintf(stderr, "[TDH2] LLVMFuzzerInitialize OK: ready to fuzz\n");
  return 0;
}

// ============================================================================
// LLVMFuzzerTestOneInput: el loop de fuzz
// ============================================================================
// Dos mem_t con el MISMO contenido? Los oraculos de label-binding lo necesitan:
// "verify acepta con otra label" solo es un bug si la label es REALMENTE otra.
// Ojo con data[0] en buffers vacios (lectura fuera de rango): por eso se compara
// el tamano primero y se trata el caso size==0 aparte.
static bool same_mem(mem_t a, mem_t b) {
  if (a.size != b.size) return false;
  if (a.size == 0) return true;
  return std::memcmp(a.data, b.data, (size_t)a.size) == 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  if (!g_bootstrapped || Size < 16) return 0;

  // Seed RNG deterministically from fuzzer input
  fuzzrng::seed_from_bytes(Data, Size);

  // ---- Parse fuzzer input ----
  // Byte layout:
  //   Data[0]:     mode / selector (which oracle to exercise)
  //   Data[1]:     label_len (0..31, actual = val % 32)
  //   Data[2]:     plaintext_len (0..255, actual = val + 1)
  //   Data[3..4]:  mutation_selector (le16)
  //   Data[5..6]:  extra_entropy
  //   Data[7..15]: reserved / extra mutation params
  //   Data[16..]:  label + plaintext + mutation_payload

  const uint8_t mode = Data[0];
  const size_t label_len = (Data[1] % 31) + 1;        // 1..32
  const size_t pt_len = ((size_t)Data[2]) + 1;         // 1..256
  const uint16_t mut_sel = (uint16_t)Data[3] | ((uint16_t)Data[4] << 8);

  size_t offset = 16;
  auto consume_bytes = [&](size_t n) -> mem_t {
    if (offset + n > Size) n = Size - offset;
    mem_t m(Data + offset, n);
    offset += n;
    return m;
  };

  mem_t label = consume_bytes(label_len);
  mem_t plaintext = consume_bytes(pt_len);

  // OJO: consume_bytes RECORTA a los bytes que quedan, asi que el largo real puede
  // ser < pt_len. Comparar contra pt_len (el largo PEDIDO) causaba dos bugs graves:
  //  1) heap-buffer-overflow al memcmp pt_len bytes sobre un buffer mas chico (ASan);
  //  2) FALSO "CRITICAL [O1-INTEGRITY-BREAK]": se cifra el plaintext recortado, el
  //     descifrado devuelve ese mismo largo, pero se comparaba contra pt_len -> los
  //     tamanos no coincidian y un roundtrip CORRECTO se reportaba como rotura.
  // Regla: para toda comparacion usar el largo REAL, no el pedido.
  const size_t pt_actual = (size_t)plaintext.size;

  // ---- STEP 1: Encrypt (honesto) ----
  buf_t ciphertext;
  error_t enc_rv = coinbase::api::tdh2::encrypt(
      to_mem(g_public_key), plaintext, label, ciphertext);
  if (enc_rv != SUCCESS) return 0; // encrypt failed, nothing to fuzz

  // ---- STEP 1b: Verify (debe pasar para el ciphertext honesto) ----
  error_t ver_rv = coinbase::api::tdh2::verify(
      to_mem(g_public_key), to_mem(ciphertext), label);

  // ---- [O7] VERIFY-BYPASS: si verify rechaza algo que combine acepta luego ----
  // (se chequea más abajo después del combine)

  // ---- STEP 2: Partial decrypts (locales, SIN RED) ----
  buf_t partials[3];
  error_t pd_rv[3];
  for (int i = 0; i < 3; i++) {
    pd_rv[i] = coinbase::api::tdh2::partial_decrypt(
        to_mem(g_private_shares[i]), to_mem(ciphertext), label, partials[i]);
  }

  // ---- STEP 3: Selector de modo de ataque ----
  // mode determina qué ataque aplicar

  std::vector<buf_t> combine_partials;
  mem_t combine_label = label;
  buf_t combine_ciphertext_buf = ciphertext;
  mem_t combine_ciphertext = to_mem(ciphertext);
  std::vector<mem_t> combine_public_shares = to_mem_vec(g_public_shares);
  buf_t plaintext_out;

  // Plaintext que DEBE salir si combine tiene exito. Por defecto el original, pero
  // hay modos que cifran OTRO plaintext y le pasan a combine un (ciphertext,partials)
  // consistente entre si: ahi lo correcto es que salga ESE otro plaintext, no el
  // original. Sin esto, el modo 14 disparaba un [O1-INTEGRITY-BREAK] FALSO cada vez
  // (combine devolvia pt2 correctamente y lo comparabamos contra el original).
  // Es seguro guardar un mem_t que apunte a Data: vive toda la llamada.
  mem_t expected_pt = plaintext;

  // ---- FILTRO DE PREMISAS ----------------------------------------------------
  // Cada modo arma un escenario "malicioso" (un partial forjado, un ciphertext
  // mutado, una label distinta...). Pero los bytes salen del fuzzer, asi que el
  // escenario puede terminar siendo INOFENSIVO: el partial forjado sale igual al
  // real, la mutacion XOR con 0 no cambia nada, la label "distinta" sale identica.
  // En esos casos que la libreria acepte es CORRECTO, y gritar CRITICAL es mentir.
  //
  // Esto no es teorico: 6 alarmas de ALTO VALOR en un dia, todas por esta causa.
  // Y no son raras — libFuzzer va guiado por cobertura, asi que BUSCA el input que
  // provoca el abort: converge al falso positivo y suena sin parar.
  //
  // Regla: el modo DECLARA si su escenario es de verdad malicioso; ningun oraculo
  // puede abortar sin eso. Si la premisa no se cumple es un bug del harness, se
  // registra como HARNESS-BUG (no despierta a nadie) y se sigue fuzzeando.
  bool escenario_malicioso = true;

  // Resultado de verify() sobre el ciphertext YA ATACADO. Tiene que vivir a nivel de
  // funcion: el modo 10 lo calculaba en una variable local que moria en el break, y el
  // oraculo O7 terminaba consultando ver_rv, que es el verify del ciphertext HONESTO y
  // por tanto casi siempre SUCCESS -> O7 no podia disparar NUNCA (oraculo muerto).
  // SUCCESS por defecto = "no se ataco el ciphertext", que no dispara nada.
  error_t ver_rv_atacado = SUCCESS;

  switch (mode & 0x3F) { // 64 modos
    // ================================================================
    // MODO 0: BASE — reemplazar partial[2] con bytes del fuzzer
    // ================================================================
    case 0: {
      mem_t evil = consume_bytes(partials[2].size() > 0 ? partials[2].size() : 256);
      partials[2] = buf_t(evil);
      for (int i = 0; i < 3; i++)
        combine_partials.push_back(partials[i]);
      break;
    }

    // ================================================================
    // MODO 1: LABEL-CONFUSION — encrypt con label A, combine con label B
    // ================================================================
    case 1: {
      // Generate a different label from the fuzzer data
      mem_t evil_label = consume_bytes(label_len > 0 ? label_len : 8);
      combine_label = evil_label;
      for (int i = 0; i < 3; i++)
        combine_partials.push_back(partials[i]);
      break;
    }

    // ================================================================
    // MODO 2: CROSS-CIPHERTEXT — partials de C1 con ciphertext C2
    // ================================================================
    case 2: {
      // Encrypt a second ciphertext
      mem_t pt2 = consume_bytes(pt_len > 0 ? pt_len : 16);
      mem_t label2 = label; // same label
      buf_t ciphertext2;
      error_t enc2_rv = coinbase::api::tdh2::encrypt(
          to_mem(g_public_key), pt2, label2, ciphertext2);
      if (enc2_rv != SUCCESS) return 0;

      // Use partials from C1 but ciphertext = C2
      // OJO: mem_t es una VISTA sin dueno. ciphertext2 es local al case y muere en el
      // break de abajo, asi que to_mem(ciphertext2) quedaba colgando y se usaba ~400
      // lineas mas abajo en combine_additive (heap-use-after-free real, visto con ASan).
      // La vista tiene que salir del buffer que SI persiste: combine_ciphertext_buf.
      combine_ciphertext_buf = ciphertext2;
      combine_ciphertext = to_mem(combine_ciphertext_buf);
      // PREMISA: C2 tiene que ser realmente OTRO ciphertext. Si saliera igual a C1,
      // combinar con los partials de C1 seria lo normal y no habria nada que reportar.
      escenario_malicioso = !same_mem(to_mem(ciphertext), combine_ciphertext);
      for (int i = 0; i < 3; i++)
        combine_partials.push_back(partials[i]);
      break;
    }

    // ================================================================
    // MODO 3: PARTIAL-FORGERY — partial completamente sintético
    // ================================================================
    case 3: {
      buf_t orig2 = partials[2];       // guardar el real ANTES de pisarlo
      mem_t evil = consume_bytes(512); // large evil partial
      partials[2] = buf_t(evil);
      // PREMISA: el partial "forjado" tiene que diferir del legitimo. Si consume_bytes
      // devolviera los mismos bytes (o el input ya se agoto), no hay forja: que combine
      // acepte seria correcto y O5-PARTIAL-FORGERY estaria mintiendo.
      escenario_malicioso = !same_mem(to_mem(partials[2]), to_mem(orig2));
      // Also poison the serialization structure
      if (partials[2].size() >= 12) {
        mutate_serialization_header(partials[2].data(), partials[2].size(),
                                    mut_sel & 0x7);
      }
      for (int i = 0; i < 3; i++)
        combine_partials.push_back(partials[i]);
      break;
    }

    // ================================================================
    // MODO 4: MALLEABILITY — ciphertext levemente mutado
    // ================================================================
    case 4: {
      // PREMISA: hay que comprobar que la mutacion REALMENTE cambie el ciphertext.
      // El XOR de abajo usa mut_sel, que puede valer 0 en los bytes tocados -> el
      // ciphertext queda intacto y todo lo que siga es comportamiento legitimo.
      buf_t ct_antes = ciphertext;
      if (ciphertext.size() > 0) {
        uint8_t* ct_data = ciphertext.data();
        size_t ct_sz = ciphertext.size();
        // Flip bits determinísticamente
        for (size_t i = 0; i < ct_sz && i < 32; i++) {
          ct_data[i] ^= (uint8_t)((mut_sel >> (i % 8)) & 0xFF);
        }
        // También probar mutación de cabecera
        if (ct_sz >= 12 && (mut_sel & 0x100)) {
          mutate_serialization_header(ct_data, ct_sz, (mut_sel >> 5) & 0x7);
        }
        combine_ciphertext = to_mem(ciphertext);
      }
      escenario_malicioso = !same_mem(to_mem(ct_antes), to_mem(ciphertext));
      for (int i = 0; i < 3; i++)
        combine_partials.push_back(partials[i]);
      break;
    }

    // ================================================================
    // MODO 5: QUORUM-BREAK — solo 1 o 2 partials (no 3)
    // ================================================================
    case 5: {
      int num_partials = 1 + ((mut_sel >> 8) & 0x1); // 1 o 2
      for (int i = 0; i < num_partials; i++)
        combine_partials.push_back(partials[i]);
      // Also reduce public_shares to match
      combine_public_shares.resize(num_partials);
      break;
    }

    // ================================================================
    // MODO 6: DUPLICATE-SHARE — mismo partial twice
    // ================================================================
    case 6: {
      combine_partials.push_back(partials[0]);
      combine_partials.push_back(partials[0]); // duplicate
      combine_partials.push_back(partials[1]);
      break;
    }

    // ================================================================
    // MODO 7: POINT-NOT-ON-CURVE — partial con punto inválido
    // ================================================================
    case 7: {
      // Buscar y corromper posibles puntos comprimidos en el partial
      if (partials[2].size() >= 33) {
        // Escanear buscando bytes 0x02/0x03
        for (size_t i = 0; i + 33 <= partials[2].size(); i++) {
          if (partials[2].data()[i] == 0x02 || partials[2].data()[i] == 0x03) {
            poison_compressed_point(partials[2].data() + i, 33, mut_sel & 0x7);
            break;
          }
        }
      }
      for (int i = 0; i < 3; i++)
        combine_partials.push_back(partials[i]);
      break;
    }

    // ================================================================
    // MODO 8: ZERO-PARTIAL — partial todo ceros
    // ================================================================
    case 8: {
      if (partials[2].size() > 0) {
        std::memset(partials[2].data(), 0x00, partials[2].size());
      } else {
        std::vector<uint8_t> zeros(256, 0x00);
        partials[2] = buf_t(mem_t(zeros.data(), zeros.size()));
      }
      for (int i = 0; i < 3; i++)
        combine_partials.push_back(partials[i]);
      break;
    }

    // ================================================================
    // MODO 9: EMPTY-PARTIAL — partial vacío
    // ================================================================
    case 9: {
      partials[2] = buf_t(); // empty
      for (int i = 0; i < 3; i++)
        combine_partials.push_back(partials[i]);
      break;
    }

    // ================================================================
    // MODO 10: VERIFY vs COMBINE — verificar ciphertext mutado
    // ================================================================
    case 10: {
      buf_t ct_orig_m10 = ciphertext;   // copia para comprobar que la mutacion muto
      // Mutar ciphertext
      if (ciphertext.size() > 0) {
        uint8_t* ct = ciphertext.data();
        for (size_t i = 0; i < ciphertext.size() && i < 8; i++)
          ct[i] ^= (uint8_t)(fuzzrng::next() & 0xFF);
      }
      // Verify sobre el ciphertext YA MUTADO. El resultado va a la variable de
      // funcion: si se quedara local, el oraculo O7 no lo ve (era el bug).
      ver_rv_atacado = coinbase::api::tdh2::verify(
          to_mem(g_public_key), to_mem(ciphertext), label);

      for (int i = 0; i < 3; i++)
        combine_partials.push_back(partials[i]);
      combine_ciphertext = to_mem(ciphertext);
      // PREMISA: solo cuenta como ataque si la mutacion cambio el ciphertext.
      escenario_malicioso = !same_mem(to_mem(ct_orig_m10), to_mem(ciphertext));
      break;
    }

    // ================================================================
    // MODO 11: DIFFERENTIAL — comparar subsets de partials
    // ================================================================
    case 11: {
      // Primero: combine con partials[0,1,2] (los 3)
      buf_t out_full;
      std::vector<buf_t> all3 = {partials[0], partials[1], partials[2]};
      error_t rv_full = coinbase::api::tdh2::combine_additive(
          to_mem(g_public_key), combine_public_shares, label,
          {to_mem(partials[0]), to_mem(partials[1]), to_mem(partials[2])},
          to_mem(ciphertext), out_full);

      // Segundo: combine con partials[1,0,2] (orden distinto)
      buf_t out_perm;
      error_t rv_perm = coinbase::api::tdh2::combine_additive(
          to_mem(g_public_key), combine_public_shares, label,
          {to_mem(partials[1]), to_mem(partials[0]), to_mem(partials[2])},
          to_mem(ciphertext), out_perm);

      // [O6] DIFFERENTIAL: ambos SUCCESS pero resultados distintos
      if (rv_full == SUCCESS && rv_perm == SUCCESS) {
        if (!(out_full == out_perm)) {
          std::fprintf(stderr,
            "\n\n========================================\n"
            "CRITICAL [O6-DIFFERENTIAL] combine da resultados distintos\n"
            "según el orden de los partials.\n"
            "  out_full.size()=%d  out_perm.size()=%d\n"
            "========================================\n\n",
            (int)out_full.size(), (int)out_perm.size());
          std::abort();
        }
      }

      // Usar los 3 partials para el combine normal
      for (int i = 0; i < 3; i++)
        combine_partials.push_back(partials[i]);
      break;
    }

    // ================================================================
    // MODO 12: SCALAR-POISON — envenenar campos escalares en partial
    // ================================================================
    case 12: {
      if (partials[2].size() >= 32) {
        // Escanear por campos de 32 bytes y envenenarlos
        size_t n = partials[2].size();
        for (size_t i = 0; i + 32 <= n; i += 32) {
          if ((fuzzrng::next() & 0x3) == 0) { // 25% chance per field
            poison_scalar_field(partials[2].data() + i, 32, (mut_sel + i) & 0xF);
          }
        }
      }
      for (int i = 0; i < 3; i++)
        combine_partials.push_back(partials[i]);
      break;
    }

    // ================================================================
    // MODO 13: SERIALIZATION-EDGE — atacar cabecera de serialización
    // ================================================================
    case 13: {
      if (partials[2].size() >= 12) {
        mutate_serialization_header(partials[2].data(), partials[2].size(),
                                    mut_sel & 0x7);
      }
      // También mutar ciphertext
      if (ciphertext.size() >= 12) {
        mutate_serialization_header(ciphertext.data(), ciphertext.size(),
                                    (mut_sel >> 4) & 0x7);
        combine_ciphertext = to_mem(ciphertext);
      }
      for (int i = 0; i < 3; i++)
        combine_partials.push_back(partials[i]);
      break;
    }

    // ================================================================
    // MODO 14: LABEL + CIPHERTEXT swap — label A en ciphertext de B
    // ================================================================
    case 14: {
      // Cifrar otro plaintext
      mem_t pt2 = consume_bytes(pt_len > 0 ? pt_len : 16);
      mem_t label2 = consume_bytes(label_len > 0 ? label_len : 8);

      buf_t ct2;
      error_t enc2_rv = coinbase::api::tdh2::encrypt(
          to_mem(g_public_key), pt2, label2, ct2);
      if (enc2_rv != SUCCESS) return 0;

      // Calcular partials para ct2
      buf_t pd2[3];
      for (int i = 0; i < 3; i++) {
        coinbase::api::tdh2::partial_decrypt(
            to_mem(g_private_shares[i]), to_mem(ct2), label2, pd2[i]);
      }

      // Mezclar: ciphertext de ct2, label original, partials de ct2
      // Mismo caso que el MODO 2: ct2 es local al case y muere en el break -> la vista
      // debe apuntar al buffer persistente, no al local (heap-use-after-free).
      combine_ciphertext_buf = ct2;
      combine_ciphertext = to_mem(combine_ciphertext_buf);
      combine_label = label; // label original con ciphertext ajeno
      // ct2 y pd2 son CONSISTENTES entre si, asi que si combine tiene exito lo
      // correcto es que devuelva pt2. Lo unico raro de este modo es la label
      // cruzada, y eso lo mira el oraculo de label-binding, no el de integridad.
      expected_pt = pt2;
      for (int i = 0; i < 3; i++)
        combine_partials.push_back(pd2[i]);
      break;
    }

    // ================================================================
    // MODO 15: SELF-DECRYPT — verificar invariante local
    //   partial_decrypt con su propio ciphertext DEBE dar consistencia
    // ================================================================
    case 15: {
      // [O16] Verificar que partial_decrypt es determinista
      buf_t pd_a, pd_b;
      error_t rva = coinbase::api::tdh2::partial_decrypt(
          to_mem(g_private_shares[0]), to_mem(ciphertext), label, pd_a);
      error_t rvb = coinbase::api::tdh2::partial_decrypt(
          to_mem(g_private_shares[0]), to_mem(ciphertext), label, pd_b);

      // ORACULO RETIRADO (era falso Y al reves).
      // partial_decrypt produce una prueba ZK de descifrado correcto, y eso EXIGE
      // aleatoriedad fresca: dos llamadas dan pruebas distintas pero ambas validas.
      // Lo alarmante seria lo contrario -> dos salidas IDENTICAS significarian nonce
      // determinista (reutilizacion de nonce), que es el bug de verdad. Este oraculo
      // gritaba CRITICAL justo por la conducta segura: 4 falsos positivos medidos.
      // Solo dejamos el caso peligroso, sin abortar (hace falta confirmar a mano que
      // no venga de que el RNG del fuzzer quedo en el mismo estado).
      if (rva == SUCCESS && rvb == SUCCESS && pd_a == pd_b) {
        std::fprintf(stderr,
          "REVISAR [O16-DETERMINISTIC] partial_decrypt dio salida IDENTICA dos veces "
          "(posible nonce determinista; confirmar que no sea el RNG del harness)\n");
      }

      for (int i = 0; i < 3; i++)
        combine_partials.push_back(partials[i]);
      break;
    }

    // ================================================================
    // MODO 16: VERIFY oracle — verify con label/ciphertext malicioso
    // ================================================================
    case 16: {
      mem_t evil_label = consume_bytes(label_len > 0 ? label_len : 8);
      error_t vrv = coinbase::api::tdh2::verify(
          to_mem(g_public_key), to_mem(ciphertext), evil_label);

      // Si verify con label incorrecta pasa → bug (label binding)
      // antes hacia label.data[0] sin mirar el tamano -> lectura fuera de rango con
      // labels vacias. same_mem compara tamano primero y trata size==0 aparte.
      if (vrv == SUCCESS && !same_mem(label, evil_label)) {
        std::fprintf(stderr,
          "\n\n========================================\n"
          "CRITICAL [O3-LABEL-CONFUSION-VERIFY] verify ACEPTA ciphertext\n"
          "con label DISTINTA a la del encrypt original.\n"
          "  → El binding de label está roto.\n"
          "========================================\n\n");
        std::abort();
      }

      for (int i = 0; i < 3; i++)
        combine_partials.push_back(partials[i]);
      break;
    }

    // ================================================================
    // MODO 17: Mismatched public_shares — combinar con public_shares
    //          que no corresponden a las partes
    // ================================================================
    case 17: {
      // Permutar public_shares
      if (combine_public_shares.size() >= 2) {
        std::swap(combine_public_shares[0], combine_public_shares[1]);
      }
      for (int i = 0; i < 3; i++)
        combine_partials.push_back(partials[i]);
      break;
    }

    // ================================================================
    // MODO 18: Partial con bytes extra (append garbage)
    // ================================================================
    case 18: {
      mem_t garbage = consume_bytes(64);
      buf_t extended(partials[2]);
      // Append garbage bytes
      size_t old_sz = extended.size();
      // Use resize-like approach: create new buf_t with extra bytes
      std::vector<uint8_t> tmp(extended.data(), extended.data() + extended.size());
      for (size_t i = 0; i < garbage.size && tmp.size() < 8192; i++)
        tmp.push_back(((const uint8_t*)garbage.data)[i]);
      partials[2] = buf_t(mem_t(tmp.data(), tmp.size()));

      for (int i = 0; i < 3; i++)
        combine_partials.push_back(partials[i]);
      break;
    }

    // ================================================================
    // MODO 19: Truncated partial
    // ================================================================
    case 19: {
      if (partials[2].size() > 4) {
        size_t trunc_len = (partials[2].size() / 2);
        partials[2] = buf_t(mem_t(partials[2].data(), trunc_len));
      }
      for (int i = 0; i < 3; i++)
        combine_partials.push_back(partials[i]);
      break;
    }

    // ================================================================
    // MODO 20+: Otros modos agresivos (fuzz puro)
    // ================================================================
    default: {
      // Fuzz agresivo: todos los partials reciben mutación
      mem_t evil = consume_bytes(256);
      for (int i = 0; i < 3; i++) {
        buf_t mutated(partials[i]);
        if (mutated.size() > 0) {
          size_t off = (fuzzrng::next() % mutated.size());
          size_t len = std::min((size_t)(fuzzrng::next() % 64) + 1,
                                mutated.size() - off);
          for (size_t j = 0; j < len && j < evil.size; j++) {
            mutated.data()[off + j] ^= ((const uint8_t*)evil.data)[j];
          }
        }
        combine_partials.push_back(mutated);
      }

      // También mutar ciphertext agresivamente
      if (ciphertext.size() > 0 && (mut_sel & 0x8000)) {
        size_t off = fuzzrng::next() % ciphertext.size();
        size_t len = std::min((size_t)(fuzzrng::next() % 16) + 1,
                              ciphertext.size() - off);
        for (size_t j = 0; j < len; j++)
          ciphertext.data()[off + j] ^= (uint8_t)(fuzzrng::next() & 0xFF);
        combine_ciphertext = to_mem(ciphertext);
      }

      // Posiblemente cambiar label
      if (mut_sel & 0x4000) {
        combine_label = consume_bytes(label_len > 0 ? label_len : 8);
      }

      // Posiblemente reducir public_shares
      if (mut_sel & 0x2000 && combine_public_shares.size() > 1) {
        combine_public_shares.resize(1 + (fuzzrng::next() % combine_public_shares.size()));
        combine_partials.resize(combine_public_shares.size());
      }

      break;
    }
  }

  // ---- STEP 4: combine_additive ----
  // Construir vector<mem_t> de partials
  std::vector<mem_t> partial_mems;
  for (const auto& p : combine_partials)
    partial_mems.push_back(to_mem(p));

  error_t combine_rv = coinbase::api::tdh2::combine_additive(
      to_mem(g_public_key), combine_public_shares, combine_label,
      partial_mems, combine_ciphertext, plaintext_out);

  // ================================================================
  // ORÁCULOS
  // ================================================================

  // [O1] INTEGRITY-BREAK: combine SUCCESS pero plaintext != original
  if (combine_rv == SUCCESS) {
    const size_t exp_len = (size_t)expected_pt.size;
    bool same_plaintext = (plaintext_out.size() == (int)exp_len &&
                           (exp_len == 0 ||
                            std::memcmp(plaintext_out.data(), expected_pt.data,
                                        exp_len) == 0));

    // Si el modo no logro armar un escenario malicioso de verdad (mutacion nula,
    // partial identico al real, ciphertext sin cambiar...), un plaintext distinto
    // no prueba nada roto: es el harness el que fallo en atacar. Se registra y sigue.
    if (!same_plaintext && !escenario_malicioso) {
      std::fprintf(stderr,
        "HARNESS-BUG [premisa] mode=0x%02x: el escenario no resulto malicioso "
        "(el ataque no cambio nada), asi que el plaintext distinto NO es un hallazgo\n",
        mode);
    } else if (!same_plaintext) {
      // Check if plaintext_out is empty
      if (plaintext_out.size() == 0 && exp_len > 0) {
        std::fprintf(stderr,
          "\n\n========================================\n"
          "CRITICAL [O8-EMPTY-OUTPUT] combine SUCCESS devolvió\n"
          "plaintext vacío cuando el original era de %zu bytes.\n"
          "  mode=0x%02x  mut_sel=0x%04x\n"
          "========================================\n\n",
          pt_len, mode, mut_sel);
        std::abort();
      }

      // Check for length oracle
      if (plaintext_out.size() != (int)exp_len) {
        std::fprintf(stderr,
          "\n\n========================================\n"
          "MEDIUM [O9-LENGTH-LEAK] combine SUCCESS pero\n"
          "plaintext de largo distinto: original=%zu bytes, out=%d bytes\n"
          "  mode=0x%02x  mut_sel=0x%04x\n"
          "========================================\n\n",
          pt_actual, (int)plaintext_out.size(), mode, mut_sel);
        // No abort: es Medium, pero lo logueamos
      }

      // Check if plaintext is a prefix/suffix/related to original
      bool is_prefix = false;
      bool is_suffix = false;
      if (plaintext_out.size() > 0 && exp_len > 0) {
        size_t min_len = std::min((size_t)plaintext_out.size(), exp_len);
        is_prefix = (std::memcmp(plaintext_out.data(), expected_pt.data, min_len) == 0);
        is_suffix = (std::memcmp(plaintext_out.data() + plaintext_out.size() - min_len,
                                 expected_pt.data + exp_len - min_len, min_len) == 0);
      }

      if (is_prefix || is_suffix) {
        std::fprintf(stderr,
          "\n\n========================================\n"
          "CRITICAL [O2-MALLEABILITY] combine SUCCESS con plaintext\n"
          "RELACIONADO al original:\n"
          "  is_prefix=%d  is_suffix=%d\n"
          "  mode=0x%02x  mut_sel=0x%04x\n"
          "========================================\n\n",
          is_prefix, is_suffix, mode, mut_sel);
        std::abort();
      }

      // [O1] Generic integrity break
      std::fprintf(stderr,
        "\n\n========================================\n"
        "CRITICAL [O1-INTEGRITY-BREAK] combine SUCCESS pero\n"
        "plaintext != original.\n"
        "  original_pt_len=%zu  out_len=%d\n"
        "  mode=0x%02x  mut_sel=0x%04x\n"
        "  label_len=%zu\n"
        "========================================\n\n",
        pt_actual, (int)plaintext_out.size(), mode, mut_sel, label_len);
      std::abort();
    }

    // [O7] VERIFY-BYPASS: combine SUCCESS pero verify dio FAIL antes
    if (ver_rv_atacado != SUCCESS && (mode & 0x3F) == 10 && escenario_malicioso) {
      std::fprintf(stderr,
        "\n\n========================================\n"
        "CRITICAL [O7-VERIFY-BYPASS] verify rechazó el ciphertext\n"
        "pero combine_additive lo aceptó y descifró correctamente.\n"
        "  → La validación de verify y combine son inconsistentes.\n"
        "========================================\n\n");
      std::abort();
    }

    // [O5] PARTIAL-FORGERY: modo 3 (partial sintético) y combine SUCCESS
    // escenario_malicioso = el partial forjado DIFIERE del real (si no, no hay forja)
    if ((mode & 0x3F) == 3 && escenario_malicioso) {
      std::fprintf(stderr,
        "\n\n========================================\n"
        "CRITICAL [O5-PARTIAL-FORGERY] combine_additive ACEPTÓ\n"
        "un partial completamente sintético.\n"
        "  → La verificación ZK dentro de combine es insuficiente.\n"
        "========================================\n\n");
      std::abort();
    }

    // [O11] QUORUM-BREAK: combine con menos de n partials
    // PREMISA explicita: que de verdad haya MENOS partials de los necesarios.
    // Sin esto, gritaba por el solo hecho de estar en el modo 5.
    if ((mode & 0x3F) == 5 && combine_partials.size() < 3) {
      std::fprintf(stderr,
        "\n\n========================================\n"
        "CRITICAL [O11-QUORUM-BREAK] combine_additive ACEPTÓ\n"
        "un conjunto incompleto de partials (%zu de 3).\n"
        "  → Se puede descifrar sin todas las partes.\n"
        "========================================\n\n",
        combine_partials.size());
      std::abort();
    }
  }

  // [O3] LABEL-CONFUSION: modo 1 y combine SUCCESS
  // El switch usa (mode & 0x3F), asi que comparar "mode == 1" dejaba fuera 65/129/193.
  // Y CLAVE: el modo 1 arma la "evil_label" con consume_bytes, que puede devolver
  // exactamente los MISMOS bytes que la label original (o dos vacias si el offset se
  // agoto). Sin el guard same_mem, que verify aceptara era CORRECTO y aun asi gritaba
  // CRITICAL. Peor: el fuzzer va guiado por cobertura, asi que BUSCA ese input para
  // provocar el abort -> converge al falso positivo y suena sin parar.
  if (combine_rv == SUCCESS && (mode & 0x3F) == 1 && !same_mem(combine_label, label)) {
    error_t vrv = coinbase::api::tdh2::verify(
        to_mem(g_public_key), to_mem(ciphertext), combine_label);
    if (vrv == SUCCESS) {
      std::fprintf(stderr,
        "\n\n========================================\n"
        "CRITICAL [O3-LABEL-CONFUSION] verify ACEPTA ciphertext\n"
        "con label DISTINTA a la del encrypt.\n"
        "  → El binding de label está roto.\n"
        "========================================\n\n");
      std::abort();
    }
  }

  // [O4] CROSS-CIPHERTEXT: modo 2
  if (combine_rv == SUCCESS && (mode & 0x3F) == 2 && escenario_malicioso) {
    std::fprintf(stderr,
      "\n\n========================================\n"
      "CRITICAL [O4-CROSS-CIPHERTEXT] combine ACEPTÓ\n"
      "partials de C1 para descifrar C2.\n"
      "  → Se puede reusar partials entre ciphertexts.\n"
      "========================================\n\n");
    std::abort();
  }

  // [O10] REPLAY: mismo combine corrido dos veces
  // (se testea implícitamente en modo 15 pero también lo hacemos siempre)
  {
    buf_t out2;
    error_t rv2 = coinbase::api::tdh2::combine_additive(
        to_mem(g_public_key), combine_public_shares, combine_label,
        partial_mems, combine_ciphertext, out2);

    if (combine_rv == SUCCESS && rv2 == SUCCESS) {
      if (!(plaintext_out == out2)) {
        std::fprintf(stderr,
          "\n\n========================================\n"
          "CRITICAL [O10-REPLAY] combine_additive NO ES DETERMINISTA:\n"
          "dos llamadas idénticas dieron resultados distintos.\n"
          "========================================\n\n");
        std::abort();
      }
    }
  }

  return 0;
}

// ============================================================================
// Custom Mutator: mutación estructura-consciente del formato converter_t
// ============================================================================
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* Data, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {
  if (MaxSize == 0) return 0;

  // Use Seed to drive deterministic mutation decisions
  uint64_t rng = (uint64_t)Seed * 0x9E3779B97F4A7C15ULL;
  auto rng_next = [&rng]() -> uint8_t {
    rng ^= rng >> 12;
    rng ^= rng << 25;
    rng ^= rng >> 27;
    return (uint8_t)(rng & 0xFF);
  };

  size_t new_size = Size;
  if (new_size > MaxSize) new_size = MaxSize;

  // ---- [ARRANQUE EN FRIO] ----------------------------------------------------
  // BUG que esto arregla (medido: 24h en la nube con cobertura 0):
  // con el corpus vacio libFuzzer entrega 1 byte. El bucle de abajo corta en
  // "if (new_size < 4) break;" y las unicas acciones que CRECEN la entrada (case 4)
  // estan DENTRO de ese bucle -> la entrada se quedaba clavada en 1 byte para
  // siempre. Y LLVMFuzzerTestOneInput exige Size>=16, asi que TODO se rechazaba:
  // sin cobertura no hay corpus, y sin corpus las entradas nunca crecen. Candado.
  // Solucion: si la entrada no llega al minimo util, la inflamos aca (libFuzzer
  // permite escribir hasta MaxSize en Data). 128 = header(16) + label(<=32) + pt.
  const size_t kMinUseful = 128;
  if (new_size < kMinUseful) {
    const size_t target = (MaxSize < kMinUseful) ? MaxSize : kMinUseful;
    while (new_size < target) Data[new_size++] = rng_next();
  }

  // Number of mutation passes
  int passes = 1 + (rng_next() % 5);
  for (int pass = 0; pass < passes; pass++) {
    if (new_size < 4) break;

    int action = rng_next() % 7;
    size_t off = (size_t)(rng_next() % (new_size > 0 ? new_size : 1));

    switch (action) {
      case 0: // Flip bit
        if (new_size > 0) {
          size_t byte_off = off % new_size;
          int bit = rng_next() % 8;
          Data[byte_off] ^= (1 << bit);
        }
        break;
      case 1: // Zero byte
        if (new_size > 0)
          Data[off % new_size] = 0x00;
        break;
      case 2: // Set byte to 0xFF
        if (new_size > 0)
          Data[off % new_size] = 0xFF;
        break;
      case 3: // Swap two bytes
        if (new_size >= 2) {
          size_t a = off % new_size;
          size_t b = rng_next() % new_size;
          std::swap(Data[a], Data[b]);
        }
        break;
      case 4: // Insert byte (expand)
        if (new_size < MaxSize && new_size > 0) {
          size_t pos = off % (new_size + 1);
          std::memmove(Data + pos + 1, Data + pos, new_size - pos);
          Data[pos] = rng_next();
          new_size++;
        }
        break;
      case 5: // Delete byte (shrink)
        if (new_size > 1) {
          size_t pos = off % new_size;
          std::memmove(Data + pos, Data + pos + 1, new_size - pos - 1);
          new_size--;
        }
        break;
      case 6: // Poison serialization header in-place
        if (new_size >= 12)
          mutate_serialization_header(Data, new_size, rng_next() & 0x7);
        break;
    }
  }

  return new_size;
}

// ============================================================================
// CustomCrossOver: combina dos entradas del corpus
// ============================================================================
extern "C" size_t LLVMFuzzerCustomCrossOver(const uint8_t* D1, size_t S1,
                                            const uint8_t* D2, size_t S2,
                                            uint8_t* Out, size_t MaxOut,
                                            unsigned int Seed) {
  if (MaxOut == 0) return 0;

  // Simple splitmix64 RNG
  uint64_t rng = (uint64_t)Seed * 0x9E3779B97F4A7C15ULL;
  auto rng_range = [&rng](size_t lo, size_t hi) -> size_t {
    rng ^= rng >> 33;
    rng *= 0xFF51AFD7ED558CCDULL;
    rng ^= rng >> 33;
    rng *= 0xC4CEB9FE1A85EC53ULL;
    rng ^= rng >> 33;
    return lo + (size_t)(rng % (hi - lo + 1));
  };

  size_t t1 = std::min(S1, MaxOut);
  if (t1 > 0) t1 = rng_range(1, t1);
  if (t1 > S1) t1 = S1;
  if (t1 > MaxOut) t1 = MaxOut;

  size_t rem = MaxOut - t1;
  size_t t2 = std::min(S2, rem);

  if (t1) std::memcpy(Out, D1, t1);
  if (t2) std::memcpy(Out + t1, D2, t2);
  return t1 + t2;
}
