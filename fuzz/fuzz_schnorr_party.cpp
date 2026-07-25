// ============================================================================
// fuzz_malicious_party.cpp — Harness DEFINITIVO (fusión A[Codex] + B[DeepSeek])
// ----------------------------------------------------------------------------
// Red-Team de cb-mpc (Coinbase). Modelo de amenaza alineado con BUG_BOUNTY.md:
//   * P1 = HONESTA, corre la lib SIN MODIFICAR, vía la API PÚBLICA.
//   * P2 = MALICIOSA: sus mensajes P2->P1 se mutan en tránsito (semántico +
//     inyección degenerada + reorden). Solo interactúa por el límite del protocolo.
//
// Lo mejor de cada versión, con el bug crítico de ambas ARREGLADO:
//   [de A]  mutador semántico + force_paillier_degenerate + force_share_null +
//           byte-plan + reorden + CustomMutator gramático + oráculo de nonce con
//           r canónico de 32 bytes (sin tope).
//   [de B]  organización limpia, clase nonce, CustomCrossOver.
//   [FIX]   Se ELIMINA el check "(rv1==SUCCESS)!=(rv2==SUCCESS)" y los checks de
//           pubkey P1-vs-P2: con una parte maliciosa, la discrepancia es NORMAL,
//           no un bug. Solo oráculos CENTRADOS EN LA PARTE HONESTA + ASan/UBSan.
//   [PERF]  La clave de referencia se genera con un DKG LIMPIO UNA sola vez
//           (cacheada + persistida). Cada input ataca sign/refresh -> miles de
//           exec/seg en vez de ~1/seg por hacer keygen Paillier cada input.
//
// Compilar con: bash fuzz/build_fuzz_malicious.sh   (ver ese script)
// ============================================================================

#include <cbmpc/api/schnorr_2p.h>
#include <cbmpc/core/buf.h>
#include <cbmpc/core/error.h>
#include <cbmpc/core/job.h>

#include <fuzzer/FuzzedDataProvider.h>

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <string_view>
#include <thread>
#include <vector>

using namespace coinbase;
namespace e2 = coinbase::api::schnorr_2p;  // Schnorr/BIP340 2P (mismo alias e2 para reusar la maquinaria)

// ============================================================================
// RNG DETERMINISTA sembrado desde el input del fuzzer. ESTO es lo que hace que
// los crashes REPRODUZCAN: mismo input -> mismo stream RNG -> misma ejecución.
// Sin esto, cb-mpc saca aleatoriedad de OpenSSL y cada corrida difiere -> los
// crashes salen flaky y NO son reportables. Las claves siguen siendo válidas.
// ============================================================================
namespace fuzzrng {
inline uint64_t s[4] = {0x9E3779B97F4A7C15ULL, 0xBF58476D1CE4E5B9ULL,
                        0x94D049BB133111EBULL, 0x2545F4914F6CDD1DULL};
inline uint64_t rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
inline uint64_t next() {  // xoshiro256**
  const uint64_t r = rotl(s[1] * 5, 7) * 9;
  const uint64_t t = s[1] << 17;
  s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3]; s[2] ^= t; s[3] = rotl(s[3], 45);
  return r;
}
inline void seed(const uint8_t* d, size_t n) {
  s[0] = 0x9E3779B97F4A7C15ULL; s[1] = 0xBF58476D1CE4E5B9ULL;
  s[2] = 0x94D049BB133111EBULL; s[3] = 0x2545F4914F6CDD1DULL;
  for (size_t i = 0; i < n; i++) { s[i & 3] ^= (uint64_t)d[i] << ((i % 8) * 8); next(); }
  for (int i = 0; i < 16; i++) next();  // warm-up
}
// CARRERA DE DATOS: s[4] es estado global mutable y run_2pc corre P1 y P2 en DOS
// HILOS que llaman next() a la vez (via RAND_bytes de OpenSSL, redirigido aca).
// Sin lock, dos hilos pueden leer/escribir s[] entremedio y devolver valores rotos.
//
// Por que importa mas de lo que parece: P2 genera una prueba ZK usando esta
// aleatoriedad. Si el estado se corrompe A MITAD de esa prueba, la prueba queda
// internamente inconsistente y P1 la rechaza en zk_dl2.verify() -> sign() retorna
// error ANTES de armar la firma. Encaja con lo medido el 2026-07-25: sign()
// devolvio SUCCESS 0 veces en 128 ejecuciones, incluso con P2 honesto.
//
// El lock va en det_bytes (el punto de entrada desde OpenSSL) para que el llenado
// de un buffer completo sea atomico, no solo cada next() suelto.
inline std::mutex rng_mtx;
inline int det_bytes(unsigned char* buf, int num) {
  std::lock_guard<std::mutex> lk(rng_mtx);
  int i = 0;
  while (i < num) { uint64_t x = next(); int c = (num - i) < 8 ? (num - i) : 8; std::memcpy(buf + i, &x, c); i += c; }
  return 1;
}
inline int det_status() { return 1; }
inline RAND_METHOD meth = {nullptr, det_bytes, nullptr, nullptr, det_bytes, det_status};
inline void install() { RAND_set_rand_method(&meth); }
}  // namespace fuzzrng

namespace {

constexpr std::chrono::seconds kRecvTimeout{8};  // backstop < 25s de libFuzzer: deadlock se auto-cura
constexpr auto kCurve = coinbase::api::curve_id::secp256k1;
constexpr int kNid = NID_secp256k1;

// ============================================================================
// splitmix64 (para CustomMutator / CrossOver) — [de B]
// ============================================================================
struct splitmix64_t {
  uint64_t state;
  explicit splitmix64_t(uint64_t seed) : state(seed) {}
  uint64_t next() {
    state += 0x9e3779b97f4a7c15ULL;
    uint64_t z = state;
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
  }
  uint64_t in_range(uint64_t lo, uint64_t hi) { return (lo >= hi) ? lo : lo + (next() % (hi - lo + 1)); }
};

// ============================================================================
// Oráculo de FORGERY BIP340 — verificador INDEPENDIENTE (OpenSSL puro).
// ----------------------------------------------------------------------------
// cb-mpc YA se auto-verifica antes de devolver SUCCESS (schnorr_2p.cpp:130).
// Por eso este verificador solo dispara si el verificador PROPIO de cb-mpc está
// roto y acepta una firma que OpenSSL rechaza -> es un TEST DIFERENCIAL del
// verificador. No reusa NADA de cb-mpc, así un bug de cb-mpc no puede ocultarse.
//   BIP340 verify(px[32], m[32], sig = r[32]||s[32]) sobre secp256k1:
//     1. r < p (primo de campo), s < n (orden).  2. Lift P = punto x=px, y PAR.
//     3. e = int(tagged_hash("BIP0340/challenge", r||px||m)) mod n
//     4. R = s*G - e*P   5. OK sii R != infinito, R.y PAR, R.x == r.
// ============================================================================
static void bip340_tagged_hash(const uint8_t* data, size_t len, uint8_t out[32]) {
  static const char* kTag = "BIP0340/challenge";
  uint8_t th[32];
  SHA256(reinterpret_cast<const uint8_t*>(kTag), std::strlen(kTag), th);
  SHA256_CTX c; SHA256_Init(&c);
  SHA256_Update(&c, th, 32); SHA256_Update(&c, th, 32); SHA256_Update(&c, data, len);
  SHA256_Final(out, &c);
}

// true = firma VÁLIDA bajo BIP340. Libera toda la memoria en cada camino.
static bool bip340_verify(mem_t px32, mem_t msg32, const buf_t& sig64) {
  if (px32.size != 32 || msg32.size != 32 || sig64.size() != 64) return false;
  const uint8_t* rb = reinterpret_cast<const uint8_t*>(sig64.data());
  const uint8_t* sb = rb + 32;

  EC_GROUP* group = nullptr; BN_CTX* ctx = nullptr;
  EC_POINT* P = nullptr; EC_POINT* R = nullptr;
  BIGNUM* p = nullptr; BIGNUM* n = nullptr; BIGNUM* r = nullptr; BIGNUM* s = nullptr;
  BIGNUM* e = nullptr; BIGNUM* px = nullptr; BIGNUM* ne = nullptr; BIGNUM* rx = nullptr; BIGNUM* ry = nullptr;
  bool ok = false;

  group = EC_GROUP_new_by_curve_name(kNid); if (!group) goto done;
  ctx = BN_CTX_new(); if (!ctx) goto done;
  p = BN_new(); n = BN_new(); if (!p || !n) goto done;
  if (!EC_GROUP_get_curve(group, p, nullptr, nullptr, ctx)) goto done;
  if (!EC_GROUP_get_order(group, n, ctx)) goto done;

  r = BN_bin2bn(rb, 32, nullptr); s = BN_bin2bn(sb, 32, nullptr);
  px = BN_bin2bn(reinterpret_cast<const uint8_t*>(px32.data), 32, nullptr);
  if (!r || !s || !px) goto done;
  if (BN_cmp(r, p) >= 0 || BN_cmp(s, n) >= 0 || BN_cmp(px, p) >= 0) goto done;  // fuera de rango

  // Lift pubkey: y PAR (y_bit = 0), convención BIP340.
  P = EC_POINT_new(group); if (!P) goto done;
  if (!EC_POINT_set_compressed_coordinates(group, P, px, 0, ctx)) goto done;

  // e = tagged_hash(r || px || m) mod n
  {
    uint8_t buf[96], eh[32];
    std::memcpy(buf, rb, 32);
    std::memcpy(buf + 32, px32.data, 32);
    std::memcpy(buf + 64, msg32.data, 32);
    bip340_tagged_hash(buf, 96, eh);
    e = BN_bin2bn(eh, 32, nullptr); if (!e) goto done;
    if (!BN_mod(e, e, n, ctx)) goto done;
  }

  // R = s*G - e*P = s*G + (n-e)*P
  ne = BN_new(); if (!ne) goto done;
  if (!BN_sub(ne, n, e)) goto done;
  R = EC_POINT_new(group); if (!R) goto done;
  if (!EC_POINT_mul(group, R, s, P, ne, ctx)) goto done;         // R = s*G + ne*P
  if (EC_POINT_is_at_infinity(group, R)) goto done;

  rx = BN_new(); ry = BN_new(); if (!rx || !ry) goto done;
  if (!EC_POINT_get_affine_coordinates(group, R, rx, ry, ctx)) goto done;
  if (BN_is_odd(ry)) goto done;                                   // R.y debe ser PAR
  ok = (BN_cmp(rx, r) == 0);                                      // R.x == r

done:
  if (rx) BN_free(rx); if (ry) BN_free(ry); if (ne) BN_free(ne);
  if (e) BN_free(e); if (px) BN_free(px); if (s) BN_free(s); if (r) BN_free(r);
  if (n) BN_free(n); if (p) BN_free(p);
  if (R) EC_POINT_free(R); if (P) EC_POINT_free(P);
  if (ctx) BN_CTX_free(ctx); if (group) EC_GROUP_free(group);
  return ok;
}

// ============================================================================
// Oráculo de reuso de nonce ($1M). Solo sobre firmas de la parte HONESTA.
// BIP340: r_x = primeros 32 bytes de la firma. Mismo r con distinto hash =>
// k reusado => clave privada extraíble. Con TOPE de memoria para correr toda
// la noche sin OOM (tras el tope, deja de registrar; el tripwire ya cubrió lo común).
// ============================================================================
class nonce_oracle_t {
 public:
  void check_and_record(const std::array<uint8_t, 32>& r, const std::array<uint8_t, 32>& h) {
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = map_.find(r);
    if (it == map_.end()) { if (map_.size() < kCap) map_.emplace(r, h); return; }
    if (it->second != h) {
      std::fprintf(stderr, "CRITICAL [NONCE-REUSE] mismo R (r_x) para dos hashes distintos: clave privada extraíble\n");
      std::abort();
    }
  }
 private:
  static constexpr size_t kCap = 200000;  // ~12MB tope; evita OOM en corridas largas
  std::mutex mtx_;
  std::map<std::array<uint8_t, 32>, std::array<uint8_t, 32>> map_;
};

// ============================================================================
// Oráculo de leak: el escalar privado NUNCA debe aparecer literal en el
// tráfico saliente de la parte honesta. [común A/B]
// ============================================================================
static bool contains_sub(const uint8_t* hay, size_t hn, const uint8_t* nee, size_t nn) {
  if (!hay || !nee || nn == 0 || hn < nn) return false;
  for (size_t i = 0; i + nn <= hn; ++i)
    if (std::memcmp(hay + i, nee, nn) == 0) return true;
  return false;
}
static void leak_oracle(const buf_t& honest_key, const std::vector<buf_t>& transcript, std::mutex& mtx) {
  buf_t pub_blob, priv;
  if (e2::detach_private_scalar(honest_key, pub_blob, priv) != SUCCESS) return;
  if (priv.size() < 16) return;
  std::lock_guard<std::mutex> lk(mtx);
  for (const auto& m : transcript)
    if (contains_sub(m.data(), (size_t)m.size(), priv.data(), (size_t)priv.size())) {
      std::fprintf(stderr, "CRITICAL [KEY-LEAK] el escalar privado apareció en el tráfico honesto\n");
      std::abort();
    }
}

// ============================================================================
// Red 2P en memoria (bloqueante con timeout anti-deadlock). [común A/B]
// ============================================================================
struct channel_t { std::mutex m; std::condition_variable cv; std::deque<buf_t> q; };
struct network_t {
  explicit network_t(int parties) : n(parties), ch(parties, std::vector<std::shared_ptr<channel_t>>(parties)) {
    for (int a = 0; a < n; ++a) for (int b = 0; b < n; ++b) if (a != b) ch[a][b] = std::make_shared<channel_t>();
  }
  int n;
  std::vector<std::vector<std::shared_ptr<channel_t>>> ch;
  std::atomic<bool> aborted{false};
  void reset_abort() { aborted.store(false); }
  void abort_all() {  // despierta a cualquier parte que espere: la otra ya terminó
    aborted.store(true);
    for (auto& row : ch) for (auto& c : row) if (c) { std::lock_guard<std::mutex> lk(c->m); c->cv.notify_all(); }
  }
};

// Config de mutación derivada del input (thread-safe: la transporta la parte
// maliciosa en su propio buffer de entropía, no toca el FDP compartido). [de A]
struct mut_cfg_t {
  bool enabled = false;
  bool enable_semantic = false;
  bool enable_reorder = false;
  uint8_t forced_mode = 0;         // 0=ninguno, 1=paillier-degenerate, 2=share-null
  std::vector<uint8_t> entropy;    // decisiones del mutador (deriva del input)
};

// ============================================================================
// Transporte HONESTO (P1): registra su tráfico saliente para el leak oracle.
// ============================================================================
class honest_transport_t final : public coinbase::api::data_transport_i {
 public:
  honest_transport_t(int self, std::shared_ptr<network_t> net, std::vector<buf_t>* tr, std::mutex* trm)
      : self_(self), net_(std::move(net)), tr_(tr), trm_(trm) {}
  error_t send(coinbase::api::party_idx_t rcv, mem_t msg) override {
    if (!net_ || rcv < 0 || rcv >= net_->n || rcv == self_) return E_BADARG;
    auto c = net_->ch[self_][rcv]; if (!c) return E_GENERAL;
    if (tr_ && trm_) { buf_t cp(msg); std::lock_guard<std::mutex> lk(*trm_); tr_->push_back(std::move(cp)); }
    { std::lock_guard<std::mutex> lk(c->m); c->q.emplace_back(msg); }
    c->cv.notify_one();
    return SUCCESS;
  }
  error_t receive(coinbase::api::party_idx_t snd, buf_t& msg) override {
    if (!net_ || snd < 0 || snd >= net_->n || snd == self_) return E_BADARG;
    auto c = net_->ch[snd][self_]; if (!c) return E_GENERAL;
    std::unique_lock<std::mutex> lk(c->m);
    c->cv.wait_for(lk, kRecvTimeout, [&] { return !c->q.empty() || net_->aborted.load(); });
    if (c->q.empty()) return E_GENERAL;  // abort (la otra parte terminó) o backstop
    msg = std::move(c->q.front()); c->q.pop_front();
    return SUCCESS;
  }
  error_t receive_all(const std::vector<coinbase::api::party_idx_t>& s, std::vector<buf_t>& m) override {
    m.clear(); m.resize(s.size());
    for (size_t i = 0; i < s.size(); ++i) if (error_t rv = receive(s[i], m[i])) return rv;
    return SUCCESS;
  }
 private:
  int self_; std::shared_ptr<network_t> net_; std::vector<buf_t>* tr_; std::mutex* trm_;
};

// ============================================================================
// Transporte MALICIOSO (P2): muta P2->P1. Núcleo de A (semántico + degenerado
// forzado + reorden), con entropía propia (thread-safe).
// ============================================================================
class malicious_transport_t final : public coinbase::api::data_transport_i {
 public:
  malicious_transport_t(int self, std::shared_ptr<network_t> net, mut_cfg_t cfg)
      : self_(self), net_(std::move(net)), cfg_(std::move(cfg)) {}

  error_t send(coinbase::api::party_idx_t rcv, mem_t msg) override {
    if (!net_ || rcv < 0 || rcv >= net_->n || rcv == self_) return E_BADARG;
    auto c = net_->ch[self_][rcv]; if (!c) return E_GENERAL;
    buf_t out(msg);
    if (cfg_.enabled && self_ == 1 && rcv == 0) {
      if (cfg_.enable_semantic) mutate_semantically(out);
      if (cfg_.forced_mode == 1) force_paillier_degenerate(out);
      if (cfg_.forced_mode == 2) force_share_null(out);
    }
    // Reorden: retiene un mensaje y lo intercala después (ataque de estado). [de A]
    if (cfg_.enabled && cfg_.enable_reorder && self_ == 1 && rcv == 0 && next_bool()) {
      if (delayed_.empty()) { delayed_.push_back(std::move(out)); return SUCCESS; }
      std::lock_guard<std::mutex> lk(c->m);
      c->q.emplace_back(std::move(out));
      c->q.emplace_back(std::move(delayed_.front())); delayed_.pop_front();
      c->cv.notify_all();
      return SUCCESS;
    }
    { std::lock_guard<std::mutex> lk(c->m); c->q.emplace_back(std::move(out)); }
    c->cv.notify_one();
    return SUCCESS;
  }
  error_t receive(coinbase::api::party_idx_t snd, buf_t& msg) override {
    if (!net_ || snd < 0 || snd >= net_->n || snd == self_) return E_BADARG;
    flush_delayed();
    auto c = net_->ch[snd][self_]; if (!c) return E_GENERAL;
    std::unique_lock<std::mutex> lk(c->m);
    c->cv.wait_for(lk, kRecvTimeout, [&] { return !c->q.empty() || net_->aborted.load(); });
    if (c->q.empty()) return E_GENERAL;  // abort (la otra parte terminó) o backstop
    msg = std::move(c->q.front()); c->q.pop_front();
    return SUCCESS;
  }
  error_t receive_all(const std::vector<coinbase::api::party_idx_t>& s, std::vector<buf_t>& m) override {
    m.clear(); m.resize(s.size());
    for (size_t i = 0; i < s.size(); ++i) if (error_t rv = receive(s[i], m[i])) return rv;
    return SUCCESS;
  }

 private:
  struct cand_t { size_t off = 0, len = 0; uint32_t score = 0; };

  static uint32_t score_bigintish(const uint8_t* p, size_t n) {
    if (!p || n == 0) return 0;
    size_t zeros = 0, same = 0; uint8_t first = p[0], last = p[n - 1], seen[16] = {0}; size_t uniq = 0;
    for (size_t i = 0; i < n; ++i) {
      if (p[i] == 0) ++zeros; if (p[i] == first) ++same;
      uint8_t b = p[i] & 0x0F; if (!seen[b]) { seen[b] = 1; ++uniq; }
    }
    if (zeros == n || same == n) return 0;
    uint32_t s = 1; if (last != 0) s += 2; if (zeros < n) s += 2; s += (uint32_t)uniq;
    return s;
  }
  static void write_be_small(uint8_t* p, size_t n, uint32_t x) {
    if (!p || n == 0) return;
    std::memset(p, 0, n);
    for (size_t i = 0; i < 4 && i < n; ++i) p[n - 1 - i] = (uint8_t)((x >> (8 * i)) & 0xFF);
  }
  std::vector<cand_t> find_candidates(const buf_t& b) {
    std::vector<cand_t> cs; const size_t sz = b.size(); if (sz < 32) return cs;
    constexpr size_t lens[] = {32, 64, 128, 256};
    for (size_t len : lens) {
      if (sz < len) continue;
      const size_t stride = (len >= 128) ? 8 : 4;
      for (size_t off = 0; off + len <= sz; off += stride)
        if (uint32_t sc = score_bigintish(b.data() + off, len); sc >= 6) cs.push_back({off, len, sc});
    }
    if (cs.empty()) for (size_t len : lens) if (sz >= len) cs.push_back({0, len, 1});
    return cs;
  }
  cand_t pick(const buf_t& b, size_t min_len) {
    auto cs = find_candidates(b);
    cs.erase(std::remove_if(cs.begin(), cs.end(), [&](const cand_t& c) { return c.len < min_len; }), cs.end());
    if (cs.empty()) return {};
    std::sort(cs.begin(), cs.end(), [](const cand_t& a, const cand_t& b2) { return a.score > b2.score; });
    return cs[next_u32() % std::min<size_t>(cs.size(), 8)];
  }
  void mutate_semantically(buf_t& b) {
    if (b.size() < 8 || !next_bool()) return;
    auto cs = find_candidates(b); if (cs.empty()) return;
    std::sort(cs.begin(), cs.end(), [](const cand_t& a, const cand_t& b2) { return a.score > b2.score; });
    const cand_t c = cs[next_u32() % std::min<size_t>(8, cs.size())];
    uint8_t* p = b.data() + c.off; const size_t n = c.len;
    switch (next_u32() % 5) {
      case 0: std::memset(p, 0, n); break;                                   // zeroize campo
      case 1: write_be_small(p, n, next_u32() % 16); break;                  // constante chica (Paillier degen)
      case 2: for (size_t i = 0; i < n / 2; ++i) std::swap(p[i], p[n - 1 - i]); break;  // endianness
      case 3: { size_t o = next_u32() % n, ml = std::min<size_t>(64, n - o), l = 1 + (next_u32() % ml);
                for (size_t i = 0; i < l; ++i) p[o + i] = (uint8_t)~p[o + i]; } break;  // NOT subrango
      case 4: { size_t o = next_u32() % n, ml = std::min<size_t>(64, n - o), l = 1 + (next_u32() % ml);
                std::memset(p + o, 0, l); } break;                           // zero subrango
    }
  }
  void force_paillier_degenerate(buf_t& b) { cand_t c = pick(b, 128); if (c.len) write_be_small(b.data() + c.off, c.len, 1); }
  void force_share_null(buf_t& b) { cand_t c = pick(b, 32); if (c.len) std::memset(b.data() + c.off, 0, std::min<size_t>(32, c.len)); }
  void flush_delayed() {
    // DETERMINISTA: entrega SIEMPRE todo lo retenido antes de que P2 bloquee en receive.
    // (Antes era probabilístico -> podía tragarse un mensaje para siempre = deadlock.)
    if (self_ != 1 || delayed_.empty() || !net_) return;
    auto c = net_->ch[1][0]; if (!c) return;
    { std::lock_guard<std::mutex> lk(c->m);
      while (!delayed_.empty()) { c->q.emplace_back(std::move(delayed_.front())); delayed_.pop_front(); } }
    c->cv.notify_all();
  }
  uint8_t next_byte() {
    if (eidx_ < cfg_.entropy.size()) return cfg_.entropy[eidx_++];
    fb_ = fb_ * 1664525u + 1013904223u; return (uint8_t)((fb_ >> 16) & 0xFF);
  }
  uint32_t next_u32() { uint32_t x = 0; for (int i = 0; i < 4; ++i) x = (x << 8) | next_byte(); return x; }
  bool next_bool() { return (next_byte() & 1u) != 0; }

  int self_; std::shared_ptr<network_t> net_; mut_cfg_t cfg_;
  std::deque<buf_t> delayed_; size_t eidx_ = 0; uint32_t fb_ = 0xC0FEBABEu;
};

// ============================================================================
// Ejecuta un paso 2P en dos hilos. SIN check de "divergent success":
// con parte maliciosa, que P2 "tenga éxito" y P1 aborte es NORMAL. [FIX]
// ============================================================================
template <typename F1, typename F2>
static void run_2pc(const std::shared_ptr<network_t>& net, F1&& f1, F2&& f2, error_t& rv1, error_t& rv2) {
  net->reset_abort();
  rv1 = E_GENERAL; rv2 = E_GENERAL;
  // abort_all SOLO ante ERROR (no en éxito): si una parte termina OK no debe
  // derribar el canal y sacar a la otra de su espera ANTES de que llegue a su
  // último paso. Eso hacía los crashes FLAKY (carrera). Con esto, si P1 va a
  // crashear en su última operación, P2 puede terminar sin matarlo -> DETERMINISTA.
  std::thread t1([&] { rv1 = f1(); if (rv1 != SUCCESS) net->abort_all(); });
  std::thread t2([&] { rv2 = f2(); if (rv2 != SUCCESS) net->abort_all(); });
  t1.join(); t2.join();
}

// ============================================================================
// Estado global: clave de referencia (DKG LIMPIO una sola vez, persistida).
// ============================================================================
static buf_t g_key1, g_key2, g_pub;   // g_key1 = honesta (P1), g_pub = pubkey ref
static buf_t g_pub_xonly;             // pubkey x-only (32B) para verificación BIP340
static bool g_ready = false;
static nonce_oracle_t g_nonce;        // reuso de nonce sobre firmas de P1 (global entre inputs)

static bool load_buf(const char* path, buf_t& out) {
  FILE* f = std::fopen(path, "rb"); if (!f) return false;
  std::fseek(f, 0, SEEK_END); long n = std::ftell(f); std::fseek(f, 0, SEEK_SET);
  bool ok = false;
  if (n > 0 && n < (64 << 20)) { out = buf_t((int)n); ok = std::fread(out.data(), 1, (size_t)n, f) == (size_t)n; }
  std::fclose(f); return ok;
}
static void save_buf(const char* path, const buf_t& b) {
  FILE* f = std::fopen(path, "wb"); if (!f) return;
  if (b.size() > 0) std::fwrite(b.data(), 1, (size_t)b.size(), f);
  std::fclose(f);
}

static bool fill_xonly() {  // rellena g_pub_xonly desde g_key1 (para el oráculo BIP340)
  return e2::extract_public_key_xonly(g_key1, g_pub_xonly) == SUCCESS && g_pub_xonly.size() == 32;
}

static bool bootstrap() {
  if (load_buf("cbmpc_schnorr_key1.bin", g_key1) && load_buf("cbmpc_schnorr_key2.bin", g_key2) &&
      e2::get_public_key_compressed(g_key1, g_pub) == SUCCESS && fill_xonly())
    return true;
  auto net = std::make_shared<network_t>(2);
  mut_cfg_t off;  // DKG de bootstrap: SIN mutación (clave de referencia limpia)
  honest_transport_t t1(0, net, nullptr, nullptr);
  malicious_transport_t t2(1, net, off);
  constexpr std::string_view p1 = "P1", p2 = "P2";
  coinbase::api::job_2p_t j1{coinbase::api::party_2p_t::p1, p1, p2, t1};
  coinbase::api::job_2p_t j2{coinbase::api::party_2p_t::p2, p1, p2, t2};
  error_t r1, r2;
  run_2pc(net, [&] { return e2::dkg(j1, kCurve, g_key1); }, [&] { return e2::dkg(j2, kCurve, g_key2); }, r1, r2);
  if (r1 != SUCCESS || r2 != SUCCESS) {
    std::fprintf(stderr, "bootstrap DKG fallo rv1=%x rv2=%x\n", (unsigned)r1, (unsigned)r2);
    return false;
  }
  if (e2::get_public_key_compressed(g_key1, g_pub) != SUCCESS) return false;
  if (!fill_xonly()) return false;
  save_buf("cbmpc_schnorr_key1.bin", g_key1);
  save_buf("cbmpc_schnorr_key2.bin", g_key2);
  return true;
}

}  // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  fuzzrng::install();  // RNG determinista: los crashes ahora REPRODUCEN
  g_ready = bootstrap();
  if (!g_ready) { std::fprintf(stderr, "bootstrap() failed\n"); std::abort(); }
  return 0;
}

// ============================================================================
// Cuerpo: máquina de estados de sign/refresh ATACADOS contra la clave cacheada.
// Oráculos SOLO centrados en la parte honesta (P1).
// ============================================================================
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
  if (!g_ready || Size < 4) return 0;
  fuzzrng::seed(Data, Size);  // el RNG del protocolo queda atado a ESTE input -> reproduce
  FuzzedDataProvider fdp(Data, Size);

  // --- config de mutación (deriva del input) ---
  const uint8_t flags = fdp.ConsumeIntegral<uint8_t>();
  mut_cfg_t cfg;
  // P2 malicioso ~3 de cada 4 veces, NO siempre.
  //
  // Estaba en "true" fijo, y eso castraba el oraculo de mas valor. Medido
  // 2026-07-25 con contadores dentro de schnorr_2p.cpp: en 128 ejecuciones con
  // 2838 entradas de corpus, sign() devolvio SUCCESS **0 veces** y la rama BIP340
  // no se alcanzo NUNCA. Con P2 mutando todos los mensajes el protocolo siempre
  // aborta antes de firmar, y [SCHNORR-FORGERY] exige SUCCESS para poder mirar la
  // firma -> se quedaba sin material que revisar.
  //
  // Consecuencia: un harness 100% adversario solo encuentra CRASHES (DoS). Los
  // bugs de soundness ("acepto y el resultado esta mal") viven justo en el medio:
  // mutaciones lo bastante sutiles como para que el protocolo COMPLETE y aun asi
  // el resultado sea invalido. Sin corridas que completen, ese terreno no existe.
  // Encaja con lo observado en dias de caza: solo aparecio el DoS is_in_range.
  //
  // Deriva del input (bits altos de flags) para no perder reproducibilidad.
  cfg.enabled = ((flags >> 6) != 0);
  cfg.enable_semantic = (flags & 0x01u);
  cfg.enable_reorder = (flags & 0x02u);
  if (flags & 0x08u) cfg.forced_mode = 1;
  if (flags & 0x10u) cfg.forced_mode = 2;

  const int num_ops = fdp.ConsumeIntegralInRange<int>(1, 8);
  std::vector<uint8_t> ops(num_ops);
  for (auto& o : ops) o = fdp.ConsumeIntegralInRange<uint8_t>(0, 1);  // 0=sign, 1=refresh

  std::vector<std::array<uint8_t, 32>> hashes;
  for (uint8_t o : ops) if (o == 0) {
    std::array<uint8_t, 32> h{};
    auto v = fdp.ConsumeBytes<uint8_t>(32);
    for (size_t i = 0; i < v.size() && i < 32; ++i) h[i] = v[i];
    hashes.push_back(h);
  }

  // entropía del mutador (buffer propio, thread-safe): el resto del input.
  cfg.entropy = fdp.ConsumeRemainingBytes<uint8_t>();

  auto net = std::make_shared<network_t>(2);
  std::vector<buf_t> transcript; std::mutex trmtx;
  honest_transport_t t_h(0, net, &transcript, &trmtx);
  malicious_transport_t t_m(1, net, cfg);
  constexpr std::string_view p1 = "P1", p2 = "P2";
  coinbase::api::job_2p_t j1{coinbase::api::party_2p_t::p1, p1, p2, t_h};
  coinbase::api::job_2p_t j2{coinbase::api::party_2p_t::p2, p1, p2, t_m};

  size_t hcur = 0;

  for (uint8_t op : ops) {
    if (op == 0) {  // ---------- SIGN atacado ----------
      if (hcur >= hashes.size()) break;
      const std::array<uint8_t, 32>& h = hashes[hcur++];
      buf_t mh((int)32); for (int i = 0; i < 32; ++i) mh[i] = h[i];
      { std::lock_guard<std::mutex> lk(trmtx); transcript.clear(); }
      buf_t sig1, sig2; error_t r1, r2;
      run_2pc(net, [&] { return e2::sign(j1, g_key1, mh, sig1); },
              [&] { return e2::sign(j2, g_key2, mh, sig2); }, r1, r2);
      // ---- ORÁCULOS honesto-céntricos sobre la firma de P1 (BIP340, 64B r_x||s) ----
      // El crash del s2 fuera de rango (schnorr_2p.cpp:118 -> is_in_range) lo caza
      // ASan/cb_assert AUTOMÁTICAMENTE durante el sign, no necesita oráculo.
      if (r1 == SUCCESS && sig1.size() == 64) {
        // (1) FORGERY: P1 dio SUCCESS -> la firma DEBE verificar bajo la pubkey real.
        //     Verificador INDEPENDIENTE (OpenSSL): caza que el verify propio de cb-mpc
        //     acepte una firma inválida. [tier alto: forgery en threshold signing]
        if (!bip340_verify(mem_t(g_pub_xonly.data(), g_pub_xonly.size()),
                           mem_t(mh.data(), mh.size()), sig1)) {
          std::fprintf(stderr, "CRITICAL [SCHNORR-FORGERY] P1 SUCCESS con firma BIP340 que NO verifica bajo la clave real\n");
          std::abort();
        }
        // (2) NONCE-REUSE: mismo r_x para dos mensajes distintos -> clave extraíble.
        std::array<uint8_t, 32> rx{}, hh{};
        std::memcpy(rx.data(), sig1.data(), 32);
        std::memcpy(hh.data(), mh.data(), 32);
        g_nonce.check_and_record(rx, hh);
        // (3) LEAK: el escalar privado de P1 no debe aparecer en su tráfico saliente.
        leak_oracle(g_key1, transcript, trmtx);
      }
    } else {  // ---------- REFRESH atacado ----------
      { std::lock_guard<std::mutex> lk(trmtx); transcript.clear(); }
      buf_t nk1, nk2; error_t r1, r2;
      run_2pc(net, [&] { return e2::refresh(j1, g_key1, nk1); },
              [&] { return e2::refresh(j2, g_key2, nk2); }, r1, r2);
      // Oráculo honesto-céntrico: P1 SUCCESS => su NUEVA pubkey DEBE == g_pub.
      if (r1 == SUCCESS && nk1.size() > 0) {
        buf_t np;
        if (e2::get_public_key_compressed(nk1, np) == SUCCESS) {
          if (!(np == g_pub)) {
            std::fprintf(stderr, "CRITICAL [REFRESH-BREAK] refresh atacado cambió la clave pública de P1\n");
            std::abort();
          }
          leak_oracle(nk1, transcript, trmtx);
        }
        // No persistimos nk (nk2 viene de la parte maliciosa): seguimos con g_key.
      }
    }
  }
  return 0;
}

// ============================================================================
// CustomMutator gramático [de A, adaptado al layout de arriba]: genera inputs
// que decodifican en secuencias de ops válidas + entropía de mutación.
// ============================================================================
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* Data, size_t Size, size_t MaxSize, unsigned int Seed) {
  if (!Data || MaxSize == 0) return 0;
  splitmix64_t rng(Seed ^ (uint64_t)(Size * 131u + 17u));
  FuzzedDataProvider fdp(Data, Size);
  std::vector<uint8_t> out; out.reserve(std::min<size_t>(MaxSize, 512));
  auto u8 = [&](uint8_t v) { if (out.size() < MaxSize) out.push_back(v); };

  u8((uint8_t)rng.next());                                   // flags
  const int nops = 1 + (int)(rng.in_range(0, 7));
  u8((uint8_t)nops);                                          // num_ops
  std::vector<uint8_t> ops;
  for (int i = 0; i < nops; ++i) { uint8_t o = (uint8_t)(rng.in_range(0, 1)); ops.push_back(o); u8(o); }
  for (uint8_t o : ops) if (o == 0) {                        // hash de 32B por cada sign
    auto h = fdp.ConsumeBytes<uint8_t>(32); h.resize(32, (uint8_t)rng.next());
    for (uint8_t b : h) u8(b);
  }
  // cola de entropía para el mutador de transporte
  const size_t etail = std::min<size_t>(192, 32 + (size_t)(rng.next() % 128));
  for (size_t i = 0; i < etail && out.size() < MaxSize; ++i)
    u8(fdp.remaining_bytes() ? fdp.ConsumeIntegral<uint8_t>() : (uint8_t)rng.next());

  if (out.empty()) return 0;
  std::memcpy(Data, out.data(), out.size());
  return out.size();
}

// ============================================================================
// CustomCrossOver [de B]: combina dos entradas del corpus en frontera de 32B.
// ============================================================================
extern "C" size_t LLVMFuzzerCustomCrossOver(const uint8_t* D1, size_t S1, const uint8_t* D2, size_t S2,
                                            uint8_t* Out, size_t MaxOut, unsigned int Seed) {
  if (MaxOut == 0) return 0;
  splitmix64_t rng(Seed);
  // Corte en D1: acotado SIEMPRE a lo disponible (S1) y al espacio (MaxOut). Nunca OOB.
  size_t t1 = std::min(S1, MaxOut);
  if (t1 >= 32) t1 = (size_t)rng.in_range(0, t1 / 32) * 32;  // 0..t1 en pasos de 32
  if (t1 > S1) t1 = S1;
  if (t1 > MaxOut) t1 = MaxOut;
  // Relleno con D2: nunca más que S2 ni que el espacio restante.
  // (AQUÍ estaba el bug: antes forzaba t2=32 sin chequear S2>=32 -> leía 32B de 1B.)
  size_t rem = MaxOut - t1;
  size_t t2 = std::min(S2, rem);
  if (t1) std::memcpy(Out, D1, t1);
  if (t2) std::memcpy(Out + t1, D2, t2);
  return t1 + t2;
}